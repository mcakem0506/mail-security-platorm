"""Применение конфигурации на узле (ТЗ 1.1 §39–§40).

Смысл активации в том, что узел **всегда** остаётся в рабочем состоянии: неудачная конфигурация
не должна оставить шлюз остановленным или, хуже, работающим с непроверенной конфигурацией.
Поэтому тесты идут по каждой ветке отказа и после каждой проверяют два факта: что
случилось с пакетом и что осталось активным.

Внешние команды подставные. Настоящий Postfix проверяется отдельно, в контейнере; здесь
проверяется логика решений вокруг него.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from msp_gateway.apply import ConfigStore, Outcome, Stage, apply_bundle
from msp_gateway.bundle import BundleError, bundle_checksum, verify_bundle, version_id


def _symlinks_supported() -> bool:
    """Узел шлюза работает только на Linux. На Windows без особых прав символическую ссылку не
    создать (WinError 1314), и это свойство машины разработчика, а не логики применения. В CI
    (Linux) условие всегда ложно, и тесты выполняются; пропуск не может скрыть падение там."""
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        try:
            os.symlink("target", os.path.join(directory, "link"))
        except OSError:
            return False
    return True


requires_symlinks = pytest.mark.skipif(
    not _symlinks_supported(),
    reason="символические ссылки недоступны на этой платформе; проверяется в CI на Linux",
)
pytestmark = requires_symlinks


def make_bundle(version: int = 1, content: str = "a") -> tuple[dict[str, bytes], dict[str, object]]:
    files = {
        "main.cf": f"myhostname = gw{content}\n".encode(),
        "master.cf": b"smtp inet n - n - - smtpd\n",
        "relay_domains": b"corp.example OK\n",
    }
    manifest: dict[str, object] = {
        "version": version,
        "checksum": bundle_checksum(files),
        "files": sorted(files),
        "hash_maps": ["relay_domains"],
    }
    return files, manifest


class FakeRunner:
    """Ведёт себя как Postfix, пока ему не скажут иначе, и записывает вызовы."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.postmap_fails = False
        self.check_stderr = ""
        self.check_returncode = 0
        self.running = True
        self.reload_fails = False

    def __call__(self, argv, *, env=None, timeout=60.0):  # type: ignore[no-untyped-def]
        from msp_gateway.apply import CommandResult

        self.calls.append(list(argv))
        if argv[0] == "postmap":
            if self.postmap_fails:
                return CommandResult(1, "", "postmap: fatal: bad map")
            target = argv[-1].removeprefix("hash:")
            Path(target + ".db").write_bytes(b"compiled")
            return CommandResult(0)
        if len(argv) == 4 and argv[:2] == ["postfix", "-c"] and argv[-1] == "check":
            return CommandResult(self.check_returncode, "", self.check_stderr)
        if argv == ["postfix", "status"]:
            return CommandResult(0 if self.running else 1)
        if argv == ["postfix", "reload"]:
            return CommandResult(1, "", "reload: fatal") if self.reload_fails else CommandResult(0)
        return CommandResult(0)

    def reloads(self) -> int:
        return sum(1 for call in self.calls if call == ["postfix", "reload"])


@pytest.fixture
def store(tmp_path: Path) -> ConfigStore:
    return ConfigStore(tmp_path / "config", state_dir=tmp_path / "state")


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


def activate(store: ConfigStore, runner: FakeRunner, version: int = 1, content: str = "a", **kwargs):  # type: ignore[no-untyped-def]
    files, manifest = make_bundle(version, content)
    return apply_bundle(files, manifest, store, runner=runner, **kwargs)


class TestSuccessfulActivation:
    def test_the_first_bundle_becomes_active(self, store: ConfigStore, runner: FakeRunner) -> None:
        result = activate(store, runner)
        assert result.outcome is Outcome.ACTIVE
        assert store.active_version() is not None
        assert (store.versions / store.active_version() / "main.cf").exists()  # type: ignore[operator]

    def test_the_steps_follow_the_order_of_the_specification(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        """ТЗ §39: сверка → подготовка → карты → postfix check → подмена → reload → здоровье."""
        result = activate(store, runner, healthcheck=lambda: [])
        joined = " | ".join(result.steps)
        order = [
            "сверка",
            "подготовительный",
            "карты скомпилированы",
            "postfix check",
            "ссылка active",
            "reload",
            "здоровья",
        ]
        positions = [joined.index(word) for word in order]
        assert positions == sorted(positions)

    def test_maps_are_compiled_with_an_explicit_config_directory(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        """postmap читал каталог из переменной окружения, которой на первой загрузке нет."""
        activate(store, runner)
        postmap = next(c for c in runner.calls if c[0] == "postmap")
        assert postmap[1] == "-c"

    def test_a_second_version_replaces_the_first_and_keeps_it_as_previous(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        activate(store, runner, 1, "a")
        first = store.active_version()
        activate(store, runner, 2, "b")
        assert store.active_version() != first
        assert os.path.basename(os.readlink(store.previous)) == first

    def test_the_same_version_again_changes_nothing_and_does_not_reload(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        activate(store, runner)
        reloads = runner.reloads()
        again = activate(store, runner)
        assert again.outcome is Outcome.ACTIVE
        assert "уже активна" in again.message
        assert runner.reloads() == reloads

    def test_a_node_whose_master_is_not_running_is_activated_without_a_reload(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        """На первой загрузке Postfix ещё не запущен: «reload» вернул бы ошибку, которую не следует
        принимать за неудачную конфигурацию."""
        runner.running = False
        result = activate(store, runner)
        assert result.outcome is Outcome.ACTIVE
        assert runner.reloads() == 0

    def test_the_active_link_is_a_relative_symlink(self, store: ConfigStore, runner: FakeRunner) -> None:
        """Подмена ссылки — одна операция: Postfix видит либо старую конфигурацию целиком, либо новую."""
        activate(store, runner)
        assert store.active.is_symlink()
        assert not os.path.isabs(os.readlink(store.active))


class TestRefusals:
    def test_a_tampered_file_is_refused_before_anything_is_written(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        files, manifest = make_bundle()
        files["main.cf"] = b"myhostname = evil\nmynetworks = 0.0.0.0/0\n"
        result = apply_bundle(files, manifest, store, runner=runner)
        assert result.outcome is Outcome.FAILED
        assert result.stage is Stage.VERIFY
        assert not store.versions.exists()
        assert runner.calls == []

    def test_an_extra_file_is_refused(self, store: ConfigStore, runner: FakeRunner) -> None:
        files, manifest = make_bundle()
        files["extra.cf"] = b"x"
        assert apply_bundle(files, manifest, store, runner=runner).stage is Stage.VERIFY

    def test_a_missing_file_is_refused(self, store: ConfigStore, runner: FakeRunner) -> None:
        files, manifest = make_bundle()
        del files["master.cf"]
        assert apply_bundle(files, manifest, store, runner=runner).stage is Stage.VERIFY

    @pytest.mark.parametrize("name", ["../evil", "a/b", ".hidden", "a\\b"])
    def test_a_file_name_with_a_path_is_refused(self, name: str) -> None:
        files = {name: b"x"}
        manifest: dict[str, object] = {"version": 1, "checksum": bundle_checksum(files), "files": [name]}
        with pytest.raises(BundleError):
            verify_bundle(files, manifest)

    def test_a_malformed_manifest_is_a_refusal_not_a_crash(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        files, manifest = make_bundle()
        manifest["hash_maps"] = "relay_domains"
        result = apply_bundle(files, manifest, store, runner=runner)
        assert result.outcome is Outcome.FAILED

    def test_a_map_that_does_not_compile_fails_and_leaves_nothing_active(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        runner.postmap_fails = True
        result = activate(store, runner)
        assert result.outcome is Outcome.FAILED
        assert result.stage is Stage.COMPILE
        assert store.active_version() is None

    def test_a_rejected_postfix_check_fails_and_cleans_up(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        runner.check_returncode = 1
        runner.check_stderr = "postfix: fatal: bad configuration"
        result = activate(store, runner)
        assert result.stage is Stage.POSTFIX_CHECK
        assert store.active_version() is None
        assert not any(p.name.startswith(".staging") for p in store.versions.iterdir())

    def test_a_fatal_word_in_stderr_fails_even_with_a_zero_exit_code(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        """postfix check возвращает 0 и при серьёзных замечаниях."""
        runner.check_stderr = "postfix: fatal: unknown parameter"
        assert activate(store, runner).stage is Stage.POSTFIX_CHECK

    def test_a_failed_second_version_leaves_the_first_active(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        activate(store, runner, 1, "a")
        first = store.active_version()
        runner.postmap_fails = True
        result = activate(store, runner, 2, "b")
        assert result.outcome is Outcome.FAILED
        assert store.active_version() == first


class TestRollback:
    def test_a_failed_reload_restores_the_previous_version(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        activate(store, runner, 1, "a")
        first = store.active_version()
        runner.reload_fails = True
        result = activate(store, runner, 2, "b")
        assert result.outcome is Outcome.ROLLED_BACK
        assert store.active_version() == first
        assert result.rolled_back_to == first

    def test_a_failed_healthcheck_restores_the_previous_version(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        """Конфигурация может быть синтаксически безупречной и при этом открытой: ровно так
        выглядит ошибка в списке доверенных сетей."""
        activate(store, runner, 1, "a")
        first = store.active_version()
        result = activate(store, runner, 2, "b", healthcheck=lambda: ["слушатель принял внешнего получателя"])
        assert result.outcome is Outcome.ROLLED_BACK
        assert store.active_version() == first
        assert "принял внешнего получателя" in result.message

    def test_a_rollback_reloads_the_old_configuration(self, store: ConfigStore, runner: FakeRunner) -> None:
        activate(store, runner, 1, "a")
        before = runner.reloads()
        activate(store, runner, 2, "b", healthcheck=lambda: ["плохо"])
        assert runner.reloads() == before + 2, "перезагрузка на новую и ещё одна — обратно"

    def test_with_no_previous_version_there_is_nothing_to_roll_back_to(
        self, store: ConfigStore, runner: FakeRunner
    ) -> None:
        result = activate(store, runner, healthcheck=lambda: ["плохо"])
        assert result.outcome is Outcome.FAILED
        assert "откатываться некуда" in result.message

    def test_a_healthy_check_activates(self, store: ConfigStore, runner: FakeRunner) -> None:
        assert activate(store, runner, healthcheck=lambda: []).outcome is Outcome.ACTIVE


class TestDrift:
    def test_an_untouched_node_is_in_sync(self, store: ConfigStore, runner: FakeRunner) -> None:
        activate(store, runner)
        assert store.active_checksum() == store.drift_checksum()

    def test_a_hand_edit_on_the_node_is_detected(self, store: ConfigStore, runner: FakeRunner) -> None:
        """Описание осталось прежним, а пересчитанная с диска сумма — нет."""
        activate(store, runner)
        version = store.active_version()
        main = store.versions / version / "main.cf"  # type: ignore[operator]
        main.write_text(main.read_text() + "mynetworks = 0.0.0.0/0\n")
        assert store.active_checksum() != store.drift_checksum()

    def test_a_missing_file_is_drift_not_a_crash(self, store: ConfigStore, runner: FakeRunner) -> None:
        activate(store, runner)
        (store.versions / store.active_version() / "relay_domains").unlink()  # type: ignore[operator]
        assert store.drift_checksum() is None

    def test_a_node_without_configuration_reports_nothing(self, store: ConfigStore) -> None:
        assert store.active_version() is None
        assert store.active_checksum() is None
        assert store.drift_checksum() is None


class TestBundleHelpers:
    def test_the_version_id_carries_the_checksum_prefix(self) -> None:
        _, manifest = make_bundle(7)
        assert version_id(manifest) == f"000007-{str(manifest['checksum'])[:12]}"

    def test_a_non_integer_version_is_refused(self) -> None:
        _, manifest = make_bundle()
        manifest["version"] = "7"
        with pytest.raises(BundleError):
            version_id(manifest)

    def test_the_checksum_depends_on_names_as_well_as_content(self) -> None:
        assert bundle_checksum({"a": b"x"}) != bundle_checksum({"b": b"x"})

    def test_the_checksum_does_not_confuse_file_boundaries(self) -> None:
        """Иначе перенос байта из одного файла в другой оставил бы сумму прежней."""
        assert bundle_checksum({"a": b"xy", "b": b""}) != bundle_checksum({"a": b"x", "b": b"y"})

    def test_a_manifest_roundtrips_through_json(self) -> None:
        _, manifest = make_bundle()
        assert json.loads(json.dumps(manifest)) == manifest
