"""Применение пакета конфигурации на узле (ТЗ 1.1 §39–§40).

Порядок шагов взят из ТЗ дословно и не случаен:

    сверка → подготовка → компиляция карт → postfix check → проверка карт →
    атомарная подмена → reload → проверка здоровья → ACTIVE

Любой сбой после подмены возвращает прежнюю версию. Смысл активации в том, что узел **всегда**
остаётся в рабочем состоянии: неудачная конфигурация не должна оставить шлюз остановленным или,
хуже, работающим с конфигурацией, которую никто не проверял.

Атомарность даёт символическая ссылка ``active``, а не копирование файлов: подмена ссылки — одна
операция, и Postfix видит либо старую конфигурацию целиком, либо новую целиком. Перезапись
``main.cf`` и ``master.cf`` по очереди оставила бы окно, в котором они принадлежат разным версиям.

Внешние команды (``postmap``, ``postfix``) вызываются через :class:`Runner`, чтобы логику
активации можно было проверять без Postfix, а сам Postfix проверять отдельно, в контейнере.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - вызывает фиксированные команды Postfix, не пользовательский ввод
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from .bundle import BundleError, bundle_checksum, manifest_names, verify_bundle, version_id


class Stage(StrEnum):
    VERIFY = "verify"
    STAGE = "stage"
    COMPILE = "compile"
    POSTFIX_CHECK = "postfix_check"
    MAP_CHECK = "map_check"
    SWAP = "swap"
    RELOAD = "reload"
    HEALTH = "health"
    DONE = "done"


class Outcome(StrEnum):
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class Runner(Protocol):
    def __call__(
        self, argv: list[str], *, env: dict[str, str] | None = None, timeout: float = 60.0
    ) -> CommandResult: ...


def subprocess_runner(
    argv: list[str], *, env: dict[str, str] | None = None, timeout: float = 60.0
) -> CommandResult:
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603 - фиксированные команды Postfix, без оболочки
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, **(env or {})},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandResult(127, "", type(exc).__name__)
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


#: Проверка здоровья после перезагрузки: возвращает список проблем, пустой — всё хорошо.
Healthcheck = Callable[[], list[str]]


@dataclass
class ApplyResult:
    outcome: Outcome
    stage: Stage
    message: str
    version_dir: str | None = None
    checksum: str | None = None
    rolled_back_to: str | None = None
    steps: list[str] = field(default_factory=list)


class ConfigStore:
    """Версии конфигурации на диске узла."""

    def __init__(self, root: str | Path, *, state_dir: str | Path | None = None) -> None:
        self.root = Path(root)
        self.versions = self.root / "versions"
        self.active = self.root / "active"
        self.previous = self.root / "previous"
        self.state_dir = Path(state_dir) if state_dir else None

    def active_version(self) -> str | None:
        if not self.active.is_symlink():
            return None
        return os.path.basename(os.readlink(self.active))

    def active_checksum(self) -> str | None:
        """Сумма активной конфигурации — то, что узел сообщает центру для обнаружения дрейфа."""
        version = self.active_version()
        if version is None:
            return None
        manifest = self.versions / version / "manifest.json"
        try:
            return str(json.loads(manifest.read_text(encoding="utf-8")).get("checksum"))
        except (OSError, ValueError):
            return None

    def drift_checksum(self) -> str | None:
        """Сумма файлов активной конфигурации, пересчитанная с диска.

        Отличается от :meth:`active_checksum` тем, что не верит описанию: если кто-то правил
        ``main.cf`` на узле руками, описание осталось прежним, а пересчитанная сумма — нет.
        """
        version = self.active_version()
        if version is None:
            return None
        directory = self.versions / version
        try:
            manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
            files = {name: (directory / name).read_bytes() for name in manifest_names(manifest, "files")}
        except (OSError, ValueError):
            return None
        return bundle_checksum(files)

    def _swap(self, link: Path, target: str) -> None:
        temp = link.with_name(link.name + ".tmp")
        if temp.is_symlink() or temp.exists():
            temp.unlink()
        os.symlink(os.path.join("versions", target), temp)
        os.replace(temp, link)  # атомарно: ссылка указывает либо на старое, либо на новое


def apply_bundle(
    files: dict[str, bytes],
    manifest: dict[str, object],
    store: ConfigStore,
    *,
    runner: Runner = subprocess_runner,
    healthcheck: Healthcheck | None = None,
    reload_wait: float = 0.0,
) -> ApplyResult:
    steps: list[str] = []

    def note(text: str) -> None:
        steps.append(text)

    try:
        checksum = verify_bundle(files, manifest)
        note("сверка пакета: сумма и состав совпали")
    except BundleError as exc:
        return ApplyResult(Outcome.FAILED, Stage.VERIFY, str(exc), steps=steps)

    try:
        hash_maps = manifest_names(manifest, "hash_maps")
    except BundleError as exc:
        return ApplyResult(Outcome.FAILED, Stage.VERIFY, str(exc), steps=steps)
    identifier = version_id(manifest)
    target = store.versions / identifier
    previous = store.active_version()

    # Одна и та же версия уже активна — ничего менять не нужно, и перезагружать Postfix тоже.
    if previous == identifier:
        return ApplyResult(
            Outcome.ACTIVE, Stage.DONE, "эта версия уже активна", str(target), checksum, steps=steps
        )

    # --- подготовка --------------------------------------------------------------------
    staging = store.versions / f".staging-{identifier}"
    try:
        store.versions.mkdir(parents=True, exist_ok=True)
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir()
        for name, content in files.items():
            (staging / name).write_bytes(content)
        (staging / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8"
        )
        note("пакет записан в подготовительный каталог")
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        return ApplyResult(
            Outcome.FAILED, Stage.STAGE, f"не удалось подготовить пакет: {type(exc).__name__}", steps=steps
        )

    # --- компиляция карт ---------------------------------------------------------------
    for name in hash_maps:
        result = runner(["postmap", "-c", str(staging), f"hash:{staging / str(name)}"])
        if result.returncode != 0:
            shutil.rmtree(staging, ignore_errors=True)
            return ApplyResult(
                Outcome.FAILED,
                Stage.COMPILE,
                f"карта {name} не скомпилировалась: {result.stderr.strip()[:200]}",
                steps=steps,
            )
    note("карты скомпилированы")

    # --- postfix check -----------------------------------------------------------------
    result = runner(["postfix", "-c", str(staging), "check"])
    if result.returncode != 0 or _has_fatal(result.stderr):
        shutil.rmtree(staging, ignore_errors=True)
        return ApplyResult(
            Outcome.FAILED,
            Stage.POSTFIX_CHECK,
            f"postfix check отверг конфигурацию: {result.stderr.strip()[:300]}",
            steps=steps,
        )
    note("postfix check пройден")

    # --- карты читаются ----------------------------------------------------------------
    for name in hash_maps:
        path = staging / str(name)
        if not (path.parent / f"{name}.db").exists():
            shutil.rmtree(staging, ignore_errors=True)
            return ApplyResult(Outcome.FAILED, Stage.MAP_CHECK, f"карта {name} не создана", steps=steps)
    note("карты на месте")

    # --- атомарная подмена -------------------------------------------------------------
    try:
        if target.exists():
            shutil.rmtree(staging)
        else:
            os.replace(staging, target)
        if previous:
            store._swap(store.previous, previous)
        store._swap(store.active, identifier)
        note("ссылка active переключена")
    except OSError as exc:
        return ApplyResult(
            Outcome.FAILED, Stage.SWAP, f"не удалось переключить версию: {type(exc).__name__}", steps=steps
        )

    # --- reload и проверка здоровья ----------------------------------------------------
    env = {"MAIL_CONFIG": str(store.active)}
    problems: list[str] = []
    # При первой загрузке узла Postfix ещё не запущен: перезагружать нечего, и «reload» вернул
    # бы ошибку, которую не следует принимать за неудачную конфигурацию. Мастер подхватит
    # активную версию при старте.
    if runner(["postfix", "status"], env=env).returncode != 0:
        note("мастер Postfix не запущен: перезагрузка не требуется")
        return ApplyResult(
            Outcome.ACTIVE,
            Stage.DONE,
            "конфигурация активна (мастер не запущен)",
            str(target),
            checksum,
            steps=steps,
        )
    reload_result = runner(["postfix", "reload"], env=env)
    if reload_result.returncode != 0:
        problems.append(f"postfix reload: {reload_result.stderr.strip()[:200]}")
    else:
        note("postfix reload выполнен")
        if reload_wait:
            time.sleep(reload_wait)
        if healthcheck is not None:
            problems.extend(healthcheck())

    if not problems:
        note("проверка здоровья пройдена")
        return ApplyResult(
            Outcome.ACTIVE, Stage.DONE, "конфигурация активна", str(target), checksum, steps=steps
        )

    # --- откат -------------------------------------------------------------------------
    if previous:
        try:
            store._swap(store.active, previous)
            runner(["postfix", "reload"], env=env)
            note("выполнен откат на предыдущую версию")
        except OSError as exc:
            return ApplyResult(
                Outcome.FAILED,
                Stage.RELOAD,
                f"откат не удался ({type(exc).__name__}); узел требует вмешательства: {'; '.join(problems)}",
                str(target),
                checksum,
                steps=steps,
            )
        return ApplyResult(
            Outcome.ROLLED_BACK,
            Stage.HEALTH,
            "; ".join(problems),
            str(target),
            checksum,
            rolled_back_to=previous,
            steps=steps,
        )
    return ApplyResult(
        Outcome.FAILED,
        Stage.HEALTH,
        f"предыдущей версии нет, откатываться некуда: {'; '.join(problems)}",
        str(target),
        checksum,
        steps=steps,
    )


def _has_fatal(stderr: str) -> bool:
    """``postfix check`` возвращает 0 и при предупреждениях; фатальными считаются эти слова."""
    lowered = stderr.lower()
    return any(word in lowered for word in ("fatal", "bad configuration", "unknown ", "invalid"))
