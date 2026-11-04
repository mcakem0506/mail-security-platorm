"""Асимметричная подпись политики принуждения (MSP 1.3P, ТЗ §9, §18).

Симметричная подпись (общий ключ у панели и узла) означала: кто захватил узел, тот может подписать любую политику от имени панели.
Ed25519 разделяет ключи: подписывает закрытый ключ панели, а узел знает только открытый и подделать пакет не может.

Главное, что проверяется, — не круг «подписал-проверил», а отказы: подмена пакета, чужой ключ, понижение алгоритма до HMAC (когда
узел настроен на открытый ключ) и подмена поля алгоритма.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from msp_enforcement import policy as pol
from msp_enforcement.model import ControlState, ControlType
from msp_enforcement.policy import (
    ALG_ED25519,
    ALG_HMAC,
    ControlPolicy,
    EnforcementPolicy,
    PolicyBundle,
    PolicyCache,
    PolicyError,
    PolicyStatus,
    sign_policy,
    verify_bundle,
)

NOW = datetime.now(UTC)
HMAC_KEY = b"h" * 48


def make_policy(version: str = "v1") -> EnforcementPolicy:
    return EnforcementPolicy(
        version=version,
        controls=(ControlPolicy(control_type=ControlType.SPAM_REJECT, state=ControlState.SHADOW),),
        gaps={"GAP-005": "VALIDATION", "GAP-006": "VALIDATION"},
        valid_from=NOW - timedelta(hours=1),
        valid_until=NOW + timedelta(days=1),
        owner="alice",
        reviewer="bob",
    )


@pytest.fixture
def keys() -> tuple[bytes, bytes]:
    return pol.generate_ed25519_keypair()


class TestKeys:
    def test_a_generated_pair_has_32_byte_keys_and_the_public_key_matches(self, keys) -> None:  # type: ignore[no-untyped-def]
        private, public = keys
        assert len(private) == 32 and len(public) == 32 and private != public
        assert pol.public_key_from_private(private) == public

    def test_two_pairs_differ(self, keys) -> None:  # type: ignore[no-untyped-def]
        assert pol.generate_ed25519_keypair()[0] != keys[0]

    @pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
    def test_a_private_key_of_the_wrong_size_is_refused(self, size: int) -> None:
        with pytest.raises(PolicyError):
            pol.sign_policy_ed25519(make_policy(), b"k" * size)


class TestSignAndVerify:
    def test_a_signed_bundle_verifies_with_the_public_key_only(self, keys) -> None:  # type: ignore[no-untyped-def]
        private, public = keys
        bundle = pol.sign_policy_ed25519(make_policy(), private, issued_at=NOW)

        assert bundle.algorithm == ALG_ED25519
        assert verify_bundle(bundle, public_key=public).checksum() == make_policy().checksum()

    def test_the_signature_is_not_the_hmac_of_anything_a_node_knows(self, keys) -> None:  # type: ignore[no-untyped-def]
        """Подпись Ed25519 имеет длину 64 байта; HMAC-SHA256 — 32. Это разные схемы, а не одна с разными ключами."""
        bundle = pol.sign_policy_ed25519(make_policy(), keys[0])
        assert len(bytes.fromhex(bundle.signature)) == 64
        assert len(bytes.fromhex(sign_policy(make_policy(), HMAC_KEY).signature)) == 32

    def test_a_tampered_policy_is_refused(self, keys) -> None:  # type: ignore[no-untyped-def]
        private, public = keys
        bundle = pol.sign_policy_ed25519(make_policy(), private)
        tampered = bundle.model_copy(update={"policy": bundle.policy.replace('"v1"', '"v2"')})
        with pytest.raises(PolicyError):
            verify_bundle(tampered, public_key=public)

    def test_a_tampered_checksum_with_a_recomputed_digest_is_refused(self, keys) -> None:  # type: ignore[no-untyped-def]
        """Атакующий меняет политику и пересчитывает контрольную сумму: подпись над старой суммой не сходится."""
        import hashlib

        private, public = keys
        bundle = pol.sign_policy_ed25519(make_policy(), private)
        body = bundle.policy.replace('"v1"', '"v2"')
        forged = bundle.model_copy(
            update={"policy": body, "checksum": hashlib.sha256(body.encode()).hexdigest()}
        )
        with pytest.raises(PolicyError):
            verify_bundle(forged, public_key=public)

    def test_a_signature_by_another_key_is_refused(self, keys) -> None:  # type: ignore[no-untyped-def]
        other_private, _ = pol.generate_ed25519_keypair()
        bundle = pol.sign_policy_ed25519(make_policy(), other_private)
        with pytest.raises(PolicyError):
            verify_bundle(bundle, public_key=keys[1])

    def test_a_changed_issue_time_is_refused(self, keys) -> None:  # type: ignore[no-untyped-def]
        private, public = keys
        bundle = pol.sign_policy_ed25519(make_policy(), private, issued_at=NOW)
        later = bundle.model_copy(update={"issued_at": NOW + timedelta(days=30)})
        with pytest.raises(PolicyError):
            verify_bundle(later, public_key=public)

    def test_a_wrong_sized_public_key_on_the_node_fails_closed(self, keys) -> None:  # type: ignore[no-untyped-def]
        bundle = pol.sign_policy_ed25519(make_policy(), keys[0])
        with pytest.raises(PolicyError):
            verify_bundle(bundle, public_key=b"short")
        with pytest.raises(PolicyError):
            verify_bundle(bundle, public_key=b"")


class TestDowngrade:
    def test_a_node_with_a_public_key_refuses_a_hmac_bundle(self, keys) -> None:  # type: ignore[no-untyped-def]
        """Узел с открытым ключом принимает только Ed25519: иначе подпись HMAC понижала бы защиту до общего секрета."""
        bundle = sign_policy(make_policy(), HMAC_KEY)
        assert bundle.algorithm == ALG_HMAC
        with pytest.raises(PolicyError):
            verify_bundle(bundle, HMAC_KEY, public_key=keys[1])

    def test_a_hmac_bundle_forged_with_the_public_key_as_the_secret_is_refused(self, keys) -> None:  # type: ignore[no-untyped-def]
        """Открытый ключ публичен. Если бы узел принимал HMAC, подпись открытым ключом как секретом была бы подделкой."""
        _, public = keys
        forged = sign_policy(make_policy("v666"), public.ljust(32, b"\0"))
        with pytest.raises(PolicyError):
            verify_bundle(forged, public.ljust(32, b"\0"), public_key=public)

    def test_relabelling_an_ed25519_bundle_as_hmac_is_refused(self, keys) -> None:  # type: ignore[no-untyped-def]
        private, public = keys
        bundle = pol.sign_policy_ed25519(make_policy(), private)
        relabelled = bundle.model_copy(update={"algorithm": ALG_HMAC})
        with pytest.raises(PolicyError):
            verify_bundle(relabelled, HMAC_KEY, public_key=public)
        with pytest.raises(PolicyError):
            verify_bundle(relabelled, HMAC_KEY)

    def test_a_node_without_a_public_key_refuses_an_ed25519_bundle(self, keys) -> None:  # type: ignore[no-untyped-def]
        bundle = pol.sign_policy_ed25519(make_policy(), keys[0])
        with pytest.raises(PolicyError):
            verify_bundle(bundle, HMAC_KEY)

    def test_an_unknown_algorithm_is_refused(self, keys) -> None:  # type: ignore[no-untyped-def]
        bundle = pol.sign_policy_ed25519(make_policy(), keys[0]).model_copy(update={"algorithm": "NONE"})
        with pytest.raises(PolicyError):
            verify_bundle(bundle, public_key=keys[1])

    def test_legacy_bundles_without_the_field_still_verify_as_hmac(self) -> None:
        bundle = sign_policy(make_policy(), HMAC_KEY)
        legacy = PolicyBundle.model_validate(
            {k: v for k, v in bundle.model_dump(mode="json").items() if k != "algorithm"}
        )
        assert legacy.algorithm == ALG_HMAC
        assert verify_bundle(legacy, HMAC_KEY).version == "v1"


class TestCache:
    def test_the_cache_installs_and_reloads_an_ed25519_bundle(self, tmp_path: Path, keys) -> None:  # type: ignore[no-untyped-def]
        private, public = keys
        cache = PolicyCache(tmp_path, b"", public_key=public)
        cache.install(pol.sign_policy_ed25519(make_policy(), private, issued_at=NOW), now=NOW)

        policy, status = PolicyCache(tmp_path, b"", public_key=public).load(NOW)
        assert policy is not None and policy.version == "v1" and status is PolicyStatus.FRESH

    def test_a_forged_bundle_does_not_displace_the_good_policy(self, tmp_path: Path, keys) -> None:  # type: ignore[no-untyped-def]
        private, public = keys
        cache = PolicyCache(tmp_path, b"", public_key=public)
        cache.install(pol.sign_policy_ed25519(make_policy("v1"), private, issued_at=NOW), now=NOW)
        attacker_private, _ = pol.generate_ed25519_keypair()

        with pytest.raises(PolicyError):
            cache.install(
                pol.sign_policy_ed25519(make_policy("v2"), attacker_private, issued_at=NOW), now=NOW
            )

        policy, _ = cache.load(NOW)
        assert policy is not None and policy.version == "v1"

    def test_a_cache_written_under_hmac_is_not_trusted_after_switching_to_a_public_key(
        self, tmp_path: Path, keys
    ) -> None:  # type: ignore[no-untyped-def]
        """После перехода на открытый ключ старая копия, подписанная общим секретом, считается недействительной."""
        PolicyCache(tmp_path, HMAC_KEY).install(sign_policy(make_policy(), HMAC_KEY, issued_at=NOW), now=NOW)

        policy, status = PolicyCache(tmp_path, HMAC_KEY, public_key=keys[1]).load(NOW)

        assert policy is None and status in (PolicyStatus.INVALID, PolicyStatus.SAFE_MODE)


def test_the_public_key_encoding_round_trips() -> None:
    private, public = pol.generate_ed25519_keypair()
    assert pol.decode_key(base64.b64encode(public).decode()) == public
    assert pol.decode_key(base64.b64encode(private).decode()) == private
    with pytest.raises(PolicyError):
        pol.decode_key("не-base64!!")
