"""Подпись политики Ed25519 на пути панель → узел (MSP 1.3P, ТЗ §9, §18).

Модульные тесты проверяют сами отказы подписи. Здесь проверяется то, что видно только на всём пути: панель действительно подписывает
Ed25519, когда задан закрытый ключ; пакет, который получает узел, проверяется открытым ключом и не проверяется общим секретом;
испорченный закрытый ключ не откатывает подпись молча к HMAC.
"""

from __future__ import annotations

import base64
from typing import ClassVar

import pytest
from msp_enforcement import policy as pol
from msp_enforcement.policy import ALG_ED25519, ALG_HMAC, PolicyBundle, PolicyError, verify_bundle

from .test_enforcement_e2e import BASE, KEY, as_, client, enf, node_headers, people  # noqa: F401


@pytest.fixture
def ed25519(enf, monkeypatch):  # type: ignore[no-untyped-def]
    private, public = pol.generate_ed25519_keypair()
    monkeypatch.setattr(enf, "enforcement_policy_signing_private_key", base64.b64encode(private).decode())
    return private, public


def node_bundle(client) -> PolicyBundle:  # type: ignore[no-untyped-def]
    payload = client.get("/api/v1/gateway-agent/enforcement/policy", headers=node_headers()).json()
    return PolicyBundle.model_validate(payload["bundle"])


class TestPanelSigning:
    def test_without_a_private_key_the_panel_still_signs_with_hmac(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        as_(client, people, "admin").get(f"{BASE}/controls")
        bundle = node_bundle(client)

        assert bundle.algorithm == ALG_HMAC
        assert verify_bundle(bundle, KEY.encode()).version

    def test_with_a_private_key_the_node_gets_an_ed25519_bundle(self, client, people, ed25519) -> None:  # type: ignore[no-untyped-def]
        _, public = ed25519
        as_(client, people, "admin").get(f"{BASE}/controls")
        bundle = node_bundle(client)

        assert bundle.algorithm == ALG_ED25519
        assert verify_bundle(bundle, public_key=public).version
        assert len(bytes.fromhex(bundle.signature)) == 64

    def test_the_shared_secret_no_longer_validates_what_the_panel_publishes(
        self, client, people, ed25519
    ) -> None:  # type: ignore[no-untyped-def]
        as_(client, people, "admin").get(f"{BASE}/controls")
        with pytest.raises(PolicyError):
            verify_bundle(node_bundle(client), KEY.encode())

    def test_a_node_that_trusts_another_public_key_refuses_the_bundle(self, client, people, ed25519) -> None:  # type: ignore[no-untyped-def]
        as_(client, people, "admin").get(f"{BASE}/controls")
        _, stranger = pol.generate_ed25519_keypair()
        with pytest.raises(PolicyError):
            verify_bundle(node_bundle(client), public_key=stranger)

    def test_a_corrupt_private_key_is_an_error_and_not_a_silent_fallback_to_hmac(
        self, client, people, enf, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        from msp_api.services import enforcement
        from msp_api.services.enforcement import EnforcementError

        monkeypatch.setattr(enf, "enforcement_policy_signing_private_key", "это не base64!!")
        with pytest.raises(EnforcementError) as caught:
            enforcement._signer(enf)
        assert caught.value.status == 503

        monkeypatch.setattr(
            enf, "enforcement_policy_signing_private_key", base64.b64encode(b"k" * 7).decode()
        )
        with pytest.raises(EnforcementError):
            enforcement._signer(enf)

    def test_the_algorithm_reported_by_the_panel_follows_the_configuration(self, enf, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_api.services.enforcement import signing_algorithm

        assert signing_algorithm(enf) == ALG_HMAC
        monkeypatch.setattr(enf, "enforcement_policy_signing_private_key", "AAAA")
        assert signing_algorithm(enf) == ALG_ED25519


class TestPilotGate:
    FACTS: ClassVar[dict[str, object]] = {
        "signing_algorithm": ALG_ED25519,
        "nodes_ready": 2,
        "nodes_asymmetric": 2,
    }

    def test_ed25519_on_the_panel_and_on_every_ready_node_replaces_the_risk_acceptance(self) -> None:
        from msp_api.services.pilot import _asymmetric_signing

        assert _asymmetric_signing(self.FACTS) is True

    @pytest.mark.parametrize(
        "change",
        [
            {"signing_algorithm": ALG_HMAC},
            {"nodes_ready": 0, "nodes_asymmetric": 0},
            {"nodes_asymmetric": 1},
            {"nodes_asymmetric": 0},
        ],
    )
    def test_anything_less_still_needs_the_written_risk_acceptance(self, change: dict[str, object]) -> None:
        from msp_api.services.pilot import _asymmetric_signing

        assert _asymmetric_signing({**self.FACTS, **change}) is False

    def test_a_node_state_report_carries_how_the_node_verifies(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models_transport import TransportNode
        from msp_api.services import enforcement
        from sqlalchemy import select

        enforcement.note_node_state(db, organization.id, "NODE-A", {"policy_verification": ALG_ED25519})
        db.commit()
        node = db.execute(select(TransportNode).where(TransportNode.node_id == "NODE-A")).scalar_one()
        assert node.details["enforcement"]["policy_verification"] == ALG_ED25519
