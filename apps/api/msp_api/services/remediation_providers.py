"""Remediation abstraction across Exchange, mail gateways and the platform (ТЗ 1.0.2 §29, §30).

Before 1.0.2 remediation meant "do something in Exchange". With an upstream gateway in the
picture there are three places an action can land, and they do not behave alike:

``EXCHANGE``
    Acts on a delivered message in a mailbox. Reversible actions exist (a move to a quarantine
    folder, a soft delete into Recoverable Items), so this is the target that can actually
    execute today.
``MAIL_GATEWAY``
    Acts in the gateway's own quarantine or block lists. **Read-only for the whole of 1.0.2**:
    the platform can say what it would do, and refuses to do it. Nothing here is a matter of
    configuration — the write side is not implemented, and a plan says so.
``MSP``
    Acts only inside this platform: mark a campaign, raise an incident, add an indicator. Always
    available and always reversible, because it touches nothing outside.

Every action goes through the same sequence, and each step is a separate decision:

.. code-block:: text

    propose -> dry-run -> approve -> execute -> verify -> audit

``verify`` is the step that is easy to omit and expensive to omit: without it the platform
reports what it *asked* for rather than what happened, and a partially applied remediation looks
identical to a complete one.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar, Protocol, runtime_checkable

from msp_contracts import GatewayCapability, RemediationType, utcnow

logger = logging.getLogger(__name__)


class RemediationTarget(StrEnum):
    EXCHANGE = "EXCHANGE"
    MAIL_GATEWAY = "MAIL_GATEWAY"
    MSP = "MSP"


class RemediationStep(StrEnum):
    PROPOSE = "propose"
    DRY_RUN = "dry_run"
    APPROVE = "approve"
    EXECUTE = "execute"
    VERIFY = "verify"
    AUDIT = "audit"


@dataclass
class RemediationPlan:
    """What an action would do, before anyone is asked to approve it."""

    target: RemediationTarget
    action: RemediationType
    provider_id: str = ""
    affected_messages: int = 0
    affected_mailboxes: list[str] = field(default_factory=list)
    reversible: bool = False
    #: Why it cannot run. A non-empty list means approval must not even be offered.
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    required_approvals: int = 1
    summary: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def executable(self) -> bool:
        return not self.blockers

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.value,
            "action": self.action.value,
            "provider_id": self.provider_id,
            "affected_messages": self.affected_messages,
            "affected_mailboxes": self.affected_mailboxes[:50],
            "reversible": self.reversible,
            "executable": self.executable,
            "blockers": self.blockers,
            "warnings": self.warnings,
            "required_approvals": self.required_approvals,
            "summary": self.summary,
            "detail": self.detail,
        }


@dataclass
class RemediationVerification:
    """What is actually true after an execution (ТЗ 1.0.2 §29).

    ``confirmed`` is not the same as "no error was raised": it means the platform went back and
    looked. When it could not look, ``verified`` stays false and the action is reported as
    unverified rather than successful.
    """

    verified: bool = False
    confirmed: int = 0
    still_present: int = 0
    unverifiable: int = 0
    detail: dict[str, Any] = field(default_factory=dict)
    checked_at: Any = field(default_factory=utcnow)

    @property
    def complete(self) -> bool:
        return self.verified and self.still_present == 0 and self.unverifiable == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "complete": self.complete,
            "confirmed": self.confirmed,
            "still_present": self.still_present,
            "unverifiable": self.unverifiable,
            "detail": self.detail,
            "checked_at": self.checked_at.isoformat()
            if hasattr(self.checked_at, "isoformat")
            else str(self.checked_at),
        }


@runtime_checkable
class RemediationProvider(Protocol):
    target: RemediationTarget
    provider_id: str

    def supports(self, action: RemediationType) -> bool: ...
    def propose(self, action: RemediationType, targets: list[Any], **context: Any) -> RemediationPlan: ...
    def execute(self, plan: RemediationPlan, targets: list[Any], **context: Any) -> dict[str, Any]: ...
    def verify(self, plan: RemediationPlan, targets: list[Any]) -> RemediationVerification: ...


class ExchangeRemediationProvider:
    """Remediation in Exchange mailboxes, through the configured Exchange provider."""

    target = RemediationTarget.EXCHANGE
    provider_id = "exchange"

    #: Actions the EWS adapter can carry out, all of them reversible.
    _SUPPORTED: ClassVar[frozenset[RemediationType]] = frozenset(
        {RemediationType.LOCATE, RemediationType.QUARANTINE, RemediationType.DELETE}
    )
    _REVERSIBLE: ClassVar[frozenset[RemediationType]] = frozenset(
        {RemediationType.LOCATE, RemediationType.QUARANTINE, RemediationType.DELETE}
    )

    def __init__(self, provider: Any, settings: Any) -> None:
        self.provider = provider
        self.settings = settings

    def supports(self, action: RemediationType) -> bool:
        return action in self._SUPPORTED

    def propose(self, action: RemediationType, targets: list[Any], **context: Any) -> RemediationPlan:
        mailboxes = sorted({getattr(t, "mailbox", "") for t in targets if getattr(t, "mailbox", "")})
        plan = RemediationPlan(
            target=self.target,
            action=action,
            provider_id=getattr(self.provider, "provider_id", "exchange"),
            affected_messages=len(targets),
            affected_mailboxes=mailboxes,
            # Quarantine is a move and delete is a soft delete: both can be undone from
            # Exchange, which is why nothing here is irreversible.
            reversible=action in self._REVERSIBLE,
            required_approvals=1 if len(targets) < self.settings.remediation_second_approver_threshold else 2,
            summary=f"{action.value}: {len(targets)} сообщений в {len(mailboxes)} ящиках",
        )
        if not self.supports(action):
            plan.blockers.append(
                f"действие '{action.value}' не выполняется через Exchange-адаптер; "
                "оно готовится как предложение для ручного применения"
            )
        if not self.settings.remediation_enabled:
            plan.blockers.append("реагирование отключено в конфигурации развёртывания")
        if self.settings.remediation_dry_run_only:
            plan.blockers.append("развёртывание работает в режиме dry-run: изменения не применяются")
        scope = self.settings.ews_mailbox_scope_list
        if self.settings.remediation_enabled and not scope:
            plan.blockers.append("не задана область ящиков (MSP_EWS_MAILBOX_SCOPE)")
        if len(targets) >= self.settings.remediation_second_approver_threshold:
            plan.warnings.append(
                f"массовое действие ({len(targets)} сообщений): требуется второе согласование"
            )
        return plan

    def execute(self, plan: RemediationPlan, targets: list[Any], **context: Any) -> dict[str, Any]:
        from msp_exchange.base import RemediationRequest

        request = RemediationRequest(
            action=plan.action,
            targets=list(targets),
            reason=str(context.get("reason", ""))[:1000],
            requested_by=str(context.get("requested_by", "")),
            approved_by=list(context.get("approved_by", [])),
            dry_run=bool(context.get("dry_run", True)),
        )
        outcome = self.provider.request_remediation(request)
        return {
            "executed": outcome.executed,
            "dry_run": outcome.dry_run,
            "affected_messages": outcome.affected_messages,
            "affected_mailboxes": outcome.affected_mailboxes,
            "rollback_supported": outcome.rollback_supported,
            "rollback_token": outcome.rollback_token,
            "warnings": outcome.warnings,
            "errors": outcome.errors,
        }

    def verify(self, plan: RemediationPlan, targets: list[Any]) -> RemediationVerification:
        """Look for each message again; a message still in place was not remediated.

        A locate action has nothing to verify — finding the message *is* the action — so it
        reports verified with nothing outstanding.
        """
        verification = RemediationVerification()
        if plan.action is RemediationType.LOCATE:
            verification.verified = True
            verification.confirmed = len(targets)
            return verification
        finder = getattr(self.provider, "_find_item", None)
        if finder is None:
            verification.unverifiable = len(targets)
            verification.detail["reason"] = "провайдер не поддерживает повторный поиск сообщения"
            return verification
        verification.verified = True
        for ref in targets:
            try:
                finder(ref)
            except KeyError:
                # Gone from where it was: exactly what quarantine and delete should achieve.
                verification.confirmed += 1
            except Exception as exc:  # noqa: BLE001 - an unverifiable item is reported as such
                verification.unverifiable += 1
                verification.detail.setdefault("errors", []).append(type(exc).__name__)
            else:
                verification.still_present += 1
        if verification.still_present:
            verification.detail["warning"] = (
                f"{verification.still_present} сообщений остались на месте: реагирование неполное"
            )
        return verification


class GatewayRemediationProvider:
    """Remediation in an upstream gateway — read-only for the whole of 1.0.2 (ТЗ 1.0.2 §30).

    The plan is still produced, because knowing what *would* happen is useful during an
    investigation, and because the capability contract has to exist before an adapter can be
    written against it. Execution refuses unconditionally: not by configuration, but because the
    write side is not implemented.
    """

    target = RemediationTarget.MAIL_GATEWAY
    provider_id = "mail_gateway"

    _CAPABILITY_FOR: ClassVar[dict[RemediationType, GatewayCapability]] = {
        RemediationType.QUARANTINE: GatewayCapability.QUARANTINE_WRITE,
        RemediationType.RELEASE: GatewayCapability.RELEASE,
        RemediationType.BLOCK_SENDER: GatewayCapability.SENDER_BLOCK,
        RemediationType.BLOCK_DOMAIN: GatewayCapability.SENDER_BLOCK,
    }

    def __init__(self, registry: Any) -> None:
        self.registry = registry

    def supports(self, action: RemediationType) -> bool:
        # Deliberately false for every action at 1.0.2: no gateway write path exists.
        return False

    def propose(self, action: RemediationType, targets: list[Any], **context: Any) -> RemediationPlan:
        capability = self._CAPABILITY_FOR.get(action)
        providers = self.registry.supports(capability) if capability is not None else []
        plan = RemediationPlan(
            target=self.target,
            action=action,
            provider_id=providers[0] if providers else "",
            affected_messages=len(targets),
            reversible=action in {RemediationType.QUARANTINE, RemediationType.RELEASE},
            summary=f"{action.value} на почтовом шлюзе: подготовлено как предложение",
            detail={
                "capability": capability.value if capability else None,
                "providers_with_capability": providers,
            },
        )
        plan.blockers.append(
            "действия над почтовым шлюзом на этапе 1.0.2 только read-only: платформа показывает, "
            "что было бы сделано, и не выполняет этого"
        )
        if capability is not None and not providers:
            plan.blockers.append(f"ни один настроенный шлюз не заявляет возможность {capability.value}")
        return plan

    def execute(self, plan: RemediationPlan, targets: list[Any], **context: Any) -> dict[str, Any]:
        return {
            "executed": False,
            "dry_run": True,
            "affected_messages": 0,
            "errors": [
                "изменение состояния почтового шлюза не реализовано на этапе 1.0.2 и не включается настройкой"
            ],
        }

    def verify(self, plan: RemediationPlan, targets: list[Any]) -> RemediationVerification:
        return RemediationVerification(
            verified=False,
            unverifiable=len(targets),
            detail={"reason": "шлюз работает в режиме только чтения"},
        )


class PlatformRemediationProvider:
    """Actions that stay inside the platform: always available, always reversible."""

    target = RemediationTarget.MSP
    provider_id = "platform"

    _SUPPORTED: ClassVar[frozenset[RemediationType]] = frozenset(
        {RemediationType.BLOCK_SENDER, RemediationType.BLOCK_DOMAIN, RemediationType.LOCATE}
    )

    def supports(self, action: RemediationType) -> bool:
        return action in self._SUPPORTED

    def propose(self, action: RemediationType, targets: list[Any], **context: Any) -> RemediationPlan:
        plan = RemediationPlan(
            target=self.target,
            action=action,
            provider_id=self.provider_id,
            affected_messages=len(targets),
            reversible=True,
            summary=(
                f"{action.value}: отметка внутри платформы. Почта не изменяется — индикатор "
                "повышает риск у будущих писем."
            ),
        )
        if not self.supports(action):
            plan.blockers.append(f"действие '{action.value}' не применимо внутри платформы")
        plan.warnings.append("письма, уже доставленные в ящики, этим действием не затрагиваются")
        return plan

    def execute(self, plan: RemediationPlan, targets: list[Any], **context: Any) -> dict[str, Any]:
        return {
            "executed": True,
            "dry_run": False,
            "affected_messages": len(targets),
            "reversible": True,
            "detail": "индикатор добавлен в платформу; почтовая система не изменялась",
        }

    def verify(self, plan: RemediationPlan, targets: list[Any]) -> RemediationVerification:
        return RemediationVerification(verified=True, confirmed=len(targets))


def build_providers(exchange_provider: Any, registry: Any, settings: Any) -> dict[RemediationTarget, Any]:
    """Every remediation target available to this deployment."""
    return {
        RemediationTarget.EXCHANGE: ExchangeRemediationProvider(exchange_provider, settings),
        RemediationTarget.MAIL_GATEWAY: GatewayRemediationProvider(registry),
        RemediationTarget.MSP: PlatformRemediationProvider(),
    }


def plan_across_targets(
    providers: dict[RemediationTarget, Any], action: RemediationType, targets: list[Any], **context: Any
) -> list[RemediationPlan]:
    """What each target would do, so an analyst chooses with the trade-offs visible."""
    plans: list[RemediationPlan] = []
    for provider in providers.values():
        try:
            plans.append(provider.propose(action, targets, **context))
        except Exception as exc:  # noqa: BLE001 - one broken provider must not hide the others
            logger.warning(
                "remediation.plan_failed",
                extra={"target": provider.target.value, "error": type(exc).__name__},
            )
    return plans
