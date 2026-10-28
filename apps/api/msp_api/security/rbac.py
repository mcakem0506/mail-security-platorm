"""Role-based access control and object-level authorization (ТЗ 23, 30).

Two separate concerns:
* permissions — what a role may do at all;
* object-level checks — whether *this* actor may touch *this* object. An employee may only ever
  see their own analyses, and platform administration is kept apart from message investigation.
"""

from __future__ import annotations

from enum import StrEnum

from msp_contracts import Role


class Permission(StrEnum):
    # employee scope
    ANALYZE_OWN_MESSAGE = "analyze:own"
    VIEW_OWN_RESULT = "view:own_result"
    REPORT_PHISHING = "report:phishing"

    # investigation scope
    VIEW_INVESTIGATIONS = "view:investigations"
    VIEW_MESSAGE_CONTENT = "view:message_content"
    DOWNLOAD_ATTACHMENT = "download:attachment"
    SEARCH_INDICATORS = "search:indicators"
    VIEW_CAMPAIGNS = "view:campaigns"
    VIEW_INCIDENTS = "view:incidents"
    MANAGE_INCIDENTS = "manage:incidents"
    CLASSIFY_MESSAGE = "classify:message"
    CREATE_EXCEPTION = "create:exception"
    PROPOSE_REMEDIATION = "propose:remediation"
    EXPORT_DATA = "export:data"

    # detection quality and rule lifecycle (ТЗ 1.0.3 §55)
    CLASSIFY_INCIDENT = "incident:classify"
    VIEW_DETECTION_QUALITY = "quality:read"
    REPORT_MISSED_DETECTION = "detection:report_miss"
    SIMULATE_DETECTION = "detection:simulate"
    PROPOSE_RULE = "detection:propose"
    #: Edit a candidate pack: create it, benchmark it, send it for review.
    EDIT_RULES = "detection:edit"
    #: Review someone else's candidate. Separate from editing so that the person who wrote
    #: a change and the person who approves it can be required to differ (§12).
    REVIEW_RULES = "detection:review"
    #: Publish a release. Deliberately not given to an analyst by default (§39): publishing
    #: decides what the whole organisation is protected by.
    PUBLISH_RULES = "detection:publish"
    #: Run a bulk re-evaluation of history.
    REEVALUATE = "detection:reevaluate"
    #: Changing a rule's lifecycle status changes what every future verdict says, so it is an
    #: administrative act even though the rule file itself lives in Git.
    MANAGE_DETECTION_RULES = "detection:manage"
    MANAGE_DETECTION_GAPS = "gap:manage"
    #: Starting or deciding a rollout changes who a rule decides for, which is the same
    #: kind of power as changing its status.
    MANAGE_CANARY = "detection:canary"
    #: Re-evaluating history can rewrite stored verdicts, which is why it is separate from
    #: simulating: a simulation changes nothing, a replay with apply does.
    EXECUTE_REPLAY = "detection:replay"

    # administration scope
    APPROVE_REMEDIATION = "approve:remediation"
    #: An exception switches detection off for something. Approving one is deliberately not the
    #: same permission as creating one, so no single analyst can silence a rule alone.
    APPROVE_EXCEPTION = "exception:approve"
    EXECUTE_REMEDIATION = "execute:remediation"
    MANAGE_POLICIES = "manage:policies"
    MANAGE_PROVIDERS = "manage:providers"
    MANAGE_PROTECTED_IDENTITIES = "manage:protected_identities"
    MANAGE_INTEGRATIONS = "manage:integrations"
    MANAGE_USERS = "manage:users"
    VIEW_AUDIT = "view:audit"

    # platform scope
    MANAGE_PLATFORM = "manage:platform"
    VIEW_SYSTEM_HEALTH = "view:system_health"

    # real-flow validation scope (ТЗ 1.0.4 §24)
    VIEW_REAL_FLOW = "realflow:read"
    #: Сказать, что было на самом деле: обычная работа аналитика.
    REVIEW_REAL_FLOW = "realflow:review"
    #: Предложить письмо в набор, по которому платформу будут мерить годами. Отдельно от
    #: разбора: у них разная цена ошибки, а согласующий не может быть автором заявки.
    PROMOTE_REAL_FLOW = "realflow:promote"
    VIEW_READINESS = "readiness:read"
    #: Подтвердить, что пробел действительно закрыт на реальной почте. Не то же, что закрыть его
    #: в реестре (``gap:manage``).
    VALIDATE_GAP = "gap:validate"

    # транспорт почты (ТЗ 1.1 §42, §43)
    VIEW_GATEWAY = "gateway:read"
    VIEW_GATEWAY_CONFIG = "gateway:config:read"
    VALIDATE_GATEWAY_CONFIG = "gateway:config:validate"
    #: Применение конфигурации меняет то, кого и как принимает почтовая граница организации.
    ACTIVATE_GATEWAY_CONFIG = "gateway:config:activate"
    ROLLBACK_GATEWAY_CONFIG = "gateway:config:rollback"
    VIEW_GATEWAY_QUEUE = "gateway:queue:read"
    #: Слив узла останавливает приём почты на нём: действие администратора, не аналитика.
    DRAIN_GATEWAY_NODE = "gateway:node:drain"
    SYNC_GATEWAY_RECIPIENTS = "gateway:recipient:sync"
    VIEW_GATEWAY_TLS = "gateway:tls:read"
    #: Повторить доставку отложенной почты. Удаление писем из очереди через панель не предусмотрено
    #: (только ручной разбор на узле): оно необратимо и в 1.1 не автоматизируется.
    ADMIN_GATEWAY_QUEUE = "gateway:queue:admin"

    # анти-спам, аутентификация и репутация (ТЗ 1.2 §34)
    VIEW_SPAM = "spam:read"
    EDIT_SPAM_POLICY = "spam:policy:edit"
    #: Одобрить кандидата политики может не тот, кто его правил (четыре глаза).
    APPROVE_SPAM_POLICY = "spam:policy:approve"
    SIMULATE_SPAM_POLICY = "spam:simulate"
    VIEW_AUTH = "auth:read"
    REVIEW_AUTH_CONFLICT = "auth:conflict:review"
    VIEW_REPUTATION = "reputation:read"
    #: Включение провайдера репутации уносит данные письма во внешний DNS и требует лицензии.
    MANAGE_REPUTATION_PROVIDER = "reputation:provider:manage"
    VIEW_DKIM = "dkim:read"
    GENERATE_DKIM_KEY = "dkim:key:generate"
    #: Активация ключа подписи — отдельное право: подпись от имени организации необратима для получателей.
    ACTIVATE_DKIM_KEY = "dkim:key:activate"
    RETIRE_DKIM_KEY = "dkim:key:retire"

    # принуждение и карантин (ТЗ 1.3 §60). Исключения принуждения используют уже существующие
    # create:exception и exception:approve.
    VIEW_ENFORCEMENT = "enforcement:read"
    SIMULATE_ENFORCEMENT = "enforcement:simulate"
    CANARY_ENFORCEMENT = "enforcement:canary"
    #: Пилот — повышенное согласование: второй человек с этим же правом (четыре глаза).
    PILOT_ENFORCEMENT = "enforcement:pilot"
    PAUSE_ENFORCEMENT = "enforcement:pause"
    ROLLBACK_ENFORCEMENT = "enforcement:rollback"
    #: Включить общий выключатель быстро и в одиночку; снять — только с подтверждением второго.
    KILL_SWITCH = "enforcement:kill_switch"
    VIEW_QUARANTINE = "quarantine:read"
    RELEASE_QUARANTINE = "quarantine:release"
    DELETE_QUARANTINE = "quarantine:delete"

    # пилот реального потока (ТЗ 1.3P §24): чтение метрик и готовности; ведение подтверждений, решений и
    # остановок;
    # подтверждение решения о фазе. Ни одно из этих прав не включает контроль принуждения.
    VIEW_PILOT = "pilot:read"
    MANAGE_PILOT = "pilot:manage"
    APPROVE_PILOT = "pilot:approve"


_EMPLOYEE: frozenset[Permission] = frozenset(
    {Permission.ANALYZE_OWN_MESSAGE, Permission.VIEW_OWN_RESULT, Permission.REPORT_PHISHING}
)
_VIEWER: frozenset[Permission] = _EMPLOYEE | {
    Permission.VIEW_DETECTION_QUALITY,
    Permission.VIEW_INVESTIGATIONS,
    Permission.VIEW_MESSAGE_CONTENT,
    Permission.SEARCH_INDICATORS,
    Permission.VIEW_CAMPAIGNS,
    Permission.VIEW_INCIDENTS,
    Permission.VIEW_REAL_FLOW,
    Permission.VIEW_READINESS,
    Permission.VIEW_GATEWAY,
    Permission.VIEW_GATEWAY_QUEUE,
    Permission.VIEW_GATEWAY_TLS,
    Permission.VIEW_SPAM,
    Permission.VIEW_AUTH,
    Permission.VIEW_REPUTATION,
    Permission.VIEW_ENFORCEMENT,
    Permission.VIEW_PILOT,
}
_ANALYST: frozenset[Permission] = _VIEWER | {
    Permission.SIMULATE_SPAM_POLICY,
    Permission.REVIEW_AUTH_CONFLICT,
    Permission.CLASSIFY_INCIDENT,
    Permission.REPORT_MISSED_DETECTION,
    Permission.SIMULATE_DETECTION,
    Permission.PROPOSE_RULE,
    Permission.EDIT_RULES,
    Permission.MANAGE_INCIDENTS,
    Permission.CLASSIFY_MESSAGE,
    Permission.CREATE_EXCEPTION,
    Permission.PROPOSE_REMEDIATION,
    Permission.DOWNLOAD_ATTACHMENT,
    Permission.EXPORT_DATA,
    Permission.REVIEW_REAL_FLOW,
    Permission.SIMULATE_ENFORCEMENT,
    Permission.VIEW_QUARANTINE,
    Permission.RELEASE_QUARANTINE,
}
_SECURITY_ADMIN: frozenset[Permission] = _ANALYST | {
    Permission.APPROVE_EXCEPTION,
    Permission.MANAGE_DETECTION_RULES,
    Permission.MANAGE_DETECTION_GAPS,
    Permission.MANAGE_CANARY,
    Permission.REVIEW_RULES,
    Permission.PUBLISH_RULES,
    Permission.REEVALUATE,
    Permission.EXECUTE_REPLAY,
    Permission.APPROVE_REMEDIATION,
    Permission.EXECUTE_REMEDIATION,
    Permission.MANAGE_POLICIES,
    Permission.MANAGE_PROVIDERS,
    Permission.MANAGE_PROTECTED_IDENTITIES,
    Permission.MANAGE_INTEGRATIONS,
    Permission.MANAGE_USERS,
    Permission.VIEW_AUDIT,
    Permission.PROMOTE_REAL_FLOW,
    Permission.VALIDATE_GAP,
    Permission.VIEW_GATEWAY_CONFIG,
    Permission.VALIDATE_GATEWAY_CONFIG,
    Permission.ACTIVATE_GATEWAY_CONFIG,
    Permission.ROLLBACK_GATEWAY_CONFIG,
    Permission.DRAIN_GATEWAY_NODE,
    Permission.SYNC_GATEWAY_RECIPIENTS,
    Permission.ADMIN_GATEWAY_QUEUE,
    Permission.EDIT_SPAM_POLICY,
    Permission.APPROVE_SPAM_POLICY,
    Permission.MANAGE_REPUTATION_PROVIDER,
    Permission.VIEW_DKIM,
    Permission.GENERATE_DKIM_KEY,
    Permission.ACTIVATE_DKIM_KEY,
    Permission.RETIRE_DKIM_KEY,
    Permission.CANARY_ENFORCEMENT,
    Permission.PILOT_ENFORCEMENT,
    Permission.PAUSE_ENFORCEMENT,
    Permission.ROLLBACK_ENFORCEMENT,
    Permission.KILL_SWITCH,
    Permission.DELETE_QUARANTINE,
    Permission.MANAGE_PILOT,
    Permission.APPROVE_PILOT,
}
# Platform Admin runs the infrastructure and is deliberately NOT granted message content access
# by default (ТЗ 23). Granting it is a policy decision recorded in the audit trail.
_PLATFORM_ADMIN: frozenset[Permission] = frozenset(
    {
        Permission.MANAGE_PLATFORM,
        Permission.VIEW_SYSTEM_HEALTH,
        Permission.MANAGE_USERS,
        Permission.MANAGE_PROVIDERS,
        Permission.MANAGE_INTEGRATIONS,
        Permission.VIEW_AUDIT,
        # Платформа эксплуатируется администратором платформы: узлы, очередь, TLS и слив.
        # Содержимое писем остаётся недоступным (см. комментарий выше).
        Permission.VIEW_GATEWAY,
        Permission.VIEW_GATEWAY_CONFIG,
        Permission.VALIDATE_GATEWAY_CONFIG,
        Permission.VIEW_GATEWAY_QUEUE,
        Permission.DRAIN_GATEWAY_NODE,
        Permission.ADMIN_GATEWAY_QUEUE,
        Permission.VIEW_GATEWAY_TLS,
        # Состояние сканера и репутации видно, чтобы эксплуатировать; политика и ключи — не его.
        Permission.VIEW_SPAM,
        Permission.VIEW_AUTH,
        Permission.VIEW_REPUTATION,
        Permission.VIEW_DKIM,
        # Администратор платформы может остановить принуждение, но не включить его и не читать письма.
        Permission.VIEW_ENFORCEMENT,
        Permission.PAUSE_ENFORCEMENT,
        Permission.KILL_SWITCH,
    }
)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.EMPLOYEE: _EMPLOYEE,
    Role.SECURITY_VIEWER: _VIEWER,
    Role.SECURITY_ANALYST: _ANALYST,
    Role.SECURITY_ADMIN: _SECURITY_ADMIN,
    Role.PLATFORM_ADMIN: _PLATFORM_ADMIN,
}

PRIVILEGED_ROLES_LABEL: frozenset[Role] = frozenset({Role.SECURITY_ADMIN, Role.PLATFORM_ADMIN})

ROLE_LABELS: dict[Role, str] = {
    Role.EMPLOYEE: "Сотрудник",
    Role.SECURITY_VIEWER: "Наблюдатель ИБ",
    Role.SECURITY_ANALYST: "Аналитик ИБ",
    Role.SECURITY_ADMIN: "Администратор ИБ",
    Role.PLATFORM_ADMIN: "Администратор платформы",
}


def permissions_for(role: Role) -> frozenset[Permission]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in permissions_for(role)


def can_view_all_messages(role: Role) -> bool:
    return has_permission(role, Permission.VIEW_INVESTIGATIONS)


def can_access_job(
    *, role: Role, actor_user_id: str, actor_mailbox: str, job_owner_id: str | None, job_mailbox: str
) -> bool:
    """Object-level check for an analysis job (ТЗ 40.6: no cross-user result access)."""
    if can_view_all_messages(role):
        return True
    if not has_permission(role, Permission.VIEW_OWN_RESULT):
        return False
    if job_owner_id and job_owner_id == actor_user_id:
        return True
    return bool(actor_mailbox) and actor_mailbox.lower() == (job_mailbox or "").lower()


def can_approve_exception(
    *, role: Role, approver_id: str, approver_email: str, created_by: str
) -> tuple[bool, str]:
    """Four-eyes rule for detection exceptions (ТЗ 1.0.3 §24).

    An exception is the one control that makes the platform deliberately blind to something, so
    the person who asked for it may not be the person who grants it — otherwise "two approvals"
    is a formality one analyst can complete alone.
    """
    if not has_permission(role, Permission.APPROVE_EXCEPTION):
        return False, "роль не вправе утверждать исключения детектирования"
    created = (created_by or "").strip().lower()
    if created and created in {approver_id.strip().lower(), approver_email.strip().lower()}:
        return False, "автор исключения не может утвердить его сам"
    return True, ""


def required_approvals(affected_mailboxes: int, threshold: int = 10) -> int:
    """Two-person approval for bulk operations (ТЗ 20.1)."""
    return 2 if affected_mailboxes > threshold else 1


def can_approve(
    *, role: Role, approver_id: str, proposer_id: str, existing_approvers: set[str]
) -> tuple[bool, str]:
    """Approval rules: admin only, never self-approval, never the same person twice."""
    if not has_permission(role, Permission.APPROVE_REMEDIATION):
        return False, "role is not permitted to approve remediation"
    if approver_id == proposer_id:
        return False, "the proposer cannot approve their own remediation request"
    if approver_id in existing_approvers:
        return False, "this approver has already decided on the request"
    return True, ""
