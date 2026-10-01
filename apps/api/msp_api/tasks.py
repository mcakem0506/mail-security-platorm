"""Task dispatch from the API to the worker.

The API never performs external lookups inline: it enqueues them. When the broker is unavailable
the analysis still stands on its local result, and the job is simply marked as not enriched —
a broker outage must not fail an employee's check (ТЗ 2.3).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

QUEUE_MAIL_PARSE = "mail_parse"
QUEUE_TI_LOOKUP = "ti_lookup"
QUEUE_ATTACHMENT = "attachment_analysis"
QUEUE_CAMPAIGN = "campaign"
QUEUE_NOTIFICATIONS = "notifications"
QUEUE_MAINTENANCE = "maintenance"

ALL_QUEUES = (
    QUEUE_MAIL_PARSE,
    QUEUE_TI_LOOKUP,
    QUEUE_ATTACHMENT,
    QUEUE_CAMPAIGN,
    QUEUE_NOTIFICATIONS,
    QUEUE_MAINTENANCE,
)


def _send(task_name: str, queue: str, *args: object) -> str | None:
    try:
        from msp_worker.app import celery_app
    except ImportError:  # pragma: no cover - worker package not installed alongside the API
        logger.info("tasks.worker_unavailable", extra={"task": task_name})
        return None
    try:
        # ``retry=False`` is what makes the promise above true. Celery's default publish retry
        # policy reconnects up to twenty times before giving up, which turns a broker outage
        # into a request that hangs for well over a minute — the employee waits, then the call
        # fails anyway. Failing immediately and standing on the local verdict is the behaviour
        # this module exists to provide.
        result = celery_app.send_task(
            task_name,
            args=list(args),
            queue=queue,
            retry=False,
            ignore_result=True,
        )
        return str(result.id)
    except Exception as exc:  # noqa: BLE001 - broker problems must not fail the request
        logger.warning("tasks.enqueue_failed", extra={"task": task_name, "error": type(exc).__name__})
        return None


def enqueue_enrichment(job_id: str) -> str | None:
    """Stage 2 of the pipeline: Threat Intelligence and attachment scanning."""
    return _send("msp.enrich_analysis", QUEUE_TI_LOOKUP, job_id)


def enqueue_attachment_scan(job_id: str) -> str | None:
    return _send("msp.scan_attachments", QUEUE_ATTACHMENT, job_id)


def enqueue_campaign_refresh(campaign_id: str) -> str | None:
    return _send("msp.refresh_campaign", QUEUE_CAMPAIGN, campaign_id)


def enqueue_notification(notification_id: str) -> str | None:
    return _send("msp.send_notification", QUEUE_NOTIFICATIONS, notification_id)


def enqueue_mailbox_poll() -> str | None:
    return _send("msp.poll_security_mailbox", QUEUE_MAIL_PARSE)
