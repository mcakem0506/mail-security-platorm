"""Celery application (ТЗ 5 MSP-CORE-02).

Queues are separated so a hanging external provider cannot block the rest of the pipeline:
mail parsing, TI lookups, attachment analysis, campaign work, notifications and maintenance each
have their own queue and can be scaled or paused independently.
"""

from __future__ import annotations

import logging

from celery import Celery
from celery.signals import setup_logging, task_failure
from kombu import Queue
from msp_api.config import get_settings
from msp_api.observability import configure_logging

logger = logging.getLogger(__name__)

QUEUE_MAIL_PARSE = "mail_parse"
QUEUE_TI_LOOKUP = "ti_lookup"
QUEUE_ATTACHMENT = "attachment_analysis"
QUEUE_CAMPAIGN = "campaign"
QUEUE_NOTIFICATIONS = "notifications"
QUEUE_MAINTENANCE = "maintenance"

settings = get_settings()

celery_app = Celery("msp", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,  # long tasks must not be hoarded by one worker
    worker_max_tasks_per_child=200,
    result_expires=3600,
    broker_connection_retry_on_startup=True,
    task_default_queue=QUEUE_MAIL_PARSE,
    task_queues=(
        Queue(QUEUE_MAIL_PARSE),
        Queue(QUEUE_TI_LOOKUP),
        Queue(QUEUE_ATTACHMENT),
        Queue(QUEUE_CAMPAIGN),
        Queue(QUEUE_NOTIFICATIONS),
        Queue(QUEUE_MAINTENANCE),
    ),
    task_routes={
        "msp.enrich_analysis": {"queue": QUEUE_TI_LOOKUP},
        "msp.scan_attachments": {"queue": QUEUE_ATTACHMENT},
        "msp.refresh_campaign": {"queue": QUEUE_CAMPAIGN},
        "msp.send_notification": {"queue": QUEUE_NOTIFICATIONS},
        "msp.poll_security_mailbox": {"queue": QUEUE_MAIL_PARSE},
        "msp.sync_directory": {"queue": QUEUE_MAINTENANCE},
        "msp.run_retention": {"queue": QUEUE_MAINTENANCE},
        "msp.recheck_indicators": {"queue": QUEUE_MAINTENANCE},
        "msp.expire_exceptions": {"queue": QUEUE_MAINTENANCE},
    },
    # Time limits keep a stuck provider from occupying a worker slot indefinitely.
    task_soft_time_limit=180,
    task_time_limit=300,
    beat_schedule={
        "poll-security-mailbox": {
            "task": "msp.poll_security_mailbox",
            "schedule": 60.0,
            "options": {"queue": QUEUE_MAIL_PARSE, "expires": 55},
        },
        "sync-directory": {
            "task": "msp.sync_directory",
            "schedule": float(settings.ad_sync_interval_minutes * 60),
            "options": {"queue": QUEUE_MAINTENANCE},
        },
        "run-retention": {
            "task": "msp.run_retention",
            "schedule": 3600.0 * 6,
            "options": {"queue": QUEUE_MAINTENANCE},
        },
        "recheck-indicators": {
            "task": "msp.recheck_indicators",
            "schedule": 3600.0 * 12,
            "options": {"queue": QUEUE_MAINTENANCE},
        },
        "expire-exceptions": {
            "task": "msp.expire_exceptions",
            "schedule": 3600.0,
            "options": {"queue": QUEUE_MAINTENANCE},
        },
    },
)


@setup_logging.connect
def _configure_worker_logging(**_kwargs: object) -> None:
    configure_logging(settings.log_level, settings.log_format)


@task_failure.connect
def _log_task_failure(sender=None, task_id=None, exception=None, **_kwargs):  # type: ignore[no-untyped-def]
    logger.error(
        "task.failed",
        extra={
            "task": getattr(sender, "name", "unknown"),
            "task_id": task_id,
            "error": type(exception).__name__ if exception else "unknown",
        },
    )


def autodiscover() -> None:
    from . import tasks  # noqa: F401 - registers tasks with the app


autodiscover()
