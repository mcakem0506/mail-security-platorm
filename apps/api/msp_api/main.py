"""FastAPI application factory (ТЗ 30: OpenAPI, auth, validation, security headers)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import Settings, get_settings
from .middleware import BodySizeLimitMiddleware, RequestContextMiddleware, SecurityHeadersMiddleware
from .observability import configure_logging
from .routers import (
    admin,
    analysis,
    auth,
    dashboard,
    incidents,
    investigations,
    remediation,
    reports,
)

logger = logging.getLogger(__name__)

DESCRIPTION = """
Корпоративная платформа защиты электронной почты для Microsoft Exchange On-Premises.

Работает как Mail Security Companion поверх существующей почтовой инфраструктуры:
анализирует письма, объясняет каждый вердикт, ведёт инциденты и кампании,
и выполняет действия в Exchange только через контролируемый workflow с согласованием.
""".strip()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    logger.info(
        "api.startup",
        extra={
            "environment": settings.environment,
            "vt_mode": settings.vt_mode,
            "remediation_enabled": settings.remediation_enabled,
            "dry_run_only": settings.remediation_dry_run_only,
        },
    )
    # Warm the rule set so a broken rule file fails fast at startup, not on first analysis.
    from .services.analysis import get_ruleset

    ruleset = get_ruleset()
    logger.info("api.rules_loaded", extra={"rule_count": len(ruleset.rules)})
    yield
    logger.info("api.shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="Mail Security Platform API",
        description=DESCRIPTION,
        version="0.9.0",
        root_path=settings.api_root_path,
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes + 1_000_000)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.cookie_secure)
    app.add_middleware(RequestContextMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Field names and messages only: request bodies may contain message content.
        fields = [
            {"field": ".".join(str(p) for p in e.get("loc", ())[1:]), "error": e.get("msg", "")}
            for e in exc.errors()[:20]
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Некорректные данные запроса",
                "fields": fields,
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "request_id": getattr(request.state, "request_id", None)},
            headers=getattr(exc, "headers", None),
        )

    api_prefix = "/api/v1"
    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(analysis.router, prefix=api_prefix)
    app.include_router(investigations.router, prefix=api_prefix)
    app.include_router(incidents.router, prefix=api_prefix)
    app.include_router(remediation.router, prefix=api_prefix)
    app.include_router(reports.router, prefix=api_prefix)
    app.include_router(admin.router, prefix=f"{api_prefix}/admin")
    app.include_router(dashboard.router, prefix=api_prefix)
    app.include_router(dashboard.health_router)
    app.include_router(dashboard.metrics_router)

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {"service": "mail-security-platform", "version": app.version, "docs": "/docs"}

    return app


app = create_app()
