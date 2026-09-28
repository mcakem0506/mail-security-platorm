"""Security headers, correlation IDs, request-size limits and error handling (ТЗ 30)."""

from __future__ import annotations

import logging
import uuid

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from .observability import Timer, http_duration, http_requests, request_id_var

logger = logging.getLogger(__name__)

# The console renders sanitised mail previews inside a sandboxed iframe; the policy below keeps
# any surviving markup inert even if sanitisation were bypassed (defence in depth, ТЗ 22.3).
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "object-src 'none'"
)
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Cache-Control": "no-store",
    "Content-Security-Policy": _CSP,
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, hsts: bool = True) -> None:
        super().__init__(app)
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if self.hsts and request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request id, records metrics and never leaks internals on failure."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex
        token = request_id_var.set(request_id)
        request.state.request_id = request_id
        timer = Timer()
        route = request.scope.get("route")
        path = getattr(route, "path", request.url.path)
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("request.unhandled_error", extra={"path": path, "method": request.method})
            http_requests.labels(request.method, path, "500").inc()
            request_id_var.reset(token)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Внутренняя ошибка сервера", "request_id": request_id},
                headers={"X-Request-ID": request_id},
            )
        response.headers["X-Request-ID"] = request_id
        http_requests.labels(request.method, path, str(response.status_code)).inc()
        http_duration.labels(request.method, path).observe(timer.elapsed)
        request_id_var.reset(token)
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects oversized requests before they are buffered (ТЗ 30)."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Размер запроса превышает допустимый лимит"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Некорректный заголовок Content-Length"},
                )
        return await call_next(request)
