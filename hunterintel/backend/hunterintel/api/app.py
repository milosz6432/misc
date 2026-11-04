"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from hunterintel import __version__
from hunterintel.api import routes_indicators, routes_investigations, routes_tools
from hunterintel.api.deps import Container, build_container
from hunterintel.config import Settings, get_settings
from hunterintel.db.session import create_schema
from hunterintel.domain.indicators import IndicatorParseError
from hunterintel.providers.dnsclient import DnsClient
from hunterintel.services.investigations import WorkspaceError

log = logging.getLogger("hunterintel")
MAX_JSON_BODY = 1_000_000
UPLOAD_PATHS = ("/api/v1/tools/file-hash",)


class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Reject oversized request bodies (the upload tool enforces its own, larger limit)."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_JSON_BODY) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in UPLOAD_PATHS:
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(send)
            return
        seen = 0

        async def limited() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise _TooLarge
            return message

        try:
            await self.app(scope, limited, send)
        except _TooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":{"code":"too_large","message":"request body too large"}}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def create_app(
    settings: Settings | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    dns: DnsClient | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    container = build_container(settings, transport=transport, dns=dns)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if settings.auto_create_schema:
            await create_schema(container.engine)
        app.state.container = container
        if settings.api_token is None and settings.environment == "production":
            log.warning("HUNTERINTEL_API_TOKEN is not set: the API is unauthenticated")
        yield
        await container.aclose()

    app = FastAPI(
        title=f"{settings.app_name} API",
        version=__version__,
        description=(
            "Modular OSINT & Cyber Threat Intelligence platform.\n\n"
            "Every datum is labelled **verified**, **provider_claim** or **inferred**; anything not "
            "obtained is reported as an explicit provider run status. Nothing is sent to a third party "
            "unless a provider is selected in an enrichment request (see `/indicators/classify` for the plan)."
        ),
        lifespan=lifespan,
    )
    app.state.container = container  # available for tests that skip lifespan

    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Filename"],
        max_age=600,
    )

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[JSONResponse]]
    ) -> JSONResponse:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(IndicatorParseError)
    async def _bad_indicator(_: Request, exc: IndicatorParseError) -> JSONResponse:
        return JSONResponse(
            status_code=422, content={"detail": {"code": "invalid_indicator", "message": str(exc)}}
        )

    @app.exception_handler(WorkspaceError)
    async def _bad_workspace(_: Request, exc: WorkspaceError) -> JSONResponse:
        return JSONResponse(
            status_code=422, content={"detail": {"code": "invalid_request", "message": str(exc)}}
        )

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        return JSONResponse(
            status_code=500,
            content={"detail": {"code": "internal_error", "message": "internal error"}},
        )

    app.include_router(routes_indicators.public)
    app.include_router(routes_indicators.router)
    app.include_router(routes_investigations.router)
    app.include_router(routes_tools.router)
    return app


def app_factory() -> FastAPI:  # `uvicorn hunterintel.api.app:app_factory --factory`
    return create_app()


__all__ = ["Container", "app_factory", "create_app"]
