"""CyberShield AI — Application Entry Point

FastAPI application factory, middleware configuration, structured error handling,
and router registration.
"""

from datetime import datetime, timezone
import logging
from pathlib import Path
import sys
from typing import Dict, Any
import uuid

# Ensure backend directory is in sys.path so 'app' imports resolve regardless of working directory (F-01)
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import get_settings
from app.api.v1.router import router as api_v1_router, HealthCheckResponse
from app.database import init_db

# Configure logging
settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
logger = logging.getLogger("cybershield")


def create_application() -> FastAPI:
    """Initialize and configure the FastAPI application."""
    # Ensure database schema is initialized
    try:
        init_db()
    except Exception as exc:
        logger.warning("Database auto-initialization deferred or failed: %s", exc)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "CyberShield AI: AI-Powered Web Threat Detection & Digital Trust Intelligence.\n\n"
            "Central API backend coordinating technical inspection, scam analysis, "
            "deterministic risk aggregation, threat intelligence, and decentralized report integrity."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --------------------------------------------------------------------------
    # Custom Structured Exception Handlers
    # --------------------------------------------------------------------------

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Handle standard HTTP exceptions with structured response, preventing leakage of internal details (F-04)."""
        error_id = uuid.uuid4().hex[:12]
        status_code = exc.status_code

        # For server-side errors (5xx) raised via HTTPException, mask internal details
        if status_code >= 500:
            logger.error(
                "HTTPException 5xx [%s] status=%d on %s: %s",
                error_id,
                status_code,
                request.url.path,
                exc.detail,
            )
            # 501 Not Implemented: allow known safe public gating messages, else generic message
            if (
                status_code == status.HTTP_501_NOT_IMPLEMENTED
                and isinstance(exc.detail, str)
                and not any(
                    sensitive in exc.detail.lower()
                    for sensitive in ["token", "secret", "password", "key", "db://", "redis://", "postgres://"]
                )
            ):
                safe_detail = exc.detail
            else:
                safe_detail = "An internal server error occurred. Please contact the administrator."
        else:
            # For client-side errors (4xx), sanitize any accidental internal secrets or paths
            raw_detail = str(exc.detail) if exc.detail is not None else "Request failed."
            sensitive_indicators = ["secret", "password", "token", "api_key", "private_key", "db://", "mongodb://", "postgres://"]
            if any(indicator in raw_detail.lower() for indicator in sensitive_indicators):
                logger.warning(
                    "Sanitized sensitive detail in HTTPException [%s] status=%d on %s: %s",
                    error_id,
                    status_code,
                    request.url.path,
                    raw_detail,
                )
                safe_detail = "Invalid request or parameter."
            else:
                safe_detail = exc.detail

        resp_headers = getattr(exc, "headers", None)
        return JSONResponse(
            status_code=status_code,
            headers=resp_headers,
            content={
                "error": "HTTPException",
                "status_code": status_code,
                "detail": safe_detail,
                "error_id": error_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(request.url.path),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle client request validation errors with sanitized field details."""
        sanitized_errors = []
        for err in exc.errors():
            sanitized_errors.append(
                {
                    "loc": [str(loc_item) for loc_item in err.get("loc", [])],
                    "msg": err.get("msg", "Invalid input"),
                    "type": err.get("type", "value_error"),
                }
            )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={
                "error": "ValidationError",
                "status_code": status.HTTP_422_UNPROCESSABLE_CONTENT,
                "detail": sanitized_errors,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(request.url.path),
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catch-all unhandled exception handler ensuring no sensitive traceback or data leaks."""
        error_id = uuid.uuid4().hex[:12]
        # Log safe generic error message with exception type and correlation ID only.
        # Avoid logging str(exc), request bodies, query strings, or submitted content
        # which may contain user secrets, URLs with tokens, or PII.
        logger.error(
            "Unhandled server error [%s] of type %s on path %s",
            error_id,
            type(exc).__name__,
            request.url.path,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "InternalServerError",
                "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "detail": "An internal server error occurred. Please contact the administrator.",
                "error_id": error_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(request.url.path),
            },
        )

    # --------------------------------------------------------------------------
    # Root Health Check
    # --------------------------------------------------------------------------

    @app.get(
        "/health",
        response_model=HealthCheckResponse,
        status_code=status.HTTP_200_OK,
        summary="Root Liveness & Readiness Health Check",
        tags=["System"],
    )
    def root_health() -> HealthCheckResponse:
        """Lightweight root health endpoint.
        Returns 200 OK without external network or database dependencies.
        """
        return HealthCheckResponse()

    # --------------------------------------------------------------------------
    # API Routers
    # --------------------------------------------------------------------------
    app.include_router(api_v1_router, prefix=settings.api_v1_prefix)

    return app


app = create_application()
