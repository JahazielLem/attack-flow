import logging
from dataclasses import dataclass, field
from typing import Protocol

from fastapi import Request
from fastapi.responses import JSONResponse

from attack_flow_api.middleware import REQUEST_ID_HEADER


@dataclass(slots=True)
class BadRequestError(Exception):
    code: str
    message: str
    details: list[dict[str, object]] = field(default_factory=list)


@dataclass(slots=True)
class NotFoundError(Exception):
    code: str
    message: str
    details: list[dict[str, object]] = field(default_factory=list)


@dataclass(slots=True)
class ConflictError(Exception):
    code: str
    message: str
    details: list[dict[str, object]] = field(default_factory=list)


@dataclass(slots=True)
class PayloadTooLargeError(Exception):
    code: str
    message: str
    details: list[dict[str, object]] = field(default_factory=list)


async def bad_request_exception_handler(request: Request, exc: BadRequestError) -> JSONResponse:
    return _structured_error_response(request, 400, exc)


async def not_found_exception_handler(request: Request, exc: NotFoundError) -> JSONResponse:
    return _structured_error_response(request, 404, exc)


async def conflict_exception_handler(request: Request, exc: ConflictError) -> JSONResponse:
    return _structured_error_response(request, 409, exc)


async def payload_too_large_exception_handler(request: Request, exc: PayloadTooLargeError) -> JSONResponse:
    return _structured_error_response(request, 413, exc)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "")
    logging.getLogger("attack_flow_api.error").exception(
        "unhandled exception",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "route": request.url.path,
            "status_code": 500,
            "duration_ms": None,
        },
    )

    response = JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_server_error",
                "message": "An unexpected error occurred",
                "details": [],
            },
            "request_id": request_id,
        },
    )

    if request_id:
        response.headers[REQUEST_ID_HEADER] = request_id
    return response


class _StructuredError(Protocol):
    code: str
    message: str
    details: list[dict[str, object]]


def _structured_error_response(
    request: Request, status_code: int, exc: _StructuredError
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "")
    response = JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            },
            "request_id": request_id,
        },
    )
    if request_id:
        response.headers[REQUEST_ID_HEADER] = request_id
    return response
