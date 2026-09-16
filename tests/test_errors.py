import asyncio
import json

from starlette.requests import Request

from attack_flow_api.errors import (
    BadRequestError,
    NotFoundError,
    PayloadTooLargeError,
    bad_request_exception_handler,
    not_found_exception_handler,
    payload_too_large_exception_handler,
)
from attack_flow_api.middleware import REQUEST_ID_HEADER


def _make_request(request_id: str) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [],
            "query_string": b"",
        },
        receive,
    )
    request.state.request_id = request_id
    return request


def test_bad_request_exception_handler_returns_structured_response():
    response = asyncio.run(
        bad_request_exception_handler(
            _make_request("req-400"),
            BadRequestError(code="bad_input", message="bad input", details=[{"field": "x"}]),
        )
    )

    payload = json.loads(response.body)
    assert response.status_code == 400
    assert payload == {
        "error": {"code": "bad_input", "message": "bad input", "details": [{"field": "x"}]},
        "request_id": "req-400",
    }
    assert response.headers[REQUEST_ID_HEADER] == "req-400"


def test_not_found_exception_handler_returns_structured_response():
    response = asyncio.run(
        not_found_exception_handler(
            _make_request("req-404"),
            NotFoundError(code="missing", message="not found", details=[]),
        )
    )

    payload = json.loads(response.body)
    assert response.status_code == 404
    assert payload == {
        "error": {"code": "missing", "message": "not found", "details": []},
        "request_id": "req-404",
    }
    assert response.headers[REQUEST_ID_HEADER] == "req-404"


def test_payload_too_large_exception_handler_returns_structured_response():
    response = asyncio.run(
        payload_too_large_exception_handler(
            _make_request("req-413"),
            PayloadTooLargeError(code="too_large", message="too large", details=[]),
        )
    )

    payload = json.loads(response.body)
    assert response.status_code == 413
    assert payload == {
        "error": {"code": "too_large", "message": "too large", "details": []},
        "request_id": "req-413",
    }
    assert response.headers[REQUEST_ID_HEADER] == "req-413"
