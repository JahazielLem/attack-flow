import logging

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from attack_flow_api.middleware import REQUEST_ID_HEADER, RequestContextMiddleware


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)

    @app.get("/request-id")
    def request_id(request: Request):
        return {"request_id": request.state.request_id}

    @app.get("/boom")
    def boom():
        raise RuntimeError("boom")

    return app


def test_request_context_middleware_generates_request_id():
    with TestClient(_build_app()) as client:
        response = client.get("/request-id")

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER]
    assert response.json()["request_id"] == response.headers[REQUEST_ID_HEADER]


def test_request_context_middleware_preserves_incoming_request_id():
    with TestClient(_build_app()) as client:
        response = client.get("/request-id", headers={REQUEST_ID_HEADER: "req-fixed-1"})

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER] == "req-fixed-1"
    assert response.json()["request_id"] == "req-fixed-1"


def test_request_context_middleware_logs_500_for_unhandled_exceptions(caplog):
    caplog.set_level(logging.INFO, logger="attack_flow_api.request")

    with TestClient(_build_app(), raise_server_exceptions=False) as client:
        response = client.get("/boom", headers={REQUEST_ID_HEADER: "req-boom-1"})

    assert response.status_code == 500
    assert any(
        record.name == "attack_flow_api.request"
        and record.message == "request completed"
        and getattr(record, "request_id", None) == "req-boom-1"
        and getattr(record, "status_code", None) == 500
        for record in caplog.records
    )
