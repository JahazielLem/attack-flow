import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


REQUEST_ID_HEADER = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
        request.state.request_id = request_id

        start_time = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            self._log_request(request, 500, duration_ms)
            raise

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        response.headers[REQUEST_ID_HEADER] = request_id
        self._log_request(request, response.status_code, duration_ms)
        return response

    def _log_request(self, request: Request, status_code: int, duration_ms: float) -> None:
        logger = logging.getLogger("attack_flow_api.request")
        logger.info(
            "request completed",
            extra={
                "request_id": request.state.request_id,
                "method": request.method,
                "path": request.url.path,
                "route": request.url.path,
                "status_code": status_code,
                "duration_ms": duration_ms,
            },
        )
