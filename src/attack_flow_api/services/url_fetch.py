from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
from urllib.parse import urljoin, urlsplit

from attack_flow_api.services.url_safety import UrlSafetyError, validate_url_destination_safety


REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


class UrlFetchError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class UrlFetchResult:
    requested_url: str
    final_url: str
    status_code: int
    content_type: str | None
    size_bytes: int
    body: bytes


def fetch_url_bounded(
    raw_url: str,
    *,
    allowed_schemes: set[str],
    block_private_destinations: bool,
    connect_timeout_seconds: float,
    read_timeout_seconds: float,
    max_redirects: int,
    max_response_bytes: int,
    resolver=None,
) -> UrlFetchResult:
    current_url = raw_url

    for redirect_count in range(max_redirects + 1):
        try:
            validate_url_destination_safety(
                current_url,
                allowed_schemes=allowed_schemes,
                block_private_destinations=block_private_destinations,
                resolver=resolver,
            )
        except UrlSafetyError as exc:
            raise UrlFetchError(exc.code, exc.message) from exc

        response, resolved_url = _request_once(
            current_url,
            connect_timeout_seconds=connect_timeout_seconds,
            read_timeout_seconds=read_timeout_seconds,
        )
        status_code = response.status

        if status_code in REDIRECT_STATUS_CODES:
            if redirect_count >= max_redirects:
                raise UrlFetchError("redirect_limit_exceeded", "maximum redirect count exceeded")
            location = response.getheader("Location")
            if not location:
                raise UrlFetchError("invalid_redirect", "redirect response missing Location header")
            current_url = urljoin(resolved_url, location)
            response.close()
            continue

        body = _read_bounded_body(response, max_response_bytes=max_response_bytes)
        content_type = response.getheader("Content-Type")
        response.close()
        return UrlFetchResult(
            requested_url=raw_url,
            final_url=resolved_url,
            status_code=status_code,
            content_type=content_type,
            size_bytes=len(body),
            body=body,
        )

    raise UrlFetchError("redirect_limit_exceeded", "maximum redirect count exceeded")


def _request_once(
    url: str,
    *,
    connect_timeout_seconds: float,
    read_timeout_seconds: float,
) -> tuple[HTTPResponse, str]:
    parsed = urlsplit(url)
    host = parsed.hostname
    if host is None:
        raise UrlFetchError("invalid_url", "url must include a valid hostname")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    connection_cls = HTTPSConnection if parsed.scheme == "https" else HTTPConnection
    port = parsed.port
    connection = connection_cls(host=host, port=port, timeout=connect_timeout_seconds)

    try:
        connection.request("GET", path, headers={"User-Agent": "attack-flow-api/afa-21"})
        if connection.sock is not None:
            connection.sock.settimeout(read_timeout_seconds)
        response = connection.getresponse()
        return response, _rebuild_url(parsed)
    except TimeoutError as exc:
        connection.close()
        raise UrlFetchError("fetch_timeout", "url fetch timed out") from exc
    except OSError as exc:
        connection.close()
        raise UrlFetchError("fetch_failed", "url fetch failed") from exc


def _read_bounded_body(response: HTTPResponse, *, max_response_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(8192)
        if not chunk:
            break
        total += len(chunk)
        if total > max_response_bytes:
            raise UrlFetchError("response_too_large", "response exceeded maximum allowed size")
        chunks.append(chunk)
    return b"".join(chunks)


def _rebuild_url(parsed) -> str:
    netloc = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        return f"{parsed.scheme}://{netloc}{path}?{parsed.query}"
    return f"{parsed.scheme}://{netloc}{path}"
