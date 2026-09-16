from dataclasses import dataclass
from ipaddress import ip_address
from socket import AF_INET, AF_INET6, getaddrinfo
from collections.abc import Callable
from urllib.parse import urlsplit


ALLOWED_URL_SCHEMES = {"http", "https"}

METADATA_SERVICE_IPS = {
    "169.254.169.254",  # AWS/Azure/GCP IMDS
    "100.100.100.200",  # Alibaba Cloud metadata
}


@dataclass(frozen=True, slots=True)
class UrlValidationResult:
    original_url: str
    normalized_url: str
    hostname: str
    resolved_ips: tuple[str, ...]


class UrlSafetyError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_url_destination_safety(
    raw_url: str,
    *,
    allowed_schemes: set[str] | None = None,
    block_private_destinations: bool = True,
    resolver: Callable | None = None,
) -> UrlValidationResult:
    normalized_url = raw_url.strip()
    if not normalized_url:
        raise UrlSafetyError("invalid_url", "url must be a non-empty string")

    parsed = urlsplit(normalized_url)
    schemes = allowed_schemes or ALLOWED_URL_SCHEMES
    if parsed.scheme.lower() not in schemes:
        raise UrlSafetyError("invalid_url_scheme", "url scheme must be http or https")
    if parsed.username is not None or parsed.password is not None:
        raise UrlSafetyError("invalid_url", "url must not include user info")
    if not parsed.hostname:
        raise UrlSafetyError("invalid_url", "url must include a valid hostname")

    hostname = parsed.hostname
    resolved_ips = _resolve_hostname_ips(hostname, resolver=resolver)
    if not resolved_ips:
        raise UrlSafetyError("dns_resolution_failed", "unable to resolve hostname")

    if block_private_destinations:
        for candidate in resolved_ips:
            _assert_ip_is_allowed(candidate)

    return UrlValidationResult(
        original_url=raw_url,
        normalized_url=normalized_url,
        hostname=hostname,
        resolved_ips=tuple(sorted(set(resolved_ips))),
    )


def _resolve_hostname_ips(hostname: str, *, resolver: Callable | None = None) -> list[str]:
    resolve = resolver or getaddrinfo
    try:
        records = resolve(hostname, None, family=0, type=0, proto=0, flags=0)
    except OSError as exc:
        raise UrlSafetyError("dns_resolution_failed", "unable to resolve hostname") from exc

    ips: list[str] = []
    for family, _socktype, _proto, _canonname, sockaddr in records:
        if family not in (AF_INET, AF_INET6):
            continue
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        if ip_str:
            ips.append(ip_str)
    return ips


def _assert_ip_is_allowed(ip_str: str) -> None:
    try:
        candidate = ip_address(ip_str)
    except ValueError as exc:
        raise UrlSafetyError("dns_resolution_failed", "resolver returned invalid IP address") from exc

    if ip_str in METADATA_SERVICE_IPS:
        raise UrlSafetyError("unsafe_destination", "destination resolves to a blocked metadata endpoint")
    if candidate.is_loopback:
        raise UrlSafetyError("unsafe_destination", "destination resolves to loopback address")
    if candidate.is_private:
        raise UrlSafetyError("unsafe_destination", "destination resolves to private address")
    if candidate.is_link_local:
        raise UrlSafetyError("unsafe_destination", "destination resolves to link-local address")
    if candidate.is_multicast:
        raise UrlSafetyError("unsafe_destination", "destination resolves to multicast address")
    if candidate.is_unspecified:
        raise UrlSafetyError("unsafe_destination", "destination resolves to unspecified address")
    if candidate.is_reserved:
        raise UrlSafetyError("unsafe_destination", "destination resolves to reserved address")
