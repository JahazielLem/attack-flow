import socket

import pytest

from attack_flow_api.services.url_safety import UrlSafetyError, validate_url_destination_safety


def _resolver_for(*ips: str):
    def _resolve(_hostname, _port, family=0, type=0, proto=0, flags=0):
        _ = (family, type, proto, flags)
        records = []
        for ip in ips:
            if ":" in ip:
                records.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 0, 0, 0)))
            else:
                records.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)))
        return records

    return _resolve


def test_validate_url_destination_safety_accepts_http_and_https():
    result = validate_url_destination_safety(
        " https://example.com/report ",
        resolver=_resolver_for("93.184.216.34"),
    )
    assert result.normalized_url == "https://example.com/report"
    assert result.hostname == "example.com"
    assert result.resolved_ips == ("93.184.216.34",)


def test_validate_url_destination_safety_rejects_unsupported_scheme():
    with pytest.raises(UrlSafetyError) as exc:
        validate_url_destination_safety("ftp://example.com", resolver=_resolver_for("93.184.216.34"))
    assert exc.value.code == "invalid_url_scheme"


def test_validate_url_destination_safety_rejects_malformed_url():
    with pytest.raises(UrlSafetyError) as exc:
        validate_url_destination_safety("https:///missing-host", resolver=_resolver_for("93.184.216.34"))
    assert exc.value.code == "invalid_url"


def test_validate_url_destination_safety_rejects_user_info():
    with pytest.raises(UrlSafetyError) as exc:
        validate_url_destination_safety(
            "https://user:pass@example.com/path",
            resolver=_resolver_for("93.184.216.34"),
        )
    assert exc.value.code == "invalid_url"


@pytest.mark.parametrize(
    "blocked_ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.10.20",
        "224.0.0.1",
        "0.0.0.0",
        "240.0.0.1",
        "::1",
        "fe80::1",
        "ff02::1",
    ],
)
def test_validate_url_destination_safety_blocks_disallowed_ranges(blocked_ip: str):
    with pytest.raises(UrlSafetyError) as exc:
        validate_url_destination_safety(
            "https://example.com/path",
            resolver=_resolver_for(blocked_ip),
        )
    assert exc.value.code == "unsafe_destination"


@pytest.mark.parametrize("metadata_ip", ["169.254.169.254", "100.100.100.200"])
def test_validate_url_destination_safety_blocks_common_metadata_ips(metadata_ip: str):
    with pytest.raises(UrlSafetyError) as exc:
        validate_url_destination_safety(
            "https://metadata.example/internal",
            resolver=_resolver_for(metadata_ip),
        )
    assert exc.value.code == "unsafe_destination"


def test_validate_url_destination_safety_can_disable_private_blocking():
    result = validate_url_destination_safety(
        "http://internal.example",
        block_private_destinations=False,
        resolver=_resolver_for("10.10.10.10"),
    )
    assert result.resolved_ips == ("10.10.10.10",)


def test_validate_url_destination_safety_reports_dns_failure():
    def _failing(*_args, **_kwargs):
        raise OSError("dns failed")

    with pytest.raises(UrlSafetyError) as exc:
        validate_url_destination_safety("https://example.com", resolver=_failing)
    assert exc.value.code == "dns_resolution_failed"
