import socket
from dataclasses import FrozenInstanceError

import pytest

from airlock.target_policy import TargetValidationError, validate_target_url


def test_public_https_target_captures_the_validated_dns_resolution():
    def resolve_example(hostname):
        assert hostname == "api.example.com"
        return ["93.184.216.34"]

    target = validate_target_url(
        "https://api.example.com:8443/mcp?transport=sse",
        resolver=resolve_example,
    )

    assert target.url == "https://api.example.com:8443/mcp?transport=sse"
    assert target.scheme == "https"
    assert target.hostname == "api.example.com"
    assert target.port == 8443
    assert target.resolved_ips == ("93.184.216.34",)


def test_validated_target_is_frozen():
    target = validate_target_url(
        "https://api.example.com/mcp",
        resolver=lambda hostname: ["93.184.216.34"],
    )

    with pytest.raises(FrozenInstanceError):
        target.hostname = "attacker.example"


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/mcp",
        "ftp://api.example.com/mcp",
        "file:///etc/passwd",
        "https://alice:secret@api.example.com/mcp",
        "https://api.example.com/mcp#tools",
        "https://api.example.com/mcp#",
    ],
)
def test_remote_mode_rejects_urls_that_are_not_credential_free_https(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url, resolver=lambda hostname: ["93.184.216.34"])


@pytest.mark.parametrize(
    "unsafe_ip",
    [
        "127.0.0.1",
        "::1",
        "10.0.0.1",
        "fd00::1",
        "169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "ff02::1",
        "240.0.0.1",
        "0.0.0.0",
        "::",
        "100.64.0.1",
        "fec0::1",
    ],
)
def test_remote_mode_rejects_any_non_public_resolved_address(unsafe_ip):
    with pytest.raises(TargetValidationError):
        validate_target_url(
            "https://api.example.com/mcp",
            resolver=lambda hostname: ["93.184.216.34", unsafe_ip],
        )


def test_target_must_resolve_to_at_least_one_address():
    with pytest.raises(TargetValidationError):
        validate_target_url(
            "https://api.example.com/mcp",
            resolver=lambda hostname: [],
        )


def test_controlled_fixture_mode_allows_http_when_every_address_is_loopback():
    target = validate_target_url(
        "http://localhost:8000/mcp",
        resolver=lambda hostname: ["127.0.0.1", "::1"],
        allow_local=True,
    )

    assert target.scheme == "http"
    assert target.hostname == "localhost"
    assert target.port == 8000
    assert target.resolved_ips == ("127.0.0.1", "::1")


@pytest.mark.parametrize(
    "resolved_ips",
    [
        ["93.184.216.34"],
        ["10.0.0.8"],
        ["127.0.0.1", "93.184.216.34"],
    ],
)
def test_allow_local_does_not_permit_http_to_non_loopback_addresses(resolved_ips):
    with pytest.raises(TargetValidationError):
        validate_target_url(
            "http://fixture.example:8000/mcp",
            resolver=lambda hostname: resolved_ips,
            allow_local=True,
        )


def test_controlled_http_fixture_uses_the_http_default_port():
    target = validate_target_url(
        "http://localhost/mcp",
        resolver=lambda hostname: ["127.0.0.1"],
        allow_local=True,
    )

    assert target.port == 80


def test_hostname_allowlist_uses_lowercase_idna_normalization():
    def resolve_idna_hostname(hostname):
        assert hostname == "xn--bcher-kva.example"
        return ["93.184.216.34"]

    target = validate_target_url(
        "https://B\u00dcCHER.Example/mcp",
        resolver=resolve_idna_hostname,
        allowed_hostnames={"XN--BCHER-KVA.EXAMPLE"},
    )

    assert target.hostname == "xn--bcher-kva.example"


def test_hostname_allowlist_does_not_match_subdomains():
    with pytest.raises(TargetValidationError):
        validate_target_url(
            "https://sub.api.example.com/mcp",
            resolver=lambda hostname: ["93.184.216.34"],
            allowed_hostnames={"api.example.com"},
        )


def test_single_string_hostname_allowlist_is_treated_as_one_exact_hostname():
    target = validate_target_url(
        "https://API.EXAMPLE.COM/mcp",
        resolver=lambda hostname: ["93.184.216.34"],
        allowed_hostnames="api.example.com",
    )

    assert target.hostname == "api.example.com"


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com:70000/mcp",
        "https://api.example.com:not-a-port/mcp",
        "https://[2001:db8::1/mcp",
    ],
)
def test_malformed_url_is_rejected_with_a_policy_error(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url, resolver=lambda hostname: ["93.184.216.34"])


def test_zero_is_not_a_valid_target_port():
    with pytest.raises(TargetValidationError):
        validate_target_url(
            "https://api.example.com:0/mcp",
            resolver=lambda hostname: ["93.184.216.34"],
        )


def test_non_ip_resolver_output_is_rejected_with_a_policy_error():
    with pytest.raises(TargetValidationError):
        validate_target_url(
            "https://api.example.com/mcp",
            resolver=lambda hostname: ["not-an-ip-address"],
        )


@pytest.mark.parametrize(
    "url",
    [
        " https://api.example.com/mcp",
        "https://api.example.com\r\n/mcp",
        "https://api.example.com/path with spaces",
    ],
)
def test_url_with_raw_whitespace_is_rejected(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url, resolver=lambda hostname: ["93.184.216.34"])


def test_url_with_a_raw_control_character_is_rejected():
    with pytest.raises(TargetValidationError):
        validate_target_url(
            "https://api.example.com/mcp\x00ignored",
            resolver=lambda hostname: ["93.184.216.34"],
        )


def test_url_with_a_backslash_is_rejected_to_avoid_parser_ambiguity():
    with pytest.raises(TargetValidationError):
        validate_target_url(
            "https://api.example.com\\attacker.example/mcp",
            resolver=lambda hostname: ["93.184.216.34"],
        )


def test_percent_encoded_hostname_is_rejected_to_avoid_parser_ambiguity():
    with pytest.raises(TargetValidationError):
        validate_target_url(
            "https://%65xample.com/mcp",
            resolver=lambda hostname: ["93.184.216.34"],
        )


def test_resolver_lookup_failure_becomes_a_target_validation_error():
    def failing_resolver(hostname):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    with pytest.raises(TargetValidationError, match="could not be resolved"):
        validate_target_url(
            "https://missing.example/mcp",
            resolver=failing_resolver,
        )


def test_transient_resolver_oserror_becomes_a_target_validation_error():
    def failing_resolver(hostname):
        raise OSError("temporary resolver failure")

    with pytest.raises(TargetValidationError, match="could not be resolved"):
        validate_target_url(
            "https://fixture.example/mcp",
            resolver=failing_resolver,
        )


def test_resolver_returning_a_non_iterable_becomes_a_target_validation_error():
    with pytest.raises(TargetValidationError, match="invalid result"):
        validate_target_url("https://x.example/mcp", resolver=lambda hostname: None)


def test_resolver_raising_type_or_value_error_stays_normalized():
    def raises_type_error(hostname):
        raise TypeError("bad resolver")

    def raises_value_error(hostname):
        raise ValueError("bad resolver")

    for resolver in (raises_type_error, raises_value_error):
        with pytest.raises(TargetValidationError, match="invalid result"):
            validate_target_url("https://x.example/mcp", resolver=resolver)
