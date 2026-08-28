"""Validation policy for MCP target URLs."""

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Callable, Iterable, Optional, Tuple
from urllib.parse import urlsplit


class TargetValidationError(ValueError):
    """Raised when an MCP target does not satisfy the connection policy."""


@dataclass(frozen=True)
class ValidatedTarget:
    """A target URL bound to the addresses checked by this policy."""

    url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: Tuple[str, ...]


def _normalize_hostname(hostname: str) -> str:
    candidate = hostname[:-1] if hostname.endswith(".") else hostname
    if not candidate:
        raise TargetValidationError("target URL must contain a hostname")
    if "%" in candidate:
        raise TargetValidationError("target URL contains an ambiguous hostname")
    try:
        return candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetValidationError("target URL contains an invalid hostname") from exc


def validate_target_url(
    url: str,
    *,
    resolver: Callable[[str], Iterable[str]],
    allow_local: bool = False,
    allowed_hostnames: Optional[Iterable[str]] = None,
) -> ValidatedTarget:
    """Validate a target and retain the exact addresses that were approved.

    Callers must connect to the retained addresses and disable redirects, or
    validate every redirect target with this function before following it.
    """
    if not isinstance(url, str):
        raise TargetValidationError("target URL must be a string")
    if any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in url
    ):
        raise TargetValidationError("target URL must not contain raw whitespace")
    if "\\" in url:
        raise TargetValidationError("target URL must not contain backslashes")
    try:
        parsed = urlsplit(url)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise TargetValidationError("target URL is malformed") from exc
    scheme = parsed.scheme.lower()
    if scheme != "https" and not (allow_local and scheme == "http"):
        raise TargetValidationError("remote targets must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("target URLs must not contain credentials")
    if "#" in url:
        raise TargetValidationError("target URLs must not contain fragments")
    hostname = _normalize_hostname(parsed.hostname or "")
    if allowed_hostnames is not None:
        allowlist_values = (
            (allowed_hostnames,)
            if isinstance(allowed_hostnames, str)
            else allowed_hostnames
        )
        normalized_allowlist = {
            _normalize_hostname(allowed_hostname)
            for allowed_hostname in allowlist_values
        }
        if hostname not in normalized_allowlist:
            raise TargetValidationError("target hostname is not allowlisted")
    try:
        explicit_port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("target URL contains an invalid port") from exc
    if explicit_port == 0:
        raise TargetValidationError("target URL contains an invalid port")
    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    try:
        resolved = tuple(resolver(hostname))
    except OSError as exc:
        # NXDOMAIN and transient resolver failures arrive as socket.gaierror.
        raise TargetValidationError(
            "target hostname could not be resolved"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise TargetValidationError("resolver returned an invalid result") from exc
    try:
        addresses = tuple(ip_address(value) for value in resolved)
    except (TypeError, ValueError) as exc:
        raise TargetValidationError("resolver returned an invalid IP address") from exc
    if not addresses:
        raise TargetValidationError("target hostname did not resolve to any addresses")
    local_fixture = allow_local and all(address.is_loopback for address in addresses)
    if scheme == "http" and not local_fixture:
        raise TargetValidationError("HTTP targets must resolve only to loopback addresses")
    for address in addresses:
        if not local_fixture and any(
            (
                address.is_loopback,
                address.is_private,
                address.is_link_local,
                address.is_multicast,
                address.is_reserved,
                address.is_unspecified,
                not address.is_global,
                getattr(address, "is_site_local", False),
            )
        ):
            raise TargetValidationError(
                f"target resolved to a prohibited address: {address}"
            )
    resolved_ips = tuple(str(address) for address in addresses)
    return ValidatedTarget(
        url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_ips=resolved_ips,
    )
