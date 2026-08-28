from __future__ import annotations

from typing import Any

import httpcore
import httpcore2
import httpx
import httpx2

from .models import TargetBinding


class PinnedTargetError(RuntimeError):
    pass


class PinnedNetworkBackend:
    def __init__(self, binding: TargetBinding, delegate: Any) -> None:
        if not binding.resolved_ips:
            raise ValueError("target binding must contain at least one IP address")
        self.binding = binding
        self.delegate = delegate

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()
        if (
            normalized_host != self.binding.hostname
            or port != self.binding.port
        ):
            raise PinnedTargetError(
                "connection origin is outside the validated target binding"
            )
        last_error: Exception | None = None
        for address in self.binding.resolved_ips:
            try:
                return await self.delegate.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options=None,
    ):
        del path, timeout, socket_options
        raise PinnedTargetError("Unix sockets are outside the validated target binding")

    async def sleep(self, seconds: float) -> None:
        await self.delegate.sleep(seconds)


def create_pinned_httpx_transport(
    binding: TargetBinding,
) -> httpx.AsyncHTTPTransport:
    transport = httpx.AsyncHTTPTransport(trust_env=False, retries=0)
    ssl_context = transport._pool._ssl_context
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl_context,
        max_connections=100,
        max_keepalive_connections=20,
        keepalive_expiry=5.0,
        retries=0,
        network_backend=PinnedNetworkBackend(
            binding,
            httpcore.AnyIOBackend(),
        ),
    )
    return transport


def create_pinned_httpx2_transport(
    binding: TargetBinding,
) -> httpx2.AsyncHTTPTransport:
    transport = httpx2.AsyncHTTPTransport(trust_env=False, retries=0)
    ssl_context = transport._pool._ssl_context
    transport._pool = httpcore2.AsyncConnectionPool(
        ssl_context=ssl_context,
        max_connections=100,
        max_keepalive_connections=20,
        keepalive_expiry=5.0,
        retries=0,
        network_backend=PinnedNetworkBackend(
            binding,
            httpcore2.AnyIOBackend(),
        ),
    )
    return transport


__all__ = [
    "PinnedTargetError",
    "PinnedNetworkBackend",
    "create_pinned_httpx2_transport",
    "create_pinned_httpx_transport",
]
