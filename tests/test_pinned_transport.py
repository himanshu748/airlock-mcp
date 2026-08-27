import asyncio

from airlock.models import TargetBinding
from airlock.pinned_transport import PinnedNetworkBackend, create_pinned_httpx_transport


def test_pinned_transport_connects_to_recorded_ip_without_resolving_hostname():
    async def exercise():
        class FakeBackend:
            def __init__(self):
                self.calls = []

            async def connect_tcp(self, host, port, **kwargs):
                self.calls.append((host, port, kwargs))
                return "stream"

        delegate = FakeBackend()
        binding = TargetBinding(
            scheme="http",
            hostname="does-not-resolve.invalid",
            port=8123,
            resolved_ips=["127.0.0.1"],
        )
        backend = PinnedNetworkBackend(binding, delegate)
        result = await backend.connect_tcp(
            "does-not-resolve.invalid",
            8123,
            timeout=5,
        )
        return result, delegate.calls

    result, calls = asyncio.run(exercise())

    assert result == "stream"
    assert calls == [
        (
            "127.0.0.1",
            8123,
            {"timeout": 5, "local_address": None, "socket_options": None},
        )
    ]


def test_pinned_transport_rejects_unexpected_origin_before_connecting():
    async def exercise():
        binding = TargetBinding(
            scheme="http",
            hostname="fixture.invalid",
            port=8080,
            resolved_ips=["127.0.0.1"],
        )
        transport = create_pinned_httpx_transport(binding)
        backend = transport._pool._network_backend
        return await backend.connect_tcp("different.invalid", 8080)

    try:
        asyncio.run(exercise())
    except Exception as exc:
        assert "outside the validated target binding" in str(exc)
    else:
        raise AssertionError("unexpected origin was not rejected")
