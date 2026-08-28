import asyncio

import httpx2
import pytest

from airlock.bounded_transport import (
    AuditResponseLimitError,
    BoundedAuditTransport,
)


def test_bounded_transport_stops_chunked_response_before_materialization():
    class OversizedStream(httpx2.AsyncByteStream):
        async def __aiter__(self):
            yield b"12345678"
            yield b"9"

    async def exercise():
        delegate = httpx2.MockTransport(
            lambda request: httpx2.Response(200, stream=OversizedStream())
        )
        async with httpx2.AsyncClient(
            transport=BoundedAuditTransport(
                delegate,
                max_response_bytes=8,
            )
        ) as client:
            await client.get("https://fixture.example/mcp")

    with pytest.raises(AuditResponseLimitError, match="byte limit"):
        asyncio.run(exercise())


def test_bounded_transport_rejects_encoded_response_before_decompression():
    class EncodedStream(httpx2.AsyncByteStream):
        async def __aiter__(self):
            yield b"compressed"

    async def exercise():
        delegate = httpx2.MockTransport(
            lambda request: httpx2.Response(
                200,
                headers={"Content-Encoding": "gzip"},
                stream=EncodedStream(),
            )
        )
        async with httpx2.AsyncClient(
            transport=BoundedAuditTransport(
                delegate,
                max_response_bytes=1024,
            )
        ) as client:
            await client.get("https://fixture.example/mcp")

    with pytest.raises(AuditResponseLimitError, match="encoded"):
        asyncio.run(exercise())
