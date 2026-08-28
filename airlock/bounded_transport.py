from __future__ import annotations

from types import TracebackType

import httpx2


class AuditResponseLimitError(httpx2.StreamError):
    pass


class _BoundedResponseStream(httpx2.AsyncByteStream):
    def __init__(self, stream: httpx2.AsyncByteStream, *, limit: int) -> None:
        self.stream = stream
        self.limit = limit

    async def __aiter__(self):
        observed = 0
        async for chunk in self.stream:
            observed += len(chunk)
            if observed > self.limit:
                await self.stream.aclose()
                raise AuditResponseLimitError(
                    "audit response exceeded the configured byte limit"
                )
            yield chunk

    async def aclose(self) -> None:
        await self.stream.aclose()


class BoundedAuditTransport(httpx2.AsyncBaseTransport):
    def __init__(
        self,
        delegate: httpx2.AsyncBaseTransport,
        *,
        max_response_bytes: int,
    ) -> None:
        if type(max_response_bytes) is not int or max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be a positive integer")
        self.delegate = delegate
        self.max_response_bytes = max_response_bytes

    async def __aenter__(self) -> "BoundedAuditTransport":
        await self.delegate.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        await self.delegate.__aexit__(exc_type, exc_value, traceback)

    async def handle_async_request(
        self,
        request: httpx2.Request,
    ) -> httpx2.Response:
        response = await self.delegate.handle_async_request(request)
        content_encoding = response.headers.get("content-encoding", "identity")
        if content_encoding.lower().strip() not in {"", "identity"}:
            await response.stream.aclose()
            raise AuditResponseLimitError(
                "encoded audit responses are outside the bounded transport profile"
            )
        content_lengths = response.headers.get_list("content-length")
        if len(content_lengths) > 1:
            await response.stream.aclose()
            raise AuditResponseLimitError(
                "audit response contains ambiguous content length"
            )
        if content_lengths:
            try:
                content_length = int(content_lengths[0])
            except ValueError as exc:
                await response.stream.aclose()
                raise AuditResponseLimitError(
                    "audit response contains an invalid content length"
                ) from exc
            if content_length < 0 or content_length > self.max_response_bytes:
                await response.stream.aclose()
                raise AuditResponseLimitError(
                    "audit response exceeded the configured byte limit"
                )
        if not isinstance(response.stream, httpx2.AsyncByteStream):
            await response.aclose()
            raise AuditResponseLimitError(
                "audit response did not expose an asynchronous byte stream"
            )
        response.stream = _BoundedResponseStream(
            response.stream,
            limit=self.max_response_bytes,
        )
        return response

    async def aclose(self) -> None:
        await self.delegate.aclose()


__all__ = ["AuditResponseLimitError", "BoundedAuditTransport"]
