"""Run one full Airlock audit against a bundled fixture and print the result.

This is the demo path: it opens a case, inventories the declared tools, probes
each one, reads the aggregate evidence and prints what diverged. It stops
before seal_case, because sealing is a human decision.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from contextlib import AsyncExitStack

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

CONTROL_URL = os.environ.get(
    "AIRLOCK_CONTROL_URL", "http://127.0.0.1:8000/airlock-control/mcp"
)
TARGET_URL = os.environ.get(
    "AIRLOCK_DEMO_TARGET", "http://127.0.0.1:8000/fixtures/dishonest/mcp"
)


def payload(result: object) -> dict:
    content = getattr(result, "structuredContent", None)
    if content:
        return content
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    raise RuntimeError("tool returned no readable payload")


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=TARGET_URL)
    parser.add_argument("--evidence-mode", default="controlled_fixture")
    parser.add_argument("--declared-egress", action="append", default=[])
    parser.add_argument("--declared-root", action="append", default=[])
    args = parser.parse_args()

    token = os.environ.get("AIRLOCK_CONTROL_BEARER_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    async with AsyncExitStack() as stack:
        http_client = await stack.enter_async_context(
            httpx2.AsyncClient(headers=headers, timeout=120.0)
        )
        read_stream, write_stream = await stack.enter_async_context(
            streamable_http_client(CONTROL_URL, http_client=http_client)
        )
        session = await stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await session.initialize()

        case = payload(
            await session.call_tool(
                "open_case",
                {
                    "target_url": args.target,
                    "evidence_mode": args.evidence_mode,
                    "declared_egress_hosts": args.declared_egress,
                    "declared_filesystem_roots": args.declared_root,
                },
            )
        )
        case_id = case["case_id"]
        print(f"case {case_id}")
        print(f"target {args.target}")
        print(f"evidence mode {args.evidence_mode}")

        inventory = payload(
            await session.call_tool("list_declared_tools", {"case_id": case_id})
        )
        tools = inventory["declared_tools"]
        print(f"declared tools: {len(tools)}")

        for tool in tools:
            probed = payload(
                await session.call_tool(
                    "probe_tool",
                    {"case_id": case_id, "tool_id": tool["tool_id"]},
                )
            )
            print(
                f"  probed {tool['tool_id']} "
                f"observations={probed['observation_count']}"
            )

        evidence = payload(
            await session.call_tool("read_evidence", {"case_id": case_id})
        )

    checks = evidence["checks"]
    findings = [check for check in checks if check["status"] == "finding"]
    print()
    print(f"status: {evidence['status']}")
    print(f"findings: {len(findings)} of {len(checks)} checks")
    for finding in findings:
        print(
            f"  [{finding['verdict']}] {finding['check']} "
            f"tool={finding['tool_id']} "
            f"evidence={finding['evidence_strength']} "
            f"sensor={finding['sensor']}"
        )
    untested = [check for check in checks if check["status"] == "not_tested"]
    if untested:
        print(f"not tested: {len(untested)} checks")
    print()
    print("Airlock reports what it observed. Absence of a finding is not proof")
    print("of safety. Read the record at http://127.0.0.1:8000/ui/record/")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
