import pytest

from airlock.models import StdioTarget
from airlock.stdio_targets import (
    StdioTargetError,
    is_stdio_target,
    parse_stdio_targets,
    resolve_stdio_target,
    stdio_target_name,
)


def test_parses_named_commands_without_a_shell():
    targets = parse_stdio_targets(
        "memory=npx -y @modelcontextprotocol/server-memory;git=uvx mcp-server-git"
    )
    assert targets["memory"] == StdioTarget(
        name="memory",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-memory"],
    )
    assert targets["git"].command == "uvx"


def test_unconfigured_target_is_refused():
    with pytest.raises(StdioTargetError):
        resolve_stdio_target("stdio:absent", parse_stdio_targets("memory=npx x"))


def test_case_cannot_smuggle_a_command_through_the_target_name():
    configured = parse_stdio_targets("memory=npx -y server-memory")
    for hostile in (
        "stdio:memory; rm -rf /",
        "stdio:../../bin/sh",
        "stdio:memory && curl evil.example",
        "stdio:$(whoami)",
        "stdio:memory|sh",
    ):
        with pytest.raises(StdioTargetError):
            resolve_stdio_target(hostile, configured)


def test_empty_and_malformed_configuration_is_rejected():
    assert parse_stdio_targets(None) == {}
    assert parse_stdio_targets("") == {}
    with pytest.raises(StdioTargetError):
        parse_stdio_targets("no-equals-sign")
    with pytest.raises(StdioTargetError):
        parse_stdio_targets("empty=")
    with pytest.raises(StdioTargetError):
        parse_stdio_targets("a=x;a=y")


def test_target_name_profile_is_bounded():
    assert stdio_target_name("stdio:server-memory.v2") == "server-memory.v2"
    with pytest.raises(StdioTargetError):
        stdio_target_name("stdio:" + "a" * 65)
    with pytest.raises(StdioTargetError):
        stdio_target_name("stdio:")
    with pytest.raises(StdioTargetError):
        stdio_target_name("https://example.test/mcp")


def test_scheme_detection():
    assert is_stdio_target("stdio:memory")
    assert not is_stdio_target("https://example.test/mcp")


def test_stdio_case_is_audit_only_and_emits_no_policy(tmp_path):
    from airlock.case_service import CaseService
    from airlock.models import (
        DeclaredScope,
        EvidenceMode,
        ObservationCapabilities,
    )
    from airlock.policy import PolicyInvariantError, compile_policy
    from airlock.store import JsonCaseStore

    store = JsonCaseStore(tmp_path)
    service = CaseService(
        store,
        public_base_url="http://127.0.0.1:8000",
        stdio_targets=parse_stdio_targets("memory=npx -y server-memory"),
    )
    case = service.open_case(
        target_url="stdio:memory",
        declared_scope=DeclaredScope(),
        evidence_mode=EvidenceMode.TRANSCRIPT_ONLY,
        capabilities=ObservationCapabilities(
            mcp_traffic=True,
            tool_results=True,
            server_egress=False,
            server_filesystem=False,
        ),
    )

    assert case.stdio_target is not None
    assert case.stdio_target.command == "npx"
    # No DNS answer exists to pin, and no proxy can front a launched process.
    assert case.target_binding is None
    assert case.proxy_url is None

    with pytest.raises(PolicyInvariantError, match="audit-only"):
        compile_policy(case, connector_name="memory")
