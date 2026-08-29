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


def test_structured_targets_preserve_native_windows_paths():
    targets = parse_stdio_targets(
        r'{"windows":["C:\\Program Files\\Airlock\\server.exe","--root","C:\\Data"]}'
    )

    assert targets["windows"] == StdioTarget(
        name="windows",
        command=r"C:\Program Files\Airlock\server.exe",
        args=["--root", r"C:\Data"],
    )


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


def _service(tmp_path, config):
    from airlock.case_service import CaseService
    from airlock.store import JsonCaseStore

    return CaseService(
        JsonCaseStore(tmp_path),
        public_base_url="http://127.0.0.1:8000",
        stdio_targets=parse_stdio_targets(config),
    )


def _open(service):
    from airlock.models import (
        DeclaredScope,
        EvidenceMode,
        ObservationCapabilities,
    )

    return service.open_case(
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


def test_repointing_a_name_revokes_the_open_case(tmp_path):
    from airlock.target_policy import TargetValidationError

    service = _service(tmp_path, "memory=npx -y server-memory")
    case = _open(service)
    service.revalidate_target(case.case_id)

    # The operator points the same name at a different command.
    service.stdio_targets = parse_stdio_targets("memory=npx -y something-else")
    with pytest.raises(TargetValidationError, match="command changed"):
        service.revalidate_target(case.case_id)


def test_changing_arguments_under_the_same_name_revokes_the_case(tmp_path):
    from airlock.target_policy import TargetValidationError

    service = _service(tmp_path, "memory=npx -y server-memory")
    case = _open(service)

    service.stdio_targets = parse_stdio_targets(
        "memory=npx -y server-memory --allow-write /"
    )
    with pytest.raises(TargetValidationError, match="command changed"):
        service.revalidate_target(case.case_id)


def test_removing_the_target_revokes_the_case(tmp_path):
    service = _service(tmp_path, "memory=npx -y server-memory")
    case = _open(service)

    service.stdio_targets = {}
    with pytest.raises(StdioTargetError):
        service.revalidate_target(case.case_id)


def test_child_environment_is_ours_not_the_sdk_default():
    from airlock.audit import _STDIO_INHERITED_ENV_VARS, _stdio_child_environment

    environment = _stdio_child_environment("/tmp/workdir")
    # Every variable the SDK would otherwise inherit is named here, so the
    # child cannot pick up the operator's shell, user or home.
    for name in _STDIO_INHERITED_ENV_VARS:
        assert name in environment
    assert environment["HOME"] == "/tmp/workdir"
    assert environment["TMPDIR"] == "/tmp/workdir"
    assert environment["USERPROFILE"] == "/tmp/workdir"
    assert environment["LOGNAME"] == ""
    assert environment["SHELL"] == ""
    assert environment["USER"] == ""


def test_stderr_capture_is_bounded_and_keeps_the_tail():
    from airlock.audit import _STDIO_STDERR_CAPTURE_BYTES, _BoundedStderr

    errlog = _BoundedStderr()
    try:
        # Far more than the cap, so an unbounded implementation would keep it.
        for index in range(400):
            errlog.stream.write(f"line {index} " .encode() + b"x" * 512)
        errlog.stream.flush()
    finally:
        errlog.close()

    tail = errlog.tail()
    assert len(tail.encode()) <= _STDIO_STDERR_CAPTURE_BYTES
    # The end is what diagnoses a failure, so that is the part retained.
    assert "line 399" in tail
    assert "line 0 " not in tail


def test_stderr_tail_survives_a_server_that_says_nothing():
    from airlock.audit import _BoundedStderr

    errlog = _BoundedStderr()
    errlog.close()
    assert errlog.tail() == ""


def test_drain_stops_even_when_a_descendant_holds_stderr():
    """A grandchild inheriting stderr means the pipe never reaches EOF."""
    import os
    import subprocess
    import threading
    import time

    from airlock.audit import _BoundedStderr

    before = threading.active_count()
    errlog = _BoundedStderr()
    # A descendant that keeps the write end open well past our teardown.
    holder = subprocess.Popen(
        ["python3", "-c", "import time; time.sleep(30)"],
        stderr=errlog.stream,
    )
    try:
        errlog.stream.write(b"starting up\n")
        errlog.stream.flush()
        time.sleep(0.2)

        started = time.monotonic()
        errlog.close()
        elapsed = time.monotonic() - started

        # Waiting for EOF here would block until the descendant exited.
        assert elapsed < 2.0
        for _ in range(40):
            if threading.active_count() <= before:
                break
            time.sleep(0.05)
        assert threading.active_count() <= before
        assert "starting up" in errlog.tail()
    finally:
        holder.kill()
        holder.wait()


def test_non_polling_platform_does_not_start_a_blocking_stderr_drain():
    import threading

    from airlock.audit import _stderr_capture_for_platform

    before = threading.active_count()
    errlog = _stderr_capture_for_platform(can_poll_pipes=False)
    try:
        errlog.stream.write(b"discarded safely\n")
        errlog.stream.flush()
    finally:
        errlog.close()

    assert threading.active_count() == before
    assert errlog.tail() == ""


def test_stdio_startup_diagnostic_is_persisted_with_inventory_failure(tmp_path):
    from airlock.audit import AuditExecutor, StdioLaunchError

    service = _service(tmp_path, "memory=npx -y server-memory")
    case = _open(service)
    assert case.stdio_target is not None

    failed = AuditExecutor(service)._record_inventory_failure(
        case.case_id,
        error=StdioLaunchError(
            case.stdio_target,
            "launch failed: missing dependency",
        ),
    )

    event = failed.events[-1]
    assert event.details == {
        "checks": [],
        "failure_class": "stdio_transport_or_protocol",
        "stderr_tail": "launch failed: missing dependency",
    }


def test_stdio_failure_reads_the_tail_after_the_drain_closes(monkeypatch):
    import asyncio

    import airlock.audit as audit

    class DelayedTail:
        stream = object()

        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        def tail(self):
            return "complete final diagnostic" if self.closed else "partial"

    class FailingClient:
        async def __aenter__(self):
            raise RuntimeError("server startup failed")

        async def __aexit__(self, *args):
            return None

    capture = DelayedTail()
    monkeypatch.setattr(
        audit,
        "_stderr_capture_for_platform",
        lambda: capture,
    )
    monkeypatch.setattr(audit, "Client", lambda *args, **kwargs: FailingClient())

    async def exercise():
        target = StdioTarget(name="broken", command="missing", args=[])
        with pytest.raises(audit.StdioLaunchError, match="complete final diagnostic"):
            async with audit._open_stdio_client(target):
                pass

    asyncio.run(exercise())


def test_path_fallback_uses_the_platform_default(monkeypatch):
    import os

    from airlock.audit import _stdio_child_environment

    monkeypatch.delenv("PATH", raising=False)
    assert _stdio_child_environment("/tmp/workdir")["PATH"] == os.defpath
