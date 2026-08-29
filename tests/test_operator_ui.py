"""The operator interface renders text from an unaudited MCP server.

These guard the properties that make that survivable, across both the built
export the backend actually serves and the frontend source it is built from.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "airlock" / "ui"
FRONTEND = ROOT / "frontend"

DISCLAIMER = (
    "Airlock reports what it observed. Absence of a finding is not proof "
    "of safety."
)


def _source_files() -> list[Path]:
    return [
        path
        for directory in ("app", "components", "lib")
        for path in (FRONTEND / directory).rglob("*.ts*")
    ]


def test_the_built_export_ships_both_pages():
    assert (UI / "index.html").is_file()
    assert (UI / "record" / "index.html").is_file()
    assert (UI / "_next").is_dir()


def _code_without_comments(source: str) -> str:
    kept: list[str] = []
    in_block = False
    for line in source.splitlines():
        stripped = line.strip()
        if in_block:
            if "*/" in stripped:
                in_block = False
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped:
                in_block = True
            continue
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        kept.append(line)
    return "\n".join(kept)


def test_the_frontend_never_injects_markup():
    for path in _source_files():
        code = _code_without_comments(path.read_text(encoding="utf-8"))
        for sink in ("dangerouslySetInnerHTML", "innerHTML", "document.write"):
            assert sink not in code, (
                f"{sink} in {path.name} would let a hostile server inject markup"
            )


def test_the_built_pages_request_nothing_from_another_origin():
    # next/font self-hosts, so the interface works with no network and cannot
    # leak a case id through a font or asset request.
    for page in (UI / "index.html", UI / "record" / "index.html"):
        markup = page.read_text(encoding="utf-8")
        assert "http://" not in markup
        assert "https://" not in markup


def test_both_built_pages_carry_the_fixed_disclaimer():
    assert DISCLAIMER in (UI / "index.html").read_text(encoding="utf-8")
    assert DISCLAIMER in (UI / "record" / "index.html").read_text(encoding="utf-8")


def test_the_landing_page_avoids_the_banned_overclaiming_vocabulary():
    # Section 10 language discipline.
    body = (
        (UI / "index.html")
        .read_text(encoding="utf-8")
        .lower()
        .replace("absence of a finding is not proof of safety.", "")
    )

    for banned in ("verified safe", "guaranteed", "clean bill of health"):
        assert banned not in body, f"the landing page overclaims with {banned!r}"


def test_the_ui_verdict_rule_matches_the_backend_approval_rule():
    # capability_absent is a disclosed limitation in both places, so a
    # transcript-only audit does not stamp HOLD on every tool.
    verdict = (FRONTEND / "lib" / "verdict.ts").read_text(encoding="utf-8")
    approval = (ROOT / "airlock" / "approval.py").read_text(encoding="utf-8")

    assert "capability_absent" in verdict
    assert "capability_absent" in approval


def test_the_export_is_pinned_to_the_route_the_backend_mounts():
    # The hosted build serves the same export from a root, so the base path is
    # configurable. What must not drift is the default, because the backend
    # mounts the export at /ui and a different default would serve a page whose
    # asset URLs all miss.
    config = (FRONTEND / "next.config.ts").read_text(encoding="utf-8")

    assert 'output: "export"' in config
    assert 'process.env.AIRLOCK_UI_BASE_PATH ?? "/ui"' in config
    assert "trailingSlash: true" in config

    # The mount the default has to agree with.
    app = (ROOT / "airlock" / "app.py").read_text(encoding="utf-8")
    assert '"/ui"' in app


def test_an_unaudited_tool_is_never_stamped_cleared():
    # A case can hold declared tools while still inventoried or probing, with
    # no checks recorded. Stamping those CLEARED would assert a result that
    # does not exist.
    verdict = (FRONTEND / "lib" / "verdict.ts").read_text(encoding="utf-8")
    code = _code_without_comments(verdict)

    assert 'if (checks.length === 0) return "NOT AUDITED";' in code
    assert '"NOT AUDITED"' in (FRONTEND / "lib" / "types.ts").read_text(encoding="utf-8")


def test_case_selection_guards_against_a_stale_response():
    view = _code_without_comments(
        (FRONTEND / "app" / "record" / "RecordView.tsx").read_text(encoding="utf-8")
    )

    assert "latestRequest" in view
    assert "token !== latestRequest.current" in view
