from pathlib import Path

from airlock.main import create_app_from_env


def test_environment_factory_builds_backend_with_owned_fixtures(tmp_path):
    app = create_app_from_env(
        {
            "AIRLOCK_CASE_ROOT": str(tmp_path / "cases"),
            "AIRLOCK_PUBLIC_BASE_URL": "http://127.0.0.1:8000",
            "AIRLOCK_ALLOW_LOCAL_TARGETS": "true",
            "AIRLOCK_MOUNT_OWNED_FIXTURES": "true",
            "AIRLOCK_FIXTURE_ROOT": str(tmp_path / "fixtures"),
            "AIRLOCK_FIXTURE_BEARER_TOKEN": "fixture-secret",
            "AIRLOCK_INSECURE_DEVELOPMENT": "true",
        }
    )

    assert app.state.case_store.root == Path(tmp_path / "cases")
    assert {route.path for route in app.routes} >= {
        "/airlock-control",
        "/fixtures/honest",
        "/fixtures/dishonest",
        "/cases/{case_id}/mcp",
    }


def test_environment_factory_rejects_invalid_boolean(tmp_path):
    try:
        create_app_from_env(
                {
                    "AIRLOCK_CASE_ROOT": str(tmp_path / "cases"),
                    "AIRLOCK_ALLOW_LOCAL_TARGETS": "sometimes",
                    "AIRLOCK_INSECURE_DEVELOPMENT": "true",
                }
        )
    except ValueError as exc:
        assert "AIRLOCK_ALLOW_LOCAL_TARGETS" in str(exc)
    else:
        raise AssertionError("invalid boolean was not rejected")


def test_environment_factory_requires_inbound_auth_by_default(tmp_path):
    try:
        create_app_from_env(
            {
                "AIRLOCK_CASE_ROOT": str(tmp_path / "cases"),
            }
        )
    except ValueError as exc:
        assert "bearer" in str(exc).lower()
    else:
        raise AssertionError("missing production authentication was not rejected")


def test_environment_factory_requires_state_integrity_key_in_production(tmp_path):
    try:
        create_app_from_env(
            {
                "AIRLOCK_CASE_ROOT": str(tmp_path / "cases"),
                "AIRLOCK_CONTROL_BEARER_TOKEN": "control-secret",
                "AIRLOCK_CASE_PROXY_BEARER_TOKEN": "runtime-secret",
            }
        )
    except ValueError as exc:
        assert "integrity" in str(exc).lower()
    else:
        raise AssertionError("missing state integrity key was not rejected")


def test_environment_factory_accepts_state_integrity_key_in_production(tmp_path):
    app = create_app_from_env(
        {
            "AIRLOCK_CASE_ROOT": str(tmp_path / "cases"),
            "AIRLOCK_CONTROL_BEARER_TOKEN": "control-secret",
            "AIRLOCK_CASE_PROXY_BEARER_TOKEN": "runtime-secret",
            "AIRLOCK_STATE_INTEGRITY_KEY": "s" * 32,
        }
    )

    assert app.state.case_store.integrity_enabled is True


def test_environment_factory_requires_exact_url_scope_for_target_auth(tmp_path):
    try:
        create_app_from_env(
            {
                "AIRLOCK_CASE_ROOT": str(tmp_path / "cases"),
                "AIRLOCK_CONTROL_BEARER_TOKEN": "control-secret",
                "AIRLOCK_CASE_PROXY_BEARER_TOKEN": "runtime-secret",
                "AIRLOCK_STATE_INTEGRITY_KEY": "s" * 32,
                "AIRLOCK_TARGET_AUTHORIZATION": "Bearer target-secret",
                "AIRLOCK_ALLOWED_TARGET_HOSTNAMES": "fixture.example",
            }
        )
    except ValueError as exc:
        assert "exact authenticated target URL" in str(exc)
    else:
        raise AssertionError("unscoped target credentials were not rejected")


def test_insecure_development_is_loopback_only_and_cannot_use_target_auth(tmp_path):
    for extra in (
        {"AIRLOCK_HOST": "0.0.0.0"},
        {
            "AIRLOCK_HOST": "127.0.0.1",
            "AIRLOCK_TARGET_AUTHORIZATION": "Bearer target-secret",
            "AIRLOCK_ALLOWED_TARGET_HOSTNAMES": "fixture.example",
        },
    ):
        values = {
            "AIRLOCK_CASE_ROOT": str(tmp_path / "cases"),
            "AIRLOCK_INSECURE_DEVELOPMENT": "true",
            **extra,
        }
        try:
            create_app_from_env(values)
        except ValueError as exc:
            assert "insecure development" in str(exc).lower()
        else:
            raise AssertionError("unsafe development configuration was not rejected")
