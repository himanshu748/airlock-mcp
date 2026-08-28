import pytest

from airlock.canaries import CanaryVault, CanaryVaultError
from airlock.models import DeclaredScope, ObservationCapabilities
from airlock.store import CaseIntegrityError, JsonCaseStore


def test_planted_canary_values_stay_out_of_downloadable_report(tmp_path):
    store = JsonCaseStore(tmp_path)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    vault = CanaryVault(store)

    planted = vault.plant(case.case_id, labels=["document_secret", "account_marker"])

    assert set(planted) == {"document_secret", "account_marker"}
    report_text = (
        tmp_path / case.case_id / "airlock-report.json"
    ).read_text(encoding="utf-8")
    assert all(value not in report_text for value in planted.values())
    assert vault.load(case.case_id) == planted
    assert (tmp_path / case.case_id / ".airlock-canaries.json").stat().st_mode & 0o777 == 0o600


def test_signed_canary_vault_rejects_tampering(tmp_path):
    store = JsonCaseStore(tmp_path, integrity_key="s" * 32)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    vault = CanaryVault(store)
    vault.plant(case.case_id, labels=["document_secret"])
    vault_path = tmp_path / case.case_id / ".airlock-canaries.json"
    vault_path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(CaseIntegrityError, match="integrity verification failed"):
        vault.load(case.case_id, expected_labels=["document_secret"])


def test_canary_vault_rejects_empty_or_unexpected_label_sets(tmp_path):
    store = JsonCaseStore(tmp_path)
    case = store.create_case(
        target_url="http://fixture.test/mcp",
        declared_scope=DeclaredScope(),
        observation_capabilities=ObservationCapabilities.controlled_fixture(),
    )
    vault = CanaryVault(store)
    vault.plant(case.case_id, labels=["document_secret"])

    with pytest.raises(CanaryVaultError, match="expected labels"):
        vault.load(case.case_id, expected_labels=["different_label"])

    (tmp_path / case.case_id / ".airlock-canaries.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    with pytest.raises(CanaryVaultError, match="invalid canary vault"):
        vault.load(case.case_id)
