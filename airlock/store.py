from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

from .models import (
    CaseRecord,
    CaseStatus,
    DeclaredScope,
    EvidenceEvent,
    EvidenceMode,
    Finding,
    ObservationCapabilities,
    ProbeRecord,
    TargetBinding,
)


_CASE_ID_PATTERN = re.compile(r"^af_[0-9a-f]{32}$")
_DOWNLOADABLE_ARTIFACTS = frozenset(
    {
        "airlock-report.json",
        "airlock-policy.json",
        "airlock-connector.json",
    }
)
_DERIVED_ARTIFACTS = _DOWNLOADABLE_ARTIFACTS - {"airlock-report.json"}
_PRIVATE_ARTIFACTS = frozenset({".airlock-canaries.json"})


class CaseIntegrityError(ValueError):
    """Persisted case state or a derived artifact failed authentication."""


class JsonCaseStore:
    def __init__(
        self,
        root: Path | str,
        *,
        integrity_key: str | bytes | None = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root.chmod(0o700)
        if isinstance(integrity_key, str):
            normalized_key = integrity_key.encode("utf-8")
        else:
            normalized_key = integrity_key
        if normalized_key is not None and len(normalized_key) < 32:
            raise ValueError("integrity_key must contain at least 32 bytes")
        self._integrity_key = normalized_key
        self._lock = threading.RLock()

    @property
    def integrity_enabled(self) -> bool:
        return self._integrity_key is not None

    def create_case(
        self,
        *,
        target_url: str,
        declared_scope: DeclaredScope,
        observation_capabilities: ObservationCapabilities,
        evidence_mode: EvidenceMode = EvidenceMode.TRANSCRIPT_ONLY,
        proxy_url: str | None = None,
        target_binding: TargetBinding | None = None,
    ) -> CaseRecord:
        record = CaseRecord.new(
            case_id=f"af_{uuid4().hex}",
            target_url=target_url,
            declared_scope=declared_scope,
            observation_capabilities=observation_capabilities,
            evidence_mode=evidence_mode,
            proxy_url=proxy_url,
            target_binding=target_binding,
        )
        self.save_case(record)
        return record

    def list_case_ids(self) -> list[str]:
        with self._lock:
            return sorted(
                entry.name
                for entry in self.root.iterdir()
                if entry.is_dir() and _CASE_ID_PATTERN.fullmatch(entry.name)
            )

    def load_case(self, case_id: str) -> CaseRecord:
        with self._lock:
            report_path = self._case_directory(case_id) / "airlock-report.json"
            serialized = self._read_verified_file(report_path)
            return CaseRecord.model_validate_json(serialized)

    def append_event(self, case_id: str, event: EvidenceEvent) -> CaseRecord:
        with self._lock:
            record = self.load_case(case_id)
            for existing in record.events:
                if existing.event_id != event.event_id:
                    continue
                if existing.model_dump(mode="json") != event.model_dump(mode="json"):
                    raise ValueError("event id already exists with different content")
                return record
            updated = record.model_copy(update={"events": [*record.events, event]})
            self.save_case(updated)
            return updated

    def append_runtime_event(
        self,
        case_id: str,
        event: EvidenceEvent,
        *,
        max_runtime_events: int,
    ) -> CaseRecord:
        if not event.probe_id.startswith("runtime_"):
            raise ValueError("runtime event probe id must start with runtime_")
        if type(max_runtime_events) is not int or max_runtime_events <= 0:
            raise ValueError("max_runtime_events must be a positive integer")
        with self._lock:
            record = self.load_case(case_id)
            for existing in record.events:
                if existing.event_id != event.event_id:
                    continue
                if existing != event:
                    raise ValueError(
                        "runtime event id already exists with different content"
                    )
                return record
            audit_events = [
                existing
                for existing in record.events
                if not existing.probe_id.startswith("runtime_")
            ]
            runtime_events = [
                existing
                for existing in record.events
                if existing.probe_id.startswith("runtime_")
            ]
            runtime_events.append(event)
            overflow = max(0, len(runtime_events) - max_runtime_events)
            if overflow:
                runtime_events = runtime_events[overflow:]
            updated = record.model_copy(
                update={
                    "events": [*audit_events, *runtime_events],
                    "runtime_events_dropped": (
                        record.runtime_events_dropped + overflow
                    ),
                }
            )
            self.save_case(updated)
            return updated

    def append_probe(self, case_id: str, probe: ProbeRecord) -> CaseRecord:
        if not probe.completed:
            raise ValueError("append_probe requires a completed probe")
        with self._lock:
            record = self.load_case(case_id)
            for existing in record.probes:
                if existing.probe_id != probe.probe_id:
                    continue
                if existing.model_dump(mode="json") != probe.model_dump(mode="json"):
                    raise ValueError("probe id already exists with different content")
                return record
            if record.probe_budget and record.probes_run >= record.probe_budget:
                raise ValueError("case probe budget is exhausted")
            updated = record.model_copy(
                update={
                    "probes": [*record.probes, probe],
                    "probes_run": len(record.probes) + 1,
                }
            )
            self.save_case(updated)
            return updated

    def configure_probe_budget(
        self,
        case_id: str,
        *,
        probe_budget: int,
    ) -> CaseRecord:
        with self._lock:
            record = self.load_case(case_id)
            if record.probe_budget != 0:
                return record
            updated = record.model_copy(update={"probe_budget": probe_budget})
            self.save_case(updated)
            return updated

    def reserve_probe(self, case_id: str, probe: ProbeRecord) -> bool:
        if probe.completed:
            raise ValueError("probe reservation must be incomplete")
        with self._lock:
            record = self.load_case(case_id)
            for existing in record.probes:
                if existing.probe_id != probe.probe_id:
                    continue
                same_identity = (
                    existing.tool == probe.tool
                    and existing.kind == probe.kind
                    and existing.request == probe.request
                    and existing.supplied_canary_ids == probe.supplied_canary_ids
                )
                if not same_identity:
                    raise ValueError(
                        "probe id already exists with different reservation content"
                    )
                return False
            if record.probe_budget and record.probes_run >= record.probe_budget:
                raise ValueError("case probe budget is exhausted")
            updated = record.model_copy(
                update={
                    "probes": [*record.probes, probe],
                    "probes_run": record.probes_run + 1,
                }
            )
            self.save_case(updated)
            return True

    def complete_probe(self, case_id: str, probe: ProbeRecord) -> CaseRecord:
        if not probe.completed:
            raise ValueError("completed probe must set completed=true")
        with self._lock:
            record = self.load_case(case_id)
            replacement_index: int | None = None
            for index, existing in enumerate(record.probes):
                if existing.probe_id != probe.probe_id:
                    continue
                if existing.completed:
                    if existing != probe:
                        raise ValueError(
                            "completed probe id already exists with different content"
                        )
                    return record
                same_identity = (
                    existing.tool == probe.tool
                    and existing.kind == probe.kind
                    and existing.request == probe.request
                    and existing.supplied_canary_ids == probe.supplied_canary_ids
                )
                if not same_identity:
                    raise ValueError(
                        "completed probe does not match its reservation"
                    )
                replacement_index = index
                break
            if replacement_index is None:
                raise ValueError("probe has no persisted reservation")
            probes = list(record.probes)
            probes[replacement_index] = probe
            updated = record.model_copy(update={"probes": probes})
            self.save_case(updated)
            return updated

    def mark_incomplete(
        self,
        case_id: str,
        *,
        checks: list[Finding] | None = None,
    ) -> CaseRecord:
        with self._lock:
            record = self.load_case(case_id)
            updates: dict[str, Any] = {
                "status": CaseStatus.INCOMPLETE,
                "enforcement_active": False,
                "audit_completed_at": None,
            }
            if checks is not None:
                updates["checks"] = checks
            updated = record.model_copy(update=updates)
            self.save_case(updated)
            return updated

    def save_case(self, record: CaseRecord) -> None:
        with self._lock:
            case_directory = self._case_directory(record.case_id)
            case_directory.mkdir(mode=0o700, parents=False, exist_ok=True)
            case_directory.chmod(0o700)
            report_path = case_directory / "airlock-report.json"
            serialized = (
                json.dumps(
                    record.model_dump(mode="json", by_alias=True),
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            self._write_verified_file(report_path, serialized)

    def write_json_artifact(
        self,
        case_id: str,
        artifact_name: str,
        payload: dict[str, Any],
    ) -> Path:
        if artifact_name not in _DERIVED_ARTIFACTS:
            raise ValueError("artifact name is not writable")
        with self._lock:
            case_directory = self._case_directory(case_id)
            if not case_directory.is_dir():
                raise FileNotFoundError("case not found")
            artifact_path = case_directory / artifact_name
            serialized = (
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            self._write_verified_file(artifact_path, serialized)
            return artifact_path

    def read_artifact(self, case_id: str, artifact_name: str) -> bytes:
        if artifact_name not in _DOWNLOADABLE_ARTIFACTS:
            raise FileNotFoundError("artifact not found")
        with self._lock:
            artifact_path = self._case_directory(case_id) / artifact_name
            return self._read_verified_file(artifact_path)

    def write_private_json(
        self,
        case_id: str,
        artifact_name: str,
        payload: dict[str, Any],
    ) -> Path:
        if artifact_name not in _PRIVATE_ARTIFACTS:
            raise ValueError("private artifact name is not writable")
        with self._lock:
            case_directory = self._case_directory(case_id)
            if not case_directory.is_dir():
                raise FileNotFoundError("case not found")
            artifact_path = case_directory / artifact_name
            serialized = (
                json.dumps(payload, sort_keys=True) + "\n"
            ).encode("utf-8")
            self._write_verified_file(artifact_path, serialized)
            return artifact_path

    def read_private_artifact(self, case_id: str, artifact_name: str) -> bytes:
        if artifact_name not in _PRIVATE_ARTIFACTS:
            raise FileNotFoundError("private artifact not found")
        with self._lock:
            artifact_path = self._case_directory(case_id) / artifact_name
            return self._read_verified_file(artifact_path)

    def _write_verified_file(self, path: Path, payload: bytes) -> None:
        self._atomic_write_private(path, payload)
        if self._integrity_key is not None:
            signature = (self._signature(path, payload) + "\n").encode("ascii")
            self._atomic_write_private(self._signature_path(path), signature)

    def _read_verified_file(self, path: Path) -> bytes:
        payload = path.read_bytes()
        if self._integrity_key is None:
            return payload
        try:
            supplied = self._signature_path(path).read_text(
                encoding="ascii"
            ).strip()
        except (FileNotFoundError, UnicodeDecodeError) as exc:
            raise CaseIntegrityError(
                "case state integrity verification failed"
            ) from exc
        expected = self._signature(path, payload)
        if not hmac.compare_digest(supplied, expected):
            raise CaseIntegrityError("case state integrity verification failed")
        return payload

    def _signature(self, path: Path, payload: bytes) -> str:
        if self._integrity_key is None:
            raise RuntimeError("integrity signing is not configured")
        relative_path = path.relative_to(self.root).as_posix().encode("utf-8")
        authenticated = b"airlock-store-v1\x00" + relative_path + b"\x00" + payload
        return hmac.new(
            self._integrity_key,
            authenticated,
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _signature_path(path: Path) -> Path:
        return path.with_name(f".{path.name}.sig")

    @staticmethod
    def _atomic_write_private(path: Path, payload: bytes) -> None:
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=path.parent,
                prefix=f".{path.name}-",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(payload)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            temporary_path.chmod(0o600)
            os.replace(temporary_path, path)
            temporary_path = None
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def _case_directory(self, case_id: str) -> Path:
        if not _CASE_ID_PATTERN.fullmatch(case_id):
            raise ValueError("invalid case id")
        return self.root / case_id

    def case_directory(self, case_id: str) -> Path:
        return self._case_directory(case_id)


__all__ = ["CaseIntegrityError", "JsonCaseStore"]
