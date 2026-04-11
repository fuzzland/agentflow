from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agentflow.audit.models import FindingRecord
from agentflow.audit.reporting import extract_json_document

_NO_PROGRESS_PATIENCE = 3
_VALIDATION_RANK = {
    "rejected": 0,
    "source_confirmed": 1,
    "poc_confirmed": 2,
}


class DiscoveryDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["CONTINUE", "STOP"]
    round: int
    consecutive_no_progress: int
    new_fingerprints: list[str] = Field(default_factory=list)
    validation_upgrades: list[str] = Field(default_factory=list)


class DiscoveryState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    round: int = 0
    consecutive_no_progress: int = 0
    accepted_findings: dict[str, FindingRecord] = Field(default_factory=dict)
    rejected_findings: dict[str, FindingRecord] = Field(default_factory=dict)
    history: list[DiscoveryDecision] = Field(default_factory=list)


def _choose_preferred_finding(existing: FindingRecord | None, current: FindingRecord) -> FindingRecord:
    if existing is None:
        return current
    if _VALIDATION_RANK[current.validation_status] > _VALIDATION_RANK[existing.validation_status]:
        return current
    if _VALIDATION_RANK[current.validation_status] < _VALIDATION_RANK[existing.validation_status]:
        return existing
    return current


def _deduplicate_round_findings(findings: list[FindingRecord]) -> dict[str, FindingRecord]:
    deduped: dict[str, FindingRecord] = {}
    for finding in findings:
        fingerprint = finding.dedup_fingerprint
        deduped[fingerprint] = _choose_preferred_finding(deduped.get(fingerprint), finding)
    return deduped


def _is_merged_finding(finding: FindingRecord) -> bool:
    return finding.review.disposition == "merged"


def load_discovery_state(path: str | Path) -> DiscoveryState:
    state_path = Path(path)
    if not state_path.exists():
        return DiscoveryState()
    return DiscoveryState.model_validate_json(state_path.read_text(encoding="utf-8"))


def write_discovery_state(path: str | Path, state: DiscoveryState) -> None:
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(state.model_dump_json(indent=2), encoding="utf-8")


def findings_from_text(text: str) -> list[FindingRecord]:
    payload = extract_json_document(text)
    if not isinstance(payload, list):
        raise ValueError("expected findings JSON array")
    return [FindingRecord.model_validate(item) for item in payload]


def apply_discovery_round(
    state: DiscoveryState,
    findings: list[FindingRecord],
    *,
    no_progress_patience: int = _NO_PROGRESS_PATIENCE,
) -> tuple[DiscoveryState, DiscoveryDecision]:
    accepted = dict(state.accepted_findings)
    rejected = dict(state.rejected_findings)
    new_fingerprints: list[str] = []
    validation_upgrades: list[str] = []

    for fingerprint, finding in _deduplicate_round_findings(findings).items():
        existing_accepted = accepted.get(fingerprint)
        existing_rejected = rejected.get(fingerprint)
        existing = existing_accepted or existing_rejected

        if _is_merged_finding(finding):
            accepted.pop(fingerprint, None)
            continue

        if finding.validation_status == "rejected":
            accepted.pop(fingerprint, None)
            rejected[fingerprint] = _choose_preferred_finding(existing, finding)
            continue

        if existing is None or existing.validation_status == "rejected":
            new_fingerprints.append(fingerprint)
        elif existing.validation_status == "source_confirmed" and finding.validation_status == "poc_confirmed":
            validation_upgrades.append(fingerprint)

        accepted[fingerprint] = _choose_preferred_finding(existing, finding)
        rejected.pop(fingerprint, None)

    progress_made = bool(new_fingerprints or validation_upgrades)
    consecutive_no_progress = 0 if progress_made else state.consecutive_no_progress + 1
    decision = DiscoveryDecision(
        status="STOP" if consecutive_no_progress >= no_progress_patience else "CONTINUE",
        round=state.round + 1,
        consecutive_no_progress=consecutive_no_progress,
        new_fingerprints=new_fingerprints,
        validation_upgrades=validation_upgrades,
    )
    next_state = DiscoveryState(
        round=decision.round,
        consecutive_no_progress=consecutive_no_progress,
        accepted_findings=accepted,
        rejected_findings=rejected,
        history=[*state.history, decision],
    )
    return next_state, decision


def advance_discovery_state(
    path: str | Path,
    findings: list[FindingRecord],
    *,
    no_progress_patience: int = _NO_PROGRESS_PATIENCE,
) -> tuple[DiscoveryState, DiscoveryDecision]:
    state = load_discovery_state(path)
    next_state, decision = apply_discovery_round(
        state,
        findings,
        no_progress_patience=no_progress_patience,
    )
    write_discovery_state(path, next_state)
    return next_state, decision


def customer_visible_findings(state: DiscoveryState) -> list[FindingRecord]:
    visible = [
        finding
        for finding in state.accepted_findings.values()
        if finding.validation_status != "rejected" and not _is_merged_finding(finding)
    ]
    return sorted(visible, key=lambda finding: finding.id)


def discovery_prompt_payload(state: DiscoveryState) -> dict[str, object]:
    return {
        "round": state.round,
        "consecutive_no_progress": state.consecutive_no_progress,
        "accepted_findings": [
            {
                "id": finding.id,
                "dedup_fingerprint": finding.dedup_fingerprint,
                "title": finding.title,
                "validation_status": finding.validation_status,
            }
            for finding in customer_visible_findings(state)
        ],
        "rejected_findings": [
            {
                "id": finding.id,
                "dedup_fingerprint": finding.dedup_fingerprint,
                "title": finding.title,
                "review_notes": finding.review.notes,
            }
            for finding in sorted(state.rejected_findings.values(), key=lambda item: item.id)
        ],
        "recent_history": [
            entry.model_dump(mode="json")
            for entry in state.history[-5:]
        ],
    }
