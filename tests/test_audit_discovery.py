from __future__ import annotations

from agentflow.audit.discovery import DiscoveryState, apply_discovery_round, findings_from_text
from agentflow.audit.models import ComponentRef, FindingRecord, PocRecord, ReviewRecord


def _finding(
    fingerprint: str,
    *,
    validation_status: str,
    finding_id: str | None = None,
) -> FindingRecord:
    return FindingRecord(
        id=finding_id or fingerprint.upper(),
        title=f"{fingerprint} title",
        severity="medium",
        category="logic",
        status="final",
        validation_status=validation_status,
        component=ComponentRef(file="src/contracts/Vault.sol", symbol="run"),
        summary=f"{fingerprint} summary",
        root_cause=f"{fingerprint} root cause",
        attack_scenario=f"{fingerprint} impact",
        poc=PocRecord(eligible=True, status="passed" if validation_status == "poc_confirmed" else "not_attempted"),
        review=ReviewRecord(disposition="confirmed", notes=""),
        dedup_fingerprint=fingerprint,
    )


def test_apply_discovery_round_stops_after_three_consecutive_rounds_without_material_progress():
    state = DiscoveryState()

    state, decision = apply_discovery_round(state, [_finding("fp-1", validation_status="source_confirmed")])
    assert decision.status == "CONTINUE"
    assert state.consecutive_no_progress == 0

    state, decision = apply_discovery_round(state, [_finding("fp-1", validation_status="source_confirmed")])
    assert decision.status == "CONTINUE"
    assert state.consecutive_no_progress == 1

    state, decision = apply_discovery_round(state, [_finding("fp-1", validation_status="source_confirmed")])
    assert decision.status == "CONTINUE"
    assert state.consecutive_no_progress == 2

    state, decision = apply_discovery_round(state, [_finding("fp-1", validation_status="source_confirmed")])
    assert decision.status == "STOP"
    assert state.consecutive_no_progress == 3


def test_apply_discovery_round_treats_source_to_poc_upgrade_as_material_progress():
    state = DiscoveryState()

    state, decision = apply_discovery_round(state, [_finding("fp-1", validation_status="source_confirmed")])
    assert decision.validation_upgrades == []

    state, decision = apply_discovery_round(state, [_finding("fp-1", validation_status="source_confirmed")])
    assert state.consecutive_no_progress == 1

    state, decision = apply_discovery_round(state, [_finding("fp-1", validation_status="poc_confirmed")])
    assert decision.status == "CONTINUE"
    assert decision.validation_upgrades == ["fp-1"]
    assert state.consecutive_no_progress == 0
    assert state.accepted_findings["fp-1"].validation_status == "poc_confirmed"


def test_findings_from_text_ignores_inline_empty_array_and_uses_trailing_findings_json():
    text = """
Using the repo FindingRecord[] shape for this pass.

[
  {
    "id": "CAN-01",
    "title": "Example finding",
    "severity": "medium",
    "category": "logic",
    "status": "validated",
    "validation_status": "source_confirmed",
    "component": {"file": "src/contracts/Vault.sol", "symbol": "run"},
    "summary": "summary",
    "root_cause": "root cause",
    "attack_scenario": "impact",
    "poc": {"eligible": true, "status": "not_attempted", "test_path": null},
    "review": {"disposition": "confirmed", "notes": "notes"},
    "dedup_fingerprint": "fp-1"
  }
]
""".strip()

    findings = findings_from_text(text)

    assert [finding.id for finding in findings] == ["CAN-01"]
