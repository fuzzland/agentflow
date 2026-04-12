from __future__ import annotations

from agentflow.audit.curation import CurationState, apply_curation_round, curate_findings, curated_findings_for_output
from agentflow.audit.models import ComponentRef, EvidenceRef, FindingRecord, PocRecord, ReviewRecord


def _finding(
    fingerprint: str,
    *,
    finding_id: str | None = None,
    validation_status: str = "source_confirmed",
    disposition: str = "confirmed",
    evidence_count: int = 1,
) -> FindingRecord:
    return FindingRecord(
        id=finding_id or fingerprint.upper(),
        title=f"{fingerprint} title",
        severity="medium",
        category="logic",
        status="final",
        validation_status=validation_status,
        component=ComponentRef(file="src/protocol/Vault.sol", symbol="operate"),
        summary=f"{fingerprint} summary",
        root_cause=f"{fingerprint} root cause",
        attack_scenario=f"{fingerprint} impact",
        evidence=[
            EvidenceRef(
                file=f"src/protocol/Vault{index}.sol",
                start_line=10 + index,
                end_line=20 + index,
                snippet_ref=f"{fingerprint}-snippet-{index}",
            )
            for index in range(evidence_count)
        ],
        poc=PocRecord(eligible=True, status="not_attempted"),
        review=ReviewRecord(disposition=disposition, notes=""),
        dedup_fingerprint=fingerprint,
    )


def test_apply_curation_round_stops_after_three_identical_rounds() -> None:
    state = CurationState()
    findings = [_finding("fp-1")]

    state, decision = apply_curation_round(state, findings)
    assert decision.status == "CONTINUE"
    assert state.consecutive_no_change == 0

    state, decision = apply_curation_round(state, findings)
    assert decision.status == "CONTINUE"
    assert state.consecutive_no_change == 1

    state, decision = apply_curation_round(state, findings)
    assert decision.status == "CONTINUE"
    assert state.consecutive_no_change == 2

    state, decision = apply_curation_round(state, findings)
    assert decision.status == "STOP"
    assert state.consecutive_no_change == 3


def test_apply_curation_round_treats_merge_and_reject_as_real_changes() -> None:
    state, _ = apply_curation_round(
        CurationState(),
        [_finding("fp-1", finding_id="CAN-01"), _finding("fp-2", finding_id="CAN-02")],
    )

    merged_state, decision = apply_curation_round(
        state,
        [_finding("fp-1", finding_id="CAN-01", evidence_count=2)],
    )

    assert decision.status == "CONTINUE"
    assert merged_state.consecutive_no_change == 0
    assert [finding.id for finding in merged_state.curated_findings] == ["CAN-01"]
    assert len(merged_state.curated_findings[0].evidence) == 2


def test_curated_findings_for_output_filters_rejected_and_merged_records() -> None:
    findings = [
        _finding("fp-keep", finding_id="CAN-01"),
        _finding("fp-merged", finding_id="CAN-02", disposition="merged"),
        _finding("fp-rejected", finding_id="CAN-03", validation_status="rejected", disposition="rejected"),
    ]

    curated = curated_findings_for_output(findings)

    assert [finding.id for finding in curated] == ["CAN-01"]


def test_curate_findings_merges_similar_root_cause_variants_and_keeps_all_evidence() -> None:
    left = _finding("hook-reentry-a", finding_id="CAN-10", evidence_count=1)
    right = _finding("hook-reentry-b", finding_id="CAN-11", evidence_count=2)
    left = left.model_copy(
        update={
            "title": "Hook callback can mutate ownership during external execution",
            "summary": "External callback can re-enter owner mutation paths while state is mid-flight.",
            "root_cause": "Untrusted callback execution shares the same owner-changing control surface.",
            "attack_scenario": "A malicious hook folds ownership mutation into a callback and changes admin state.",
            "category": "integration",
        }
    )
    right = right.model_copy(
        update={
            "title": "Callback-driven owner mutation remains reachable through the same hook path",
            "summary": "The same callback path can still hit ownership mutation while protocol state is unstable.",
            "root_cause": "Owner mutation is exposed through the same untrusted callback surface.",
            "attack_scenario": "A hook-driven re-entry sequence lets an attacker alter admin state during execution.",
            "category": "integration",
        }
    )

    curated = curate_findings([left, right])

    assert [finding.id for finding in curated] == ["CAN-10"]
    assert len(curated[0].evidence) == 3


def test_curate_findings_makes_duplicate_ids_unique() -> None:
    left = _finding("fp-1", finding_id="CAN-01")
    right = _finding("fp-2", finding_id="CAN-01")
    right = right.model_copy(
        update={
            "title": "Distinct accounting drift finding",
            "summary": "A separate accounting path can drift from the stored balance checkpoints.",
            "root_cause": "Independent accounting logic fails to reconcile a different state transition.",
            "attack_scenario": "A separate execution path can produce a distinct balance mismatch.",
            "category": "accounting",
        }
    )

    curated = curate_findings([left, right])

    assert [finding.id for finding in curated] == ["CAN-01", "CAN-01-2"]
