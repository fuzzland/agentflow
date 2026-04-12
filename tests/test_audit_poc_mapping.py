from __future__ import annotations

from pathlib import Path

from agentflow.audit.models import ComponentRef, FindingRecord, PocRecord, ReviewRecord
from agentflow.audit.poc_mapping import derive_poc_mappings


def _finding(
    finding_id: str,
    *,
    dedup_fingerprint: str,
    title: str,
) -> FindingRecord:
    return FindingRecord(
        id=finding_id,
        title=title,
        severity="medium",
        category="logic",
        status="validated",
        validation_status="source_confirmed",
        component=ComponentRef(file="src/protocol/Vault.sol", symbol="run"),
        summary=title,
        root_cause=title,
        attack_scenario=title,
        poc=PocRecord(eligible=True, status="not_attempted"),
        review=ReviewRecord(disposition="confirmed", notes=""),
        dedup_fingerprint=dedup_fingerprint,
    )


def test_derive_poc_mappings_matches_exact_id_and_fuzzy_name(tmp_path: Path) -> None:
    security_dir = tmp_path / "test" / "security"
    security_dir.mkdir(parents=True)
    (security_dir / "StateAndIntegrationPoC.t.sol").write_text(
        """
        contract StateAndIntegrationPoCTest {
            function test_cf_01_constructor_sets_owner_to_tx_origin() public {}
            function test_interest_setter_zero_probe_admission_allows_runtime_freeze() public {}
        }
        """,
        encoding="utf-8",
    )

    findings = [
        _finding(
            "CF-01",
            dedup_fingerprint="dolomite:tx-origin-owner",
            title="Constructor sets owner to tx.origin",
        ),
        _finding(
            "interest-setter-zero-probe-runtime-freeze",
            dedup_fingerprint="adminimpl::_setinterestsetter::zero_probe_only::live_totals_revert",
            title="Interest setter zero probe admission allows runtime freeze",
        ),
        _finding(
            "UNMAPPED-01",
            dedup_fingerprint="unmapped:finding",
            title="No matching test exists",
        ),
    ]

    mappings = derive_poc_mappings(findings, tmp_path)

    by_id = {item["finding_id"]: item for item in mappings}
    assert by_id["CF-01"]["test_path"] == "test/security/StateAndIntegrationPoC.t.sol"
    assert by_id["CF-01"]["test_name"] == "test_cf_01_constructor_sets_owner_to_tx_origin"
    assert by_id["interest-setter-zero-probe-runtime-freeze"]["test_name"] == "test_interest_setter_zero_probe_admission_allows_runtime_freeze"
    assert by_id["UNMAPPED-01"]["test_path"] is None
    assert by_id["UNMAPPED-01"]["reason"]
