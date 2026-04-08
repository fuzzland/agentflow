from __future__ import annotations

from agentflow.audit.models import ComponentRef, EvidenceRef, FindingRecord, PocRecord, ReportManifest, ReviewRecord
from agentflow.audit.reporting import public_findings_projection, render_audit_report


def _finding(
    finding_id: str,
    *,
    severity: str,
    validation_status: str,
    component_file: str,
    evidence_file: str | None = None,
    poc_status: str = "not_attempted",
    poc_test_path: str | None = None,
) -> FindingRecord:
    return FindingRecord(
        id=finding_id,
        title=f"{finding_id} title",
        severity=severity,
        category="logic",
        status="final",
        validation_status=validation_status,
        component=ComponentRef(file=component_file, symbol="transfer"),
        summary=f"{finding_id} summary",
        root_cause=f"{finding_id} root cause",
        attack_scenario=f"{finding_id} impact",
        review=ReviewRecord(disposition="confirmed", notes=""),
        dedup_fingerprint=f"fp-{finding_id}",
        poc=PocRecord(eligible=True, status=poc_status, test_path=poc_test_path),
        evidence=(
            [
                EvidenceRef(
                    file=evidence_file,
                    start_line=10,
                    end_line=20,
                    snippet_ref=f"{finding_id}-snippet",
                )
            ]
            if evidence_file is not None
            else []
        ),
    )


def test_render_audit_report_orders_findings_and_renders_validation_status_labels():
    manifest = ReportManifest(
        project_name="TokenVault",
        audit_scope="contracts",
        source_mode="local snapshot",
        source_identifier="local://snapshot",
        chain="Ethereum",
        contract_address_url="https://etherscan.io/address/0x1234",
        creation_tx_url="https://etherscan.io/tx/0xabcd",
    )
    findings = [
        _finding("F-020", severity="low", validation_status="rejected", component_file="contracts/Low.sol"),
        _finding(
            "F-002",
            severity="critical",
            validation_status="poc_confirmed",
            component_file="/tmp/workspace/contracts/Critical2.sol",
            poc_status="passed",
            poc_test_path="test/PoC.t.sol",
        ),
        _finding(
            "F-001",
            severity="critical",
            validation_status="source_confirmed",
            component_file="/tmp/workspace/contracts/Critical1.sol",
        ),
        _finding("F-010", severity="high", validation_status="source_confirmed", component_file="contracts/High.sol"),
    ]

    report = render_audit_report(manifest, findings)

    assert report.index("## Findings\n\n### F-001") < report.index("\n### F-002")
    assert report.index("\n### F-002") < report.index("\n### F-010")
    assert report.index("\n### F-010") < report.index("\n### F-020")
    assert "Validation Status: PoC Confirmed" in report
    assert "Validation Status: Source Confirmed" in report
    assert "Validation Status: Rejected" in report
    assert "PoC / Reproduction: test/PoC.t.sol" in report
    assert "Chain Context" in report
    assert "Contract Address: https://etherscan.io/address/0x1234" in report
    assert "Creation Transaction: https://etherscan.io/tx/0xabcd" in report


def test_public_findings_projection_never_leaks_absolute_paths():
    findings = [
        _finding(
            "F-100",
            severity="medium",
            validation_status="source_confirmed",
            component_file="/home/ubuntu/repo/contracts/AbsolutePath.sol",
            evidence_file="/home/ubuntu/repo/contracts/EvidenceAbsolute.sol",
            poc_test_path="/home/ubuntu/repo/test/PoCAbsolute.t.sol",
        ),
        _finding(
            "F-101",
            severity="medium",
            validation_status="source_confirmed",
            component_file="contracts/RelativePath.sol",
            evidence_file="contracts/EvidenceRelative.sol",
            poc_test_path="test/PoCRelative.t.sol",
        ),
        _finding(
            "F-102",
            severity="medium",
            validation_status="source_confirmed",
            component_file="../../private/Secret.sol",
            evidence_file="../outside/Evidence.sol",
            poc_test_path="..\\..\\private\\Exploit.t.sol",
        ),
    ]

    projected = public_findings_projection(findings)

    assert [item["id"] for item in projected] == ["F-100", "F-101", "F-102"]
    assert projected[0]["component"]["file"] == "AbsolutePath.sol"
    assert projected[1]["component"]["file"] == "contracts/RelativePath.sol"
    assert projected[2]["component"]["file"] == "Secret.sol"
    assert projected[0]["evidence"][0]["file"] == "EvidenceAbsolute.sol"
    assert projected[1]["evidence"][0]["file"] == "contracts/EvidenceRelative.sol"
    assert projected[2]["evidence"][0]["file"] == "Evidence.sol"
    assert projected[0]["poc"]["test_path"] == "PoCAbsolute.t.sol"
    assert projected[1]["poc"]["test_path"] == "test/PoCRelative.t.sol"
    assert projected[2]["poc"]["test_path"] == "Exploit.t.sol"
    assert all(not item["component"]["file"].startswith("/") for item in projected)
    assert all(not item["evidence"][0]["file"].startswith("/") for item in projected)
    assert all(not str(item["poc"]["test_path"]).startswith("/") for item in projected)
    assert all(".." not in item["component"]["file"] for item in projected)
    assert all(".." not in item["evidence"][0]["file"] for item in projected)
    assert all(".." not in str(item["poc"]["test_path"]) for item in projected)


def test_render_audit_report_sanitizes_absolute_poc_paths():
    manifest = ReportManifest(
        project_name="TokenVault",
        audit_scope="contracts",
        source_mode="local snapshot",
        source_identifier="local://snapshot",
    )
    finding = _finding(
        "F-900",
        severity="high",
        validation_status="poc_confirmed",
        component_file="contracts/Vault.sol",
        poc_status="passed",
        poc_test_path="/data/workdir/tests/poc/Exploit.t.sol",
    )

    report = render_audit_report(manifest, [finding])

    assert "PoC / Reproduction: Exploit.t.sol" in report
    assert "/data/workdir/tests/poc/Exploit.t.sol" not in report


def test_render_audit_report_sanitizes_traversal_style_poc_paths():
    manifest = ReportManifest(
        project_name="TokenVault",
        audit_scope="contracts",
        source_mode="local snapshot",
        source_identifier="local://snapshot",
    )
    finding = _finding(
        "F-901",
        severity="high",
        validation_status="poc_confirmed",
        component_file="contracts/Vault.sol",
        poc_status="passed",
        poc_test_path="..\\..\\private\\Exploit.t.sol",
    )

    report = render_audit_report(manifest, [finding])

    assert "PoC / Reproduction: Exploit.t.sol" in report
    assert "..\\..\\private\\Exploit.t.sol" not in report
