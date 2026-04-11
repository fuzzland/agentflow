from __future__ import annotations

from agentflow.audit.models import (
    ChainContext,
    ComponentRef,
    ContractAuditManifest,
    EvidenceRef,
    FindingRecord,
    GitHubSourceConfig,
    LocalSourceConfig,
    PocRecord,
    PolicyConfig,
    ReportManifest,
    ReviewRecord,
    RunConfig,
    TargetConfig,
    TargetReportConfig,
)
import json

from agentflow.audit.reporting import (
    extract_json_document,
    infer_package_execution_time,
    public_findings_projection,
    render_audit_report,
    render_package_readme,
    write_package_readme,
    write_report_bundle,
)


def _finding(
    finding_id: str,
    *,
    severity: str,
    validation_status: str,
    component_file: str,
    evidence_file: str | None = None,
    poc_status: str = "not_attempted",
    poc_test_path: str | None = None,
    summary_text: str | None = None,
    root_cause_text: str | None = None,
    attack_scenario_text: str | None = None,
    review_notes: str = "",
) -> FindingRecord:
    return FindingRecord(
        id=finding_id,
        title=f"{finding_id} title",
        severity=severity,
        category="logic",
        status="final",
        validation_status=validation_status,
        component=ComponentRef(file=component_file, symbol="transfer"),
        summary=summary_text or f"{finding_id} summary",
        root_cause=root_cause_text or f"{finding_id} root cause",
        attack_scenario=attack_scenario_text or f"{finding_id} impact",
        review=ReviewRecord(disposition="confirmed", notes=review_notes),
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
    assert "Validation Status: PoC Confirmed" in report
    assert "Validation Status: Source Confirmed" in report
    assert "Validation Status: Rejected" not in report
    assert "### F-020" not in report
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
    assert projected[0]["evidence"][0]["snippet_ref"] == "F-100-snippet"
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


def test_public_findings_projection_sanitizes_absolute_paths_inside_free_text_fields():
    findings = [
        _finding(
            "F-300",
            severity="high",
            validation_status="source_confirmed",
            component_file="contracts/Vault.sol",
            summary_text="Observed at /tmp/workspace/src/Vault.sol during review.",
            root_cause_text=r"Mirror on C:\Users\alice\audit\RootCause.sol must not leak.",
            attack_scenario_text=r"UNC path \\server\share\attack.txt should also be sanitized.",
            review_notes="See /var/tmp/repro.log for the raw repro notes.",
        )
    ]

    projected = public_findings_projection(findings)

    payload = projected[0]
    assert "/tmp/workspace/src/Vault.sol" not in payload["summary"]
    assert r"C:\Users\alice\audit\RootCause.sol" not in payload["root_cause"]
    assert r"\\server\share\attack.txt" not in payload["attack_scenario"]
    assert "/var/tmp/repro.log" not in payload["review"]["notes"]
    assert "Vault.sol" in payload["summary"]
    assert "RootCause.sol" in payload["root_cause"]
    assert "attack.txt" in payload["attack_scenario"]
    assert "repro.log" in payload["review"]["notes"]


def test_render_audit_report_sanitizes_absolute_paths_inside_free_text_fields():
    manifest = ReportManifest(
        project_name="TokenVault",
        audit_scope="contracts",
        source_mode="local snapshot",
        source_identifier="local://snapshot",
    )
    finding = _finding(
        "F-301",
        severity="high",
        validation_status="source_confirmed",
        component_file="contracts/Vault.sol",
        summary_text="Source path /tmp/workspace/src/Vault.sol should not be rendered verbatim.",
        root_cause_text=r"Windows path C:\Users\alice\audit\RootCause.sol should not survive.",
        attack_scenario_text=r"UNC path \\server\share\attack.txt should be reduced.",
    )

    report = render_audit_report(manifest, [finding])

    assert "/tmp/workspace/src/Vault.sol" not in report
    assert r"C:\Users\alice\audit\RootCause.sol" not in report
    assert r"\\server\share\attack.txt" not in report
    assert "Vault.sol" in report
    assert "RootCause.sol" in report
    assert "attack.txt" in report


def test_public_findings_projection_sanitizes_absolute_paths_inside_snippet_refs():
    finding = _finding(
        "F-302",
        severity="medium",
        validation_status="source_confirmed",
        component_file="contracts/Vault.sol",
        evidence_file="contracts/Vault.sol",
    )
    finding.evidence[0].snippet_ref = "/Users/alice/private/debug.txt:1-2"

    projected = public_findings_projection([finding])

    assert projected[0]["evidence"][0]["snippet_ref"] == "debug.txt:1-2"


def test_extract_json_document_accepts_leading_prose_before_json_array():
    payload = extract_json_document(
        "Using skills first.\nValidating schema now.\n[\n  {\"id\": \"CF-02\"},\n  {\"id\": \"CF-04\"}\n]\n"
    )

    assert payload == [{"id": "CF-02"}, {"id": "CF-04"}]


def test_extract_json_document_accepts_trailing_text_after_json_object():
    payload = extract_json_document("{\"status\": \"ok\"}\nFinal note.\n")

    assert payload == {"status": "ok"}


def test_write_report_bundle_filters_rejected_findings_from_customer_outputs(tmp_path):
    manifest = ReportManifest(
        project_name="TokenVault",
        audit_scope="contracts",
        source_mode="local snapshot",
        source_identifier="local://snapshot",
    )
    findings = [
        _finding("F-010", severity="high", validation_status="source_confirmed", component_file="contracts/High.sol"),
        _finding("F-020", severity="low", validation_status="rejected", component_file="contracts/Low.sol"),
    ]

    write_report_bundle(tmp_path, manifest, findings)

    report_text = (tmp_path / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    public_findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    summary = json.loads((tmp_path / "audit_summary.json").read_text(encoding="utf-8"))

    assert "### F-010" in report_text
    assert "### F-020" not in report_text
    assert [item["id"] for item in public_findings] == ["F-010"]
    assert summary["total_findings"] == 1
    assert summary["validation_counts"]["rejected"] == 0


def test_write_report_bundle_writes_root_audit_report_for_standard_package_layout(tmp_path):
    package_dir = tmp_path / "cap-vault-reports"
    report_dir = package_dir / "artifacts" / "report"
    manifest = ReportManifest(
        project_name="TokenVault",
        audit_scope="contracts",
        source_mode="local snapshot",
        source_identifier="local://snapshot",
    )
    findings = [
        _finding(
            "F-010",
            severity="high",
            validation_status="poc_confirmed",
            component_file="contracts/High.sol",
            poc_status="passed",
            poc_test_path="test/security/VaultPoC.t.sol",
        )
    ]

    write_report_bundle(report_dir, manifest, findings)

    nested_report = (report_dir / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    root_report = (package_dir / "AUDIT_REPORT.md").read_text(encoding="utf-8")

    assert nested_report == root_report
    assert "### F-010" in root_report


def test_render_package_readme_includes_customer_summary_verification_and_deliverables(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    package_dir = tmp_path / "cap-vault-reports"
    workspace_dir = package_dir / "artifacts" / "workspace" / "foundry_project"
    workspace_dir.mkdir(parents=True)
    manifest = ContractAuditManifest(
        target=TargetConfig(
            source=LocalSourceConfig(kind="local", local_path=source_dir),
            report=TargetReportConfig(project_name="TokenVault", audit_scope="src/contracts/vault"),
            chain_context=ChainContext(
                chain="ethereum",
                contract_address_url="https://etherscan.io/address/0x1234",
                creation_tx_url="https://etherscan.io/tx/0xabcd",
            ),
        ),
        run=RunConfig(
            artifacts_dir=str(package_dir / "artifacts"),
            parallel_shards=6,
        ),
        policy=PolicyConfig(),
    )
    report_manifest = ReportManifest(
        project_name="TokenVault",
        audit_scope="src/contracts/vault",
        source_mode="local snapshot",
        source_identifier="snapshot:deadbeef",
        chain="ethereum",
        contract_address_url="https://etherscan.io/address/0x1234",
        creation_tx_url="https://etherscan.io/tx/0xabcd",
    )
    findings = [
        _finding(
            "CAN-01",
            severity="high",
            validation_status="poc_confirmed",
            component_file="src/contracts/Vault.sol",
            poc_status="passed",
            poc_test_path="test/security/VaultPoC.t.sol",
            summary_text="Permissionless initialization lets the first caller seize bootstrap.",
        ),
        _finding(
            "CAN-02",
            severity="medium",
            validation_status="poc_confirmed",
            component_file="src/contracts/Vault.sol",
            poc_status="passed",
            poc_test_path="test/security/VaultPoC.t.sol",
            summary_text="A second PoC-confirmed issue is present.",
        ),
    ]
    verification = {
        "workspace": str(workspace_dir),
        "build": {"status": "passed", "command": "forge build", "exit_code": 0},
        "test": {"status": "passed", "command": "forge test -vvv", "exit_code": 0},
        "stdout": "Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 12.34ms (5.67ms CPU time)\n",
        "stderr": "",
    }

    readme = render_package_readme(
        package_dir,
        manifest,
        report_manifest,
        findings,
        verification=verification,
        execution_time="~8h 20m",
    )

    assert "# TokenVault Audit Package" in readme
    assert "## Executive Summary" in readme
    assert "## Scope" in readme
    assert "## Verification" in readme
    assert "## Deliverables" in readme
    assert "## Key Findings" in readme
    assert "| Execution Time | `~8h 20m` |" in readme
    assert "| Audit Report | `AUDIT_REPORT.md` |" in readme
    assert (
        "| PoC Test | `artifacts/workspace/foundry_project/test/security/VaultPoC.t.sol` |"
        in readme
    )
    assert "- Source directory: `../source`" in readme
    assert "cd artifacts/workspace/foundry_project" in readme
    assert "forge build" in readme
    assert "forge test -vvv" in readme
    assert "- `forge build`: `passed` (exit `0`)" in readme
    assert "- `forge test -vvv`: `passed` (exit `0`)" in readme
    assert "- PoC suite: `2 passed, 0 failed, 0 skipped`" in readme
    assert "| `AUDIT_REPORT.md` | Human-readable audit report |" in readme
    assert "`artifacts/workspace/foundry_project/test/security/VaultPoC.t.sol`" in readme
    assert "`CAN-01` High: Permissionless initialization lets the first caller seize bootstrap." in readme
    assert "execution_summary.md" not in readme


def test_render_package_readme_prefers_foundry_total_summary_when_present(tmp_path):
    package_dir = tmp_path / "routers-reports"
    workspace_dir = package_dir / "artifacts" / "workspace" / "foundry_project"
    workspace_dir.mkdir(parents=True)
    manifest = ContractAuditManifest(
        target=TargetConfig(
            source=LocalSourceConfig(kind="local", local_path=tmp_path / "source"),
            report=TargetReportConfig(project_name="Routers", audit_scope="src/routers"),
        ),
        run=RunConfig(artifacts_dir=str(package_dir / "artifacts"), parallel_shards=6),
        policy=PolicyConfig(),
    )
    report_manifest = ReportManifest(
        project_name="Routers",
        audit_scope="src/routers",
        source_mode="local snapshot",
        source_identifier="snapshot:test",
    )
    findings = [
        _finding(
            "CAN-01",
            severity="high",
            validation_status="poc_confirmed",
            component_file="src/routers/RouterBase.sol",
            poc_status="passed",
            poc_test_path="test/security/RouterPoC.t.sol",
        )
    ]
    verification = {
        "workspace": str(workspace_dir),
        "build": {"status": "passed", "command": "forge build", "exit_code": 0},
        "test": {"status": "passed", "command": "forge test -vvv", "exit_code": 0},
        "stdout": (
            "Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 1.67ms (454.05us CPU time)\n"
            "Ran 4 test suites in 9.67ms (6.91ms CPU time): 11 tests passed, 0 failed, 0 skipped (11 total tests)\n"
        ),
        "stderr": "",
    }

    readme = render_package_readme(
        package_dir,
        manifest,
        report_manifest,
        findings,
        verification=verification,
    )

    assert "- PoC suite: `11 passed, 0 failed, 0 skipped`" in readme


def test_write_package_readme_removes_legacy_execution_summary(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (package_dir / "execution_summary.md").write_text("legacy", encoding="utf-8")
    manifest = ContractAuditManifest(
        target=TargetConfig(
            source=LocalSourceConfig(kind="local", local_path=source_dir),
            report=TargetReportConfig(project_name="TokenVault", audit_scope="contracts"),
        ),
        run=RunConfig(artifacts_dir=str(package_dir / "artifacts"), parallel_shards=6),
        policy=PolicyConfig(),
    )
    report_manifest = ReportManifest(
        project_name="TokenVault",
        audit_scope="contracts",
        source_mode="local snapshot",
        source_identifier="snapshot:deadbeef",
    )
    findings = [
        _finding(
            "CAN-01",
            severity="high",
            validation_status="poc_confirmed",
            component_file="contracts/Vault.sol",
            poc_status="passed",
            poc_test_path="test/security/VaultPoC.t.sol",
        )
    ]

    write_package_readme(package_dir, manifest, report_manifest, findings, verification=None)

    assert (package_dir / "README.md").exists()
    assert not (package_dir / "execution_summary.md").exists()


def test_render_package_readme_for_github_source_omits_execution_time_when_not_provided(tmp_path):
    package_dir = tmp_path / "protocol-reports"
    package_dir.mkdir()
    manifest = ContractAuditManifest(
        target=TargetConfig(
            source=GitHubSourceConfig(
                kind="github",
                repo_url="https://github.com/example/protocol",
                commit="0123456789abcdef0123456789abcdef01234567",
            ),
            report=TargetReportConfig(project_name="Protocol", audit_scope="src/protocol"),
        ),
        run=RunConfig(artifacts_dir=str(package_dir / "artifacts"), parallel_shards=6),
        policy=PolicyConfig(),
    )
    report_manifest = ReportManifest(
        project_name="Protocol",
        audit_scope="src/protocol",
        source_mode="github repo",
        source_identifier="github:example/protocol@0123456",
    )

    readme = render_package_readme(package_dir, manifest, report_manifest, [])

    assert "- Upstream repository: `https://github.com/example/protocol`" in readme
    assert "- Fetched revision: `0123456789abcdef0123456789abcdef01234567`" in readme
    assert "Execution Time" not in readme


def test_infer_package_execution_time_uses_current_run_file(tmp_path):
    package_dir = tmp_path / "cap-vault-reports"
    runs_dir = package_dir / "runs"
    run_dir = runs_dir / "run-123"
    run_dir.mkdir(parents=True)
    (runs_dir / "current-run-id").write_text("run-123\n", encoding="utf-8")
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "pipeline": {"name": "contract-audit-example"},
                "started_at": "2026-04-08T12:00:00+00:00",
                "finished_at": "2026-04-08T20:20:00+00:00",
            }
        ),
        encoding="utf-8",
    )

    execution_time = infer_package_execution_time(package_dir)

    assert execution_time == "8h 20m"


def test_infer_package_execution_time_returns_none_when_package_has_multiple_runs(tmp_path):
    package_dir = tmp_path / "cap-vault-reports"
    runs_dir = package_dir / "runs"
    first_run_dir = runs_dir / "run-123"
    second_run_dir = runs_dir / "run-456"
    first_run_dir.mkdir(parents=True)
    second_run_dir.mkdir(parents=True)
    (runs_dir / "current-run-id").write_text("run-123\n", encoding="utf-8")
    for run_dir in (first_run_dir, second_run_dir):
        (run_dir / "run.json").write_text(
            json.dumps(
                {
                    "pipeline": {"name": "contract-audit-example"},
                    "started_at": "2026-04-08T12:00:00+00:00",
                    "finished_at": "2026-04-08T20:20:00+00:00",
                }
            ),
            encoding="utf-8",
        )

    execution_time = infer_package_execution_time(package_dir)

    assert execution_time is None
