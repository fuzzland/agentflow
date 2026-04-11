from __future__ import annotations

import os
import sys
from pathlib import Path
from textwrap import dedent

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentflow import Graph, codex, python_node
from agentflow.audit.intake import load_manifest
from agentflow.audit.pipeline_builder import (
    AUDIT_MANIFEST_ENV,
    CODEX_BYPASS_EXTRA_ARGS,
    _AUDIT_CODEX_RETRIES,
    _AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
    _deployment_context_prompt,
    _manifest_runtime_python_node,
)


DEFAULT_SAVED_EVIDENCE_GATE_RUN_JSON = (
    "/data/agentenv/agentflow-audit-reports/dolomite-exchange/routers-reports/"
    "runs/0f665f716bbd489884be1d09bdd26064/run.json"
)


manifest_path = os.environ.get(AUDIT_MANIFEST_ENV)
if not manifest_path:
    sys.stderr.write(
        f"Set {AUDIT_MANIFEST_ENV} to the manifest JSON path before running this example.\n"
    )
    raise SystemExit(1)

resolved_manifest_path = Path(manifest_path).expanduser()
if not resolved_manifest_path.is_absolute():
    resolved_manifest_path = (REPO_ROOT / resolved_manifest_path).resolve()
else:
    resolved_manifest_path = resolved_manifest_path.resolve()

saved_evidence_gate_run_json = os.environ.get(
    "AGENTFLOW_SAVED_EVIDENCE_GATE_RUN_JSON",
    DEFAULT_SAVED_EVIDENCE_GATE_RUN_JSON,
)
manifest = load_manifest(resolved_manifest_path)
poc_workspace_dir = Path(manifest.run.artifacts_dir) / "workspace" / "foundry_project"
deployment_context_prompt = _deployment_context_prompt(manifest)


def _apply_saved_round_code(expect_status: str) -> str:
    return _manifest_runtime_python_node(
        dedent(
            f"""
            import json
            from pathlib import Path

            from agentflow.audit.discovery import advance_discovery_state, findings_from_text
            from agentflow.audit.intake import load_manifest

            manifest = load_manifest(resolved_manifest_path)
            state_path = Path(manifest.run.artifacts_dir) / "workspace" / "discovery_state.json"
            run = json.loads(Path({saved_evidence_gate_run_json!r}).read_text(encoding="utf-8"))
            output = run["nodes"]["evidence_gate"].get("output")
            if not isinstance(output, str) or not output.strip():
                raise SystemExit("missing saved evidence_gate output")
            findings = findings_from_text(output)
            state, decision = advance_discovery_state(
                state_path,
                findings,
                no_progress_patience=1,
            )
            print(
                json.dumps(
                    {{
                        "status": decision.status,
                        "round": state.round,
                        "consecutive_no_progress": state.consecutive_no_progress,
                        "new_fingerprints": decision.new_fingerprints,
                        "validation_upgrades": decision.validation_upgrades,
                        "accepted_findings": len(state.accepted_findings),
                        "rejected_findings": len(state.rejected_findings),
                    }},
                    indent=2,
                )
            )
            if decision.status != {expect_status!r}:
                raise SystemExit(f"expected decision status {expect_status}, got {{decision.status}}")
            """
        ).strip()
    )


with Graph(
    "contract-audit-continue-from-saved-evidence-gate",
    working_dir=str(REPO_ROOT),
    concurrency=1,
) as graph:
    intake_target = python_node(
        task_id="intake_target",
        code=_manifest_runtime_python_node(
            """
            from agentflow.audit.intake import emit_normalized_manifest

            emit_normalized_manifest(resolved_manifest_path)
            """
        ),
    )
    materialize_target = python_node(
        task_id="materialize_target",
        code=_manifest_runtime_python_node(
            """
            import json
            from pathlib import Path

            from agentflow.audit.intake import load_manifest
            from agentflow.audit.materialize import materialize_source

            manifest = load_manifest(resolved_manifest_path)
            materialized = materialize_source(manifest, Path(manifest.run.artifacts_dir))
            print(
                json.dumps(
                    {
                        "snapshot_dir": str(materialized.snapshot_dir),
                        "source_identifier": materialized.source_identifier,
                        "source_mode": materialized.source_mode,
                        "source_inventory": materialized.source_inventory,
                    },
                    indent=2,
                )
            )
            """
        ),
    )
    prepare_foundry_workspace = python_node(
        task_id="prepare_foundry_workspace",
        code=_manifest_runtime_python_node(
            """
            import json
            from pathlib import Path

            from agentflow.audit.foundry import prepare_foundry_workspace
            from agentflow.audit.intake import load_manifest
            from agentflow.audit.materialize import materialize_source

            manifest = load_manifest(resolved_manifest_path)
            materialized = materialize_source(manifest, Path(manifest.run.artifacts_dir))
            prepared = prepare_foundry_workspace(materialized, Path(manifest.run.artifacts_dir))
            print(
                json.dumps(
                    {
                        "workspace_dir": str(prepared.workspace_dir),
                        "source_snapshot_dir": str(prepared.source_snapshot_dir),
                        "foundry_toml_path": str(prepared.foundry_toml_path),
                        "remappings_path": (
                            str(prepared.remappings_path) if prepared.remappings_path else None
                        ),
                    },
                    indent=2,
                )
            )
            """
        ),
    )
    apply_saved_round_1 = python_node(
        task_id="apply_saved_round_1",
        code=_apply_saved_round_code("CONTINUE"),
    )
    apply_saved_round_2 = python_node(
        task_id="apply_saved_round_2",
        code=_apply_saved_round_code("STOP"),
    )
    discovery_finalize = python_node(
        task_id="discovery_finalize",
        code=_manifest_runtime_python_node(
            """
            import json
            from pathlib import Path

            from agentflow.audit.discovery import customer_visible_findings, load_discovery_state
            from agentflow.audit.intake import load_manifest

            manifest = load_manifest(resolved_manifest_path)
            state_path = Path(manifest.run.artifacts_dir) / "workspace" / "discovery_state.json"
            state = load_discovery_state(state_path)
            print(
                json.dumps(
                    [finding.model_dump(mode="json") for finding in customer_visible_findings(state)],
                    indent=2,
                )
            )
            """
        ),
    )
    poc_author = codex(
        task_id="poc_author",
        prompt=(
            "Author Foundry PoC tests for every non-rejected validated finding.\n"
            f"Legacy policy field: max_poc_candidates={manifest.policy.max_poc_candidates} (ignored in this pipeline version; every shipped finding must have a PoC).\n"
            "Keep changes limited to test assets and the minimum harness support needed.\n"
            "After writing files, return only a JSON array with this shape:\n"
            '[{"finding_id":"CAN-01","test_path":"test/security/VaultPoC.t.sol","test_name":"test_can_01_initialize_takeover","reason":null}]\n'
            "Include every non-rejected finding exactly once. If you cannot produce a PoC for a finding, keep it in the array with null test fields and a short reason.\n\n"
            "{{ nodes.discovery_finalize.output }}"
        ),
        tools="read_write",
        extra_args=CODEX_BYPASS_EXTRA_ARGS,
        retries=_AUDIT_CODEX_RETRIES,
        retry_backoff_seconds=_AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
        target={"kind": "local", "cwd": str(poc_workspace_dir)},
        skills=[
            "foundry-solidity::default",
            "property-based-testing::default",
        ],
    )
    poc_verify = python_node(
        task_id="poc_verify",
        code=dedent(
            """
            import json
            import subprocess
            from pathlib import Path

            from agentflow.audit.reporting import extract_json_document

            prepared_payload = {{ nodes.prepare_foundry_workspace.output | tojson }}
            prepared = (
                json.loads(prepared_payload)
                if isinstance(prepared_payload, str)
                else prepared_payload
            )
            findings_payload = {{ nodes.discovery_finalize.output | tojson }}
            findings = (
                extract_json_document(findings_payload)
                if isinstance(findings_payload, str)
                else findings_payload
            )
            authored_payload = {{ nodes.poc_author.output | tojson }}
            authored = (
                extract_json_document(authored_payload)
                if isinstance(authored_payload, str)
                else authored_payload
            )
            workspace_dir = Path(prepared["workspace_dir"])
            authored = authored if isinstance(authored, list) else []
            findings = findings if isinstance(findings, list) else []

            expected_finding_ids = [
                item["id"]
                for item in findings
                if isinstance(item, dict) and item.get("validation_status") != "rejected"
            ]
            authored_by_id = {
                entry.get("finding_id"): entry
                for entry in authored
                if isinstance(entry, dict) and entry.get("finding_id")
            }
            missing_mappings = [
                finding_id for finding_id in expected_finding_ids if finding_id not in authored_by_id
            ]
            missing_test_paths = [
                finding_id
                for finding_id in expected_finding_ids
                if not authored_by_id.get(finding_id, {}).get("test_path")
            ]
            nonexistent_test_paths = []
            for finding_id, entry in authored_by_id.items():
                test_path = entry.get("test_path")
                if not test_path:
                    continue
                if not (workspace_dir / test_path).exists():
                    nonexistent_test_paths.append({"finding_id": finding_id, "test_path": test_path})

            build = subprocess.run(["forge", "build"], cwd=workspace_dir, capture_output=True, text=True)
            test = subprocess.run(["forge", "test", "-vvv"], cwd=workspace_dir, capture_output=True, text=True)
            print(
                json.dumps(
                    {
                        "workspace": str(workspace_dir),
                        "expected_finding_ids": expected_finding_ids,
                        "authored_tests": authored,
                        "missing_mappings": missing_mappings,
                        "missing_test_paths": missing_test_paths,
                        "nonexistent_test_paths": nonexistent_test_paths,
                        "build": {
                            "status": "passed" if build.returncode == 0 else "failed",
                            "command": "forge build",
                            "exit_code": build.returncode,
                        },
                        "test": {
                            "status": "passed" if test.returncode == 0 else "failed",
                            "command": "forge test -vvv",
                            "exit_code": test.returncode,
                        },
                        "stdout": test.stdout,
                        "stderr": test.stderr,
                    },
                    indent=2,
                )
            )
            """
        ).strip(),
    )
    final_adjudication = codex(
        task_id="final_adjudication",
        prompt=(
            "Combine the validated findings with the PoC authoring and verification results and return the "
            "draft canonical findings JSON for reporting.\n"
            "Hard requirement: only findings with a corresponding Foundry PoC test may survive.\n"
            "Do not return any `source_confirmed` findings.\n"
            "Keep a finding only if all of the following are true:\n"
            "1. It appears in the validated findings set and is not rejected.\n"
            "2. `poc_author` returned a non-null `test_path` for it.\n"
            "3. `poc_verify` reports a successful `forge build`, a successful `forge test -vvv`, and no missing/nonexistent test mappings.\n"
            "For every kept finding, set `validation_status` to `poc_confirmed`, `poc.status` to `passed`, and `poc.test_path` to the authored test path.\n"
            "Reject or drop everything else.\n"
            "Return only a JSON array of final `FindingRecord` objects.\n\n"
            "Validated findings:\n{{ nodes.discovery_finalize.output }}\n\n"
            "PoC authoring map:\n{{ nodes.poc_author.output }}\n\n"
            "PoC verification:\n{{ nodes.poc_verify.output }}"
        ),
        tools="read_only",
        extra_args=CODEX_BYPASS_EXTRA_ARGS,
        retries=_AUDIT_CODEX_RETRIES,
        retry_backoff_seconds=_AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
    )
    report_build = python_node(
        task_id="report_build",
        code=_manifest_runtime_python_node(
            """
            import json
            from pathlib import Path

            from agentflow.audit.intake import build_report_manifest, load_manifest
            from agentflow.audit.models import FindingRecord
            from agentflow.audit.reporting import extract_json_document, write_report_bundle

            manifest = load_manifest(resolved_manifest_path)
            materialized_payload = {{ nodes.materialize_target.output | tojson }}
            materialized = (
                json.loads(materialized_payload)
                if isinstance(materialized_payload, str)
                else materialized_payload
            )
            final_adjudication_payload = {{ nodes.final_adjudication.output | tojson }}
            final_adjudication = (
                extract_json_document(final_adjudication_payload)
                if isinstance(final_adjudication_payload, str)
                else final_adjudication_payload
            )
            if not isinstance(final_adjudication, list):
                raise ValueError("final_adjudication output must decode to a JSON list")
            findings = [
                FindingRecord.model_validate(item)
                for item in final_adjudication
            ]
            report_manifest = build_report_manifest(
                manifest,
                source_identifier=materialized["source_identifier"],
            )
            report_dir = Path(manifest.run.artifacts_dir) / "report"
            write_report_bundle(report_dir, report_manifest, findings)
            print((report_dir / "AUDIT_REPORT.md").read_text(encoding="utf-8"))
            """
        ),
    )
    report_review = codex(
        task_id="report_review",
        prompt=(
            "Review this draft audit report as a delivery artifact and return only a revised JSON array of final findings.\n"
            "Do not add new findings.\n"
            "Only keep findings that remain PoC-confirmed and have a non-null `poc.test_path`.\n"
            "Merge findings that are materially the same root cause or exploit path.\n"
            "Reject only findings that are absolutely impossible in the real business scenario implied by the codebase, manifest, and deployment context.\n"
            "If a finding is merely unlikely or lacks extra business context, keep it.\n"
            "Return only final `FindingRecord` JSON.\n\n"
            f"{deployment_context_prompt}\n"
            "Draft report:\n{{ nodes.report_build.output }}\n\n"
            "Draft findings JSON:\n{{ nodes.final_adjudication.output }}\n\n"
            "PoC verification:\n{{ nodes.poc_verify.output }}"
        ),
        tools="read_only",
        extra_args=CODEX_BYPASS_EXTRA_ARGS,
        retries=_AUDIT_CODEX_RETRIES,
        retry_backoff_seconds=_AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
        target={"kind": "local", "cwd": str(poc_workspace_dir)},
    )
    report_finalize_build = python_node(
        task_id="report_finalize_build",
        code=_manifest_runtime_python_node(
            """
            import json
            from pathlib import Path

            from agentflow.audit.intake import build_report_manifest, load_manifest
            from agentflow.audit.models import FindingRecord
            from agentflow.audit.reporting import extract_json_document, write_report_bundle

            manifest = load_manifest(resolved_manifest_path)
            materialized_payload = {{ nodes.materialize_target.output | tojson }}
            materialized = (
                json.loads(materialized_payload)
                if isinstance(materialized_payload, str)
                else materialized_payload
            )
            report_review_payload = {{ nodes.report_review.output | tojson }}
            report_review = (
                extract_json_document(report_review_payload)
                if isinstance(report_review_payload, str)
                else report_review_payload
            )
            if not isinstance(report_review, list):
                raise ValueError("report_review output must decode to a JSON list")
            findings = [
                FindingRecord.model_validate(item)
                for item in report_review
            ]
            report_manifest = build_report_manifest(
                manifest,
                source_identifier=materialized["source_identifier"],
            )
            report_dir = Path(manifest.run.artifacts_dir) / "report"
            write_report_bundle(report_dir, report_manifest, findings)
            print((report_dir / "AUDIT_REPORT.md").read_text(encoding="utf-8"))
            """
        ),
    )
    package_readme_build = python_node(
        task_id="package_readme_build",
        code=_manifest_runtime_python_node(
            """
            import json
            from pathlib import Path

            from agentflow.audit.intake import load_manifest
            from agentflow.audit.models import FindingRecord, ReportManifest
            from agentflow.audit.reporting import (
                extract_json_document,
                infer_package_execution_time,
                write_package_readme,
            )

            manifest = load_manifest(resolved_manifest_path)
            report_dir = Path(manifest.run.artifacts_dir) / "report"
            package_dir = Path(manifest.run.artifacts_dir).parent
            report_manifest = ReportManifest.model_validate_json(
                (report_dir / "report_manifest.json").read_text(encoding="utf-8")
            )
            findings = [
                FindingRecord.model_validate(item)
                for item in json.loads((report_dir / "findings.json").read_text(encoding="utf-8"))
            ]
            poc_verify_payload = {{ nodes.poc_verify.output | tojson }}
            poc_verify = (
                extract_json_document(poc_verify_payload)
                if isinstance(poc_verify_payload, str)
                else poc_verify_payload
            )
            if not isinstance(poc_verify, dict):
                raise ValueError("poc_verify output must decode to a JSON object")
            execution_time = infer_package_execution_time(package_dir)
            write_package_readme(
                package_dir,
                manifest,
                report_manifest,
                findings,
                verification=poc_verify,
                execution_time=execution_time,
            )
            print((package_dir / "README.md").read_text(encoding="utf-8"))
            """
        ),
    )
    publish_artifacts = python_node(
        task_id="publish_artifacts",
        code=dedent(
            """
            import json
            from pathlib import Path

            report_dir = Path("report")
            print(
                json.dumps(
                    {
                        "artifacts_root": "run.artifacts_dir",
                        "readme": "README.md",
                        "report_dir": report_dir.as_posix(),
                        "report": (report_dir / "AUDIT_REPORT.md").as_posix(),
                        "findings": (report_dir / "findings.json").as_posix(),
                        "summary": (report_dir / "audit_summary.json").as_posix(),
                    },
                    indent=2,
                )
            )
            """
        ).strip(),
    )

    intake_target >> materialize_target >> prepare_foundry_workspace >> apply_saved_round_1 >> apply_saved_round_2 >> discovery_finalize
    discovery_finalize >> poc_author >> poc_verify >> final_adjudication >> report_build >> report_review >> report_finalize_build >> package_readme_build >> publish_artifacts


print(graph.to_json())
