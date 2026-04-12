from __future__ import annotations

import os
import sys
from pathlib import Path
from textwrap import dedent

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentflow import Graph, python_node
from agentflow.audit.intake import load_manifest
from agentflow.audit.pipeline_builder import (
    AUDIT_MANIFEST_ENV,
    _CURATION_STATE_FILENAME,
    _deployment_context_prompt,
    _manifest_runtime_python_node,
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

manifest = load_manifest(resolved_manifest_path)
poc_workspace_dir = Path(manifest.run.artifacts_dir) / "workspace" / "foundry_project"
deployment_context_prompt = _deployment_context_prompt(manifest)


with Graph(
    "contract-audit-continue-from-existing-pocs",
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

            from agentflow.audit.intake import load_manifest

            manifest = load_manifest(resolved_manifest_path)
            workspace_dir = Path(manifest.run.artifacts_dir) / "workspace" / "foundry_project"
            if not workspace_dir.exists():
                raise SystemExit(f"existing foundry workspace not found: {workspace_dir}")
            foundry_toml_path = workspace_dir / "foundry.toml"
            remappings_path = workspace_dir / "remappings.txt"
            print(
                json.dumps(
                    {
                        "workspace_dir": str(workspace_dir),
                        "source_snapshot_dir": None,
                        "foundry_toml_path": str(foundry_toml_path),
                        "remappings_path": str(remappings_path) if remappings_path.exists() else None,
                    },
                    indent=2,
                )
            )
            """
        ),
    )
    load_curated_findings = python_node(
        task_id="load_curated_findings",
        code=_manifest_runtime_python_node(
            f"""
            import json
            from pathlib import Path

            from agentflow.audit.curation import load_curation_state
            from agentflow.audit.intake import load_manifest

            manifest = load_manifest(resolved_manifest_path)
            state_path = Path(manifest.run.artifacts_dir) / "workspace" / "{_CURATION_STATE_FILENAME}"
            state = load_curation_state(state_path)
            print(
                json.dumps(
                    [finding.model_dump(mode="json") for finding in state.curated_findings],
                    separators=(",", ":"),
                )
            )
            """
        ),
    )
    derive_poc_mappings = python_node(
        task_id="derive_poc_mappings",
        code=dedent(
            """
            import json
            from pathlib import Path

            from agentflow.audit.models import FindingRecord
            from agentflow.audit.poc_mapping import derive_poc_mappings
            from agentflow.audit.reporting import extract_json_document

            prepared_payload = {{ nodes.prepare_foundry_workspace.output | tojson }}
            prepared = (
                json.loads(prepared_payload)
                if isinstance(prepared_payload, str)
                else prepared_payload
            )
            findings_payload = {{ nodes.load_curated_findings.output | tojson }}
            findings = (
                extract_json_document(findings_payload)
                if isinstance(findings_payload, str)
                else findings_payload
            )
            if not isinstance(findings, list):
                raise ValueError("load_curated_findings output must decode to a JSON list")
            records = [FindingRecord.model_validate(item) for item in findings]
            workspace_dir = Path(prepared["workspace_dir"])
            print(json.dumps(derive_poc_mappings(records, workspace_dir), indent=2))
            """
        ).strip(),
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
            findings_payload = {{ nodes.load_curated_findings.output | tojson }}
            findings = (
                extract_json_document(findings_payload)
                if isinstance(findings_payload, str)
                else findings_payload
            )
            authored_payload = {{ nodes.derive_poc_mappings.output | tojson }}
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
    final_adjudication = python_node(
        task_id="final_adjudication",
        code=dedent(
            """
            import json

            from agentflow.audit.models import FindingRecord
            from agentflow.audit.reporting import extract_json_document

            findings_payload = {{ nodes.load_curated_findings.output | tojson }}
            findings = (
                extract_json_document(findings_payload)
                if isinstance(findings_payload, str)
                else findings_payload
            )
            authored_payload = {{ nodes.derive_poc_mappings.output | tojson }}
            authored = (
                extract_json_document(authored_payload)
                if isinstance(authored_payload, str)
                else authored_payload
            )
            verification_payload = {{ nodes.poc_verify.output | tojson }}
            verification = (
                extract_json_document(verification_payload)
                if isinstance(verification_payload, str)
                else verification_payload
            )

            if not isinstance(findings, list):
                raise ValueError("load_curated_findings output must decode to a JSON list")
            if not isinstance(authored, list):
                raise ValueError("derive_poc_mappings output must decode to a JSON list")
            if not isinstance(verification, dict):
                raise ValueError("poc_verify output must decode to a JSON object")

            build_status = (
                verification.get("build", {}).get("status")
                if isinstance(verification.get("build"), dict)
                else None
            )
            test_status = (
                verification.get("test", {}).get("status")
                if isinstance(verification.get("test"), dict)
                else None
            )
            if build_status != "passed" or test_status != "passed":
                raise ValueError("PoC verification must pass forge build and forge test before adjudication")

            missing_test_paths = set(verification.get("missing_test_paths") or [])
            nonexistent_test_paths = {
                item.get("finding_id")
                for item in (verification.get("nonexistent_test_paths") or [])
                if isinstance(item, dict) and item.get("finding_id")
            }
            authored_by_id = {
                entry.get("finding_id"): entry
                for entry in authored
                if isinstance(entry, dict) and entry.get("finding_id")
            }

            final_findings = []
            for item in findings:
                finding = FindingRecord.model_validate(item)
                if finding.validation_status == "rejected":
                    continue
                mapping = authored_by_id.get(finding.id)
                if not isinstance(mapping, dict):
                    continue
                test_path = mapping.get("test_path")
                if not test_path or finding.id in missing_test_paths:
                    continue
                if finding.id in nonexistent_test_paths:
                    continue
                final_findings.append(
                    finding.model_copy(
                        update={
                            "status": "final",
                            "validation_status": "poc_confirmed",
                            "poc": finding.poc.model_copy(
                                update={"eligible": True, "status": "passed", "test_path": test_path}
                            ),
                        }
                    ).model_dump(mode="json")
                )

            print(json.dumps(final_findings, indent=2))
            """
        ).strip(),
    )
    report_build = python_node(
        task_id="report_build",
        code=_manifest_runtime_python_node(
            """
            import json
            from pathlib import Path

            from agentflow.audit.intake import build_report_manifest, load_manifest
            from agentflow.audit.models import FindingRecord
            from agentflow.audit.reporting import (
                extract_json_document,
                root_audit_report_path,
                write_report_bundle,
            )

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
            print(root_audit_report_path(report_dir).read_text(encoding="utf-8"))
            """
        ),
    )
    report_review = python_node(
        task_id="report_review",
        code=dedent(
            """
            review_payload = {{ nodes.final_adjudication.output | tojson }}
            if isinstance(review_payload, str):
                print(review_payload)
            else:
                import json
                print(json.dumps(review_payload, indent=2))
            """
        ).strip(),
    )
    report_finalize_build = python_node(
        task_id="report_finalize_build",
        code=_manifest_runtime_python_node(
            """
            import json
            from pathlib import Path

            from agentflow.audit.intake import build_report_manifest, load_manifest
            from agentflow.audit.models import FindingRecord
            from agentflow.audit.reporting import (
                extract_json_document,
                root_audit_report_path,
                write_report_bundle,
            )

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
            print(root_audit_report_path(report_dir).read_text(encoding="utf-8"))
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
                        "package_root": ".",
                        "artifacts_root": "artifacts",
                        "readme": "README.md",
                        "audit_report": "AUDIT_REPORT.md",
                        "report_dir": (Path("artifacts") / report_dir).as_posix(),
                        "findings": (Path("artifacts") / report_dir / "findings.json").as_posix(),
                        "summary": (Path("artifacts") / report_dir / "audit_summary.json").as_posix(),
                    },
                    indent=2,
                )
            )
            """
        ).strip(),
    )

    intake_target >> materialize_target >> prepare_foundry_workspace >> load_curated_findings >> derive_poc_mappings >> poc_verify >> final_adjudication
    final_adjudication >> report_build >> report_review >> report_finalize_build >> package_readme_build >> publish_artifacts


print(graph.to_json())
