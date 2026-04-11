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
from agentflow.audit.pipeline_builder import AUDIT_MANIFEST_ENV, _manifest_runtime_python_node


REVIEWED_FINDINGS_ENV = "AGENTFLOW_CONTRACT_AUDIT_REVIEWED_FINDINGS_PATH"
SAVED_POC_VERIFY_RUN_ID_ENV = "AGENTFLOW_CONTRACT_AUDIT_POC_VERIFY_RUN_ID"


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
default_reviewed_findings_path = Path(manifest.run.artifacts_dir) / "workspace" / "report_review_final.json"
reviewed_findings_path = Path(
    os.environ.get(REVIEWED_FINDINGS_ENV, str(default_reviewed_findings_path))
).expanduser()
if not reviewed_findings_path.is_absolute():
    reviewed_findings_path = (REPO_ROOT / reviewed_findings_path).resolve()
else:
    reviewed_findings_path = reviewed_findings_path.resolve()


def _load_saved_node_output(node_id: str) -> str:
    return _manifest_runtime_python_node(
        dedent(
            f"""
            import json
            import os
            from pathlib import Path

            from agentflow.audit.intake import load_manifest

            manifest = load_manifest(resolved_manifest_path)
            package_dir = Path(manifest.run.artifacts_dir).parent
            runs_dir = package_dir / "runs"
            explicit_run_id = os.environ.get({SAVED_POC_VERIFY_RUN_ID_ENV!r}, "").strip()

            candidate_paths: list[Path] = []
            if explicit_run_id:
                candidate_paths.append(runs_dir / explicit_run_id / "run.json")
            else:
                current_run_id_path = runs_dir / "current-run-id"
                if current_run_id_path.exists():
                    current_run_id = current_run_id_path.read_text(encoding="utf-8").strip()
                    if current_run_id:
                        candidate_paths.append(runs_dir / current_run_id / "run.json")
                candidate_paths.extend(sorted(runs_dir.glob("*/run.json"), reverse=True))

            seen: set[Path] = set()
            for run_path in candidate_paths:
                if run_path in seen or not run_path.exists():
                    continue
                seen.add(run_path)
                run = json.loads(run_path.read_text(encoding="utf-8"))
                node = run.get("nodes", {{}}).get({node_id!r})
                if not isinstance(node, dict):
                    continue
                output = node.get("output")
                if output is None:
                    continue
                if isinstance(output, str) and not output.strip():
                    continue
                if isinstance(output, str):
                    print(output)
                else:
                    print(json.dumps(output, indent=2))
                raise SystemExit(0)

            raise SystemExit("no saved output found for node {node_id}")
            """
        ).strip()
    )


with Graph(
    "contract-audit-finalize-from-saved-review",
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
    load_saved_report_review = python_node(
        task_id="load_saved_report_review",
        code=_manifest_runtime_python_node(
            dedent(
                f"""
                from pathlib import Path

                reviewed_findings_path = Path({str(reviewed_findings_path)!r})
                if not reviewed_findings_path.exists():
                    raise SystemExit(f"reviewed findings file not found: {{reviewed_findings_path}}")
                print(reviewed_findings_path.read_text(encoding="utf-8"))
                """
            ).strip()
        ),
    )
    load_saved_poc_verify = python_node(
        task_id="load_saved_poc_verify",
        code=_load_saved_node_output("poc_verify"),
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
            report_review_payload = {{ nodes.load_saved_report_review.output | tojson }}
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
            poc_verify_payload = {{ nodes.load_saved_poc_verify.output | tojson }}
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
                        "report_dir": ("artifacts" / report_dir).as_posix(),
                        "findings": ("artifacts" / report_dir / "findings.json").as_posix(),
                        "summary": ("artifacts" / report_dir / "audit_summary.json").as_posix(),
                    },
                    indent=2,
                )
            )
            """
        ),
    )

    intake_target >> materialize_target
    materialize_target >> load_saved_report_review >> report_finalize_build
    materialize_target >> load_saved_poc_verify
    [report_finalize_build, load_saved_poc_verify] >> package_readme_build
    package_readme_build >> publish_artifacts


print(graph.to_json())
