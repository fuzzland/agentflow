from __future__ import annotations

import os
import sys
from pathlib import Path
from textwrap import dedent

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentflow import Graph, claude, codex, python_node
from agentflow.audit.intake import load_manifest
from agentflow.audit.pipeline_builder import (
    AUDIT_MANIFEST_ENV,
    CODEX_BYPASS_EXTRA_ARGS,
    _AUDIT_CODEX_RETRIES,
    _AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
    _deployment_context_prompt,
    _manifest_runtime_python_node,
)


DEFAULT_SAVED_RUN_ID = "509a57ed3e6a4936bc2875c540f88c68"
SAVED_RUN_ID_ENV = "AGENTFLOW_CONTRACT_AUDIT_CONTINUE_FROM_RUN_ID"


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

saved_run_id = os.environ.get(SAVED_RUN_ID_ENV, DEFAULT_SAVED_RUN_ID).strip() or DEFAULT_SAVED_RUN_ID
saved_run_json = resolved_manifest_path.parent / "runs" / saved_run_id / "run.json"
manifest = load_manifest(resolved_manifest_path)
poc_workspace_dir = Path(manifest.run.artifacts_dir) / "workspace" / "foundry_project"
deployment_context_prompt = _deployment_context_prompt(manifest)


def _load_saved_node_output(node_id: str) -> str:
    return _manifest_runtime_python_node(
        dedent(
            f"""
            import json
            from pathlib import Path

            run_path = Path({str(saved_run_json)!r})
            if not run_path.exists():
                raise SystemExit(f"saved run not found: {{run_path}}")

            run = json.loads(run_path.read_text(encoding="utf-8"))
            node = run.get("nodes", {{}}).get({node_id!r})
            if not isinstance(node, dict):
                raise SystemExit(f"missing saved node: {node_id}")

            output = node.get("output")
            if output is None:
                raise SystemExit(f"saved node {node_id} has no output")

            if isinstance(output, str):
                print(output)
            else:
                print(json.dumps(output, indent=2))
            """
        ).strip()
    )


with Graph(
    "contract-audit-continue-from-saved-final-adjudication",
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
    load_saved_poc_verify = python_node(
        task_id="load_saved_poc_verify",
        code=_load_saved_node_output("poc_verify"),
    )
    load_saved_final_adjudication = python_node(
        task_id="load_saved_final_adjudication",
        code=_load_saved_node_output("final_adjudication"),
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
            final_adjudication_payload = {{ nodes.load_saved_final_adjudication.output | tojson }}
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
    report_review = claude(
        task_id="report_review",
        prompt=(
            "Review this draft audit report as a delivery QA pass and return only a revised JSON array of final findings.\n"
            "Do not add, remove, merge, split, reject, or re-scope findings.\n"
            "Do not change finding count, `dedup_fingerprint`, `severity`, `validation_status`, or `poc.test_path`.\n"
            "Keep every finding PoC-confirmed with a non-null `poc.test_path`.\n"
            "Only improve wording, ordering, report-safe phrasing, and citation clarity.\n"
            "Return only final `FindingRecord` JSON.\n\n"
            f"{deployment_context_prompt}\n"
            "Draft report:\n{{ nodes.report_build.output }}\n\n"
            "Draft findings JSON:\n{{ nodes.load_saved_final_adjudication.output }}\n\n"
            "PoC verification:\n{{ nodes.load_saved_poc_verify.output }}"
        ),
        tools="read_only",
        timeout_seconds=900,
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
            poc_verify_payload = {{ nodes.load_saved_poc_verify.output | tojson }}
            poc_verify = (
                extract_json_document(poc_verify_payload)
                if isinstance(poc_verify_payload, str)
                else poc_verify_payload
            )
            if not isinstance(poc_verify, dict):
                raise ValueError("saved poc_verify output must decode to a JSON object")
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
    [materialize_target, intake_target] >> load_saved_poc_verify
    [materialize_target, intake_target] >> load_saved_final_adjudication
    [materialize_target, load_saved_final_adjudication] >> report_build
    [report_build, load_saved_final_adjudication, load_saved_poc_verify] >> report_review
    [materialize_target, report_review] >> report_finalize_build
    [report_finalize_build, load_saved_poc_verify] >> package_readme_build
    package_readme_build >> publish_artifacts


print(graph.to_json())
