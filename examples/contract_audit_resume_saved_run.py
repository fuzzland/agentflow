from __future__ import annotations

import asyncio
import os
from pathlib import Path
from textwrap import dedent

from agentflow import Graph, codex, python_node
from agentflow.audit.intake import load_manifest
from agentflow.audit.pipeline_builder import (
    AUDIT_MANIFEST_ENV,
    AUDIT_TRACKS,
    CODEX_BYPASS_EXTRA_ARGS,
    REPO_ROOT,
    _AUDIT_CODEX_RETRIES,
    _AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
    _DISCOVERY_NO_PROGRESS_PATIENCE,
    _DISCOVERY_STATE_FILENAME,
    _deployment_context_prompt,
    _manifest_runtime_python_node,
)
from agentflow.loader import load_pipeline_from_text
from agentflow.orchestrator import Orchestrator
from agentflow.store import RunStore


DEFAULT_SAVED_RUN_JSON = (
    "/data/agentenv/agentflow-audit-reports/dolomite-exchange/routers-reports/"
    "runs/0ebd6761845d4604a90a0722c3348ef7/run.json"
)
DEFAULT_RUNS_DIR = "/data/agentenv/agentflow-audit-reports/dolomite-exchange/routers-reports/runs"
RESUME_NO_PROGRESS_PATIENCE = 1


def build_resume_graph(manifest_path: str, saved_run_json: str) -> Graph:
    manifest = load_manifest(manifest_path)
    selected_tracks = AUDIT_TRACKS[: min(manifest.run.parallel_shards, len(AUDIT_TRACKS))]
    poc_workspace_dir = Path(manifest.run.artifacts_dir) / "workspace" / "foundry_project"
    deployment_context_prompt = _deployment_context_prompt(manifest)

    with Graph(
        "contract-audit-resume",
        working_dir=str(REPO_ROOT),
        concurrency=1,
        max_iterations=10,
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
        load_discovery_state = python_node(
            task_id="load_discovery_state",
            code=_manifest_runtime_python_node(
                f"""
                import json
                from pathlib import Path

                from agentflow.audit.discovery import discovery_prompt_payload, load_discovery_state
                from agentflow.audit.intake import load_manifest

                manifest = load_manifest(resolved_manifest_path)
                state_path = Path(manifest.run.artifacts_dir) / "workspace" / "{_DISCOVERY_STATE_FILENAME}"
                state = load_discovery_state(state_path)
                print(json.dumps(discovery_prompt_payload(state), indent=2))
                """
            ),
        )
        load_saved_shards = python_node(
            task_id="load_saved_shards",
            code=dedent(
                f"""
                import json
                from pathlib import Path

                from agentflow.audit.reporting import normalize_shard_findings

                run = json.loads(Path({saved_run_json!r}).read_text(encoding="utf-8"))
                selected_tracks = {selected_tracks!r}
                shard_outputs = []
                for index, track in enumerate(selected_tracks):
                    node = run["nodes"][f"audit_shard_{{index}}"]
                    output = node.get("output")
                    if not isinstance(output, str) or not output.strip():
                        raise SystemExit(f"missing saved output for audit_shard_{{index}}")
                    shard_outputs.append(
                        {{
                            "track": track,
                            "output": output,
                            "final_response": node.get("final_response"),
                            "stdout": (
                                node.get("stdout")
                                if isinstance(node.get("stdout"), str)
                                else "\\n".join(node.get("stdout_lines", []))
                            ),
                            "trace_events": node.get("trace_events"),
                        }}
                    )
                print(json.dumps(normalize_shard_findings(shard_outputs), indent=2))
                """
            ).strip(),
        )
        finding_reduce = codex(
            task_id="finding_reduce",
            prompt=(
                "Merge these normalized track-specific outputs into a canonical candidate finding set.\n"
                "Deduplicate by root cause and exploit path, normalize severity, and keep the "
                "best evidence references.\n"
                "Return only JSON with this shape:\n"
                '{\n'
                '  "dedupe_summary": {\n'
                '    "input_findings": 1,\n'
                '    "canonical_findings": 1,\n'
                '    "merged_duplicates": [{"canonical_id":"CAN-001","merged_from":["x","y"],"reason":"..."}]\n'
                '  },\n'
                '  "canonical_findings": [\n'
                '    {\n'
                '      "status":"candidate",\n'
                '      "canonical_id":"CAN-001",\n'
                '      "title":"...",\n'
                '      "severity":"high",\n'
                '      "confidence":"high",\n'
                '      "tracks":["..."],\n'
                '      "merged_from":["..."],\n'
                '      "affected_contracts":["..."],\n'
                '      "root_cause":"...",\n'
                '      "exploit_path":"...",\n'
                '      "impact":"...",\n'
                '      "best_evidence_refs":["path:line-line"]\n'
                '    }\n'
                '  ]\n'
                '}\n\n'
                "{{ nodes.load_saved_shards.output }}"
            ),
            tools="read_only",
            extra_args=CODEX_BYPASS_EXTRA_ARGS,
            retries=_AUDIT_CODEX_RETRIES,
            retry_backoff_seconds=_AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
        )
        evidence_review = codex(
            task_id="evidence_review",
            prompt=(
                "Review the reduced candidate findings against the source and narrow, reject, or "
                "confirm each item with explicit source-grounded reasoning.\n"
                "Return only a JSON array of finding reviews with this shape:\n"
                "[\n"
                "  {\n"
                '    "id":"CAN-001",\n'
                '    "title":"...",\n'
                '    "severity":"high",\n'
                '    "category":"...",\n'
                '    "status":"validated",\n'
                '    "validation_status":"source_confirmed|rejected",\n'
                '    "component":{"file":"...","symbol":null,"lines":[1,2]},\n'
                '    "summary":"...",\n'
                '    "root_cause":"...",\n'
                '    "attack_scenario":"...",\n'
                '    "evidence":[{"file":"...","start_line":1,"end_line":2,"snippet_ref":"..."}],\n'
                '    "poc":{"eligible":true,"status":"not_attempted","test_path":null},\n'
                '    "review":{"disposition":"confirmed|narrowed|merged|rejected|requires_manual_poc_design","notes":"..."},\n'
                '    "dedup_fingerprint":"..."\n'
                "  }\n"
                "]\n\n"
                f"{deployment_context_prompt}\n"
                "Discovery state:\n{{ nodes.load_discovery_state.output }}\n\n"
                "{{ nodes.finding_reduce.output }}"
            ),
            tools="read_only",
            extra_args=CODEX_BYPASS_EXTRA_ARGS,
            retries=_AUDIT_CODEX_RETRIES,
            retry_backoff_seconds=_AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
            target={"kind": "local", "cwd": str(poc_workspace_dir)},
            skills=[
                "differential-review::default",
                "spec-to-code-compliance::default",
            ],
        )
        evidence_gate = codex(
            task_id="evidence_gate",
            prompt=(
                "Produce the validated findings set for the iterative discovery pipeline.\n"
                "Return only a JSON array of findings.\n"
                "Each item must match this schema exactly:\n"
                "{\n"
                '  "id": "string",\n'
                '  "title": "string",\n'
                '  "severity": "critical|high|medium|low|info",\n'
                '  "category": "string",\n'
                '  "status": "validated",\n'
                '  "validation_status": "poc_confirmed|source_confirmed|rejected",\n'
                '  "component": {"file": "string", "symbol": "string|null", "lines": [start, end]|null},\n'
                '  "summary": "string",\n'
                '  "root_cause": "string",\n'
                '  "attack_scenario": "string",\n'
                '  "evidence": [{"file": "string", "start_line": 1, "end_line": 1, "snippet_ref": "string"}],\n'
                '  "poc": {"eligible": true, "status": "not_attempted", "test_path": null},\n'
                '  "review": {"disposition": "confirmed|narrowed|merged|rejected|requires_manual_poc_design", "notes": "string"},\n'
                '  "dedup_fingerprint": "string"\n'
                "}\n"
                "Do not use alternative keys like finding_id, review_notes, poc_eligibility, or verdict.\n"
                f"Policy: allow_source_confirmed_without_poc={manifest.policy.allow_source_confirmed_without_poc}\n\n"
                "Global audit policy override: every finding that survives to the final report must have a Foundry PoC.\n"
                "If a candidate is only a documentation/read-model mismatch, depends on a business scenario the code itself cannot support, "
                "or cannot realistically be turned into a concrete Foundry PoC in this repository, reject it now.\n"
                "For any non-rejected finding, keep `poc.eligible=true`.\n\n"
                f"{deployment_context_prompt}\n"
                "If uncertain, do not reject the finding.\n\n"
                "{{ nodes.evidence_review.output }}"
            ),
            tools="read_only",
            extra_args=CODEX_BYPASS_EXTRA_ARGS,
            retries=_AUDIT_CODEX_RETRIES,
            retry_backoff_seconds=_AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
        )
        novelty_gate = python_node(
            task_id="novelty_gate",
            code=_manifest_runtime_python_node(
                f"""
                import json
                from pathlib import Path

                from agentflow.audit.discovery import advance_discovery_state, findings_from_text
                from agentflow.audit.intake import load_manifest

                manifest = load_manifest(resolved_manifest_path)
                state_path = Path(manifest.run.artifacts_dir) / "workspace" / "{_DISCOVERY_STATE_FILENAME}"
                findings = findings_from_text(\"\"\"{{{{ nodes.evidence_gate.output }}}}\"\"\")
                state, decision = advance_discovery_state(
                    state_path,
                    findings,
                    no_progress_patience={RESUME_NO_PROGRESS_PATIENCE},
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
                """
            ),
            success_criteria=[{"kind": "output_contains", "value": '"status": "STOP"'}],
        )
        discovery_finalize = python_node(
            task_id="discovery_finalize",
            code=_manifest_runtime_python_node(
                f"""
                import json
                from pathlib import Path

                from agentflow.audit.discovery import customer_visible_findings, load_discovery_state
                from agentflow.audit.intake import load_manifest

                manifest = load_manifest(resolved_manifest_path)
                state_path = Path(manifest.run.artifacts_dir) / "workspace" / "{_DISCOVERY_STATE_FILENAME}"
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

                prepared = json.loads(\"\"\"{{ nodes.prepare_foundry_workspace.output }}\"\"\")
                findings = extract_json_document(\"\"\"{{ nodes.discovery_finalize.output }}\"\"\")
                authored = extract_json_document(\"\"\"{{ nodes.poc_author.output }}\"\"\")
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
                materialized = json.loads(\"\"\"{{ nodes.materialize_target.output }}\"\"\")
                findings = [
                    FindingRecord.model_validate(item)
                    for item in extract_json_document(\"\"\"{{ nodes.final_adjudication.output }}\"\"\")
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
                materialized = json.loads(\"\"\"{{ nodes.materialize_target.output }}\"\"\")
                findings = [
                    FindingRecord.model_validate(item)
                    for item in extract_json_document(\"\"\"{{ nodes.report_review.output }}\"\"\")
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

        intake_target >> materialize_target >> prepare_foundry_workspace >> load_discovery_state >> load_saved_shards >> finding_reduce
        finding_reduce >> evidence_review >> evidence_gate >> novelty_gate >> discovery_finalize >> poc_author >> poc_verify >> final_adjudication
        novelty_gate.on_failure >> load_discovery_state
        final_adjudication >> report_build >> report_review >> report_finalize_build >> publish_artifacts

    return graph


async def main() -> None:
    manifest_path = os.environ[AUDIT_MANIFEST_ENV]
    saved_run_json = os.environ.get("AGENTFLOW_SAVED_RUN_JSON", DEFAULT_SAVED_RUN_JSON)
    runs_dir = os.environ.get("AGENTFLOW_RUNS_DIR", DEFAULT_RUNS_DIR)
    graph = build_resume_graph(manifest_path, saved_run_json)
    pipeline = load_pipeline_from_text(graph.to_json(), base_dir=REPO_ROOT)
    store = RunStore(runs_dir)
    orchestrator = Orchestrator(store=store, max_concurrent_runs=1)
    record = await orchestrator.submit(pipeline)
    print(f"RUN_ID {record.id}", flush=True)
    completed = await orchestrator.wait(record.id, timeout=None)
    print(f"STATUS {completed.status.value}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
