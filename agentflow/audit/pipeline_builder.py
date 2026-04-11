from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from agentflow import Graph, codex, fanout, merge, python_node
from agentflow.audit.intake import load_manifest


AUDIT_MANIFEST_ENV = "AGENTFLOW_CONTRACT_AUDIT_MANIFEST"
REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_TRACKS = [
    "access-control-and-init",
    "accounting-and-rounding",
    "reentrancy-and-external-calls",
    "state-machine-and-epoch-flow",
    "upgradeability-migration-storage-layout",
    "integration-trust-boundaries",
]
CODEX_BYPASS_EXTRA_ARGS = ["--dangerously-bypass-approvals-and-sandbox"]
_DISCOVERY_STATE_FILENAME = "discovery_state.json"
_DISCOVERY_NO_PROGRESS_PATIENCE = 3
_DISCOVERY_MAX_ITERATIONS = 100
_AUDIT_CODEX_RETRIES = 5
_AUDIT_CODEX_RETRY_BACKOFF_SECONDS = 5.0


def _manifest_runtime_preamble() -> str:
    return dedent(
        f"""
        import os
        from pathlib import Path

        manifest_path = os.environ.get({AUDIT_MANIFEST_ENV!r})
        if not manifest_path:
            raise SystemExit(
                "Set {AUDIT_MANIFEST_ENV} to the manifest JSON path before running this pipeline."
            )
        resolved_manifest_path = Path(manifest_path).expanduser()
        if not resolved_manifest_path.is_absolute():
            resolved_manifest_path = (Path.cwd() / resolved_manifest_path).resolve()
        else:
            resolved_manifest_path = resolved_manifest_path.resolve()
        """
    ).strip()


def _manifest_runtime_python_node(body: str) -> str:
    return f"{_manifest_runtime_preamble()}\n\n{dedent(body).strip()}"


def _deployment_context_prompt(manifest) -> str:
    context = (manifest.target.deployment_context or "").strip()
    if context:
        return (
            "Deployment context provided by the operator:\n"
            f"{context}\n\n"
            "Use this context only when it directly invalidates exploit preconditions.\n"
            "If the context is insufficient or ambiguous, keep the finding.\n"
        )
    return (
        "No deployment context was provided.\n"
        "Reject a finding only when the code itself proves it is non-actionable.\n"
        "If there is any uncertainty, keep the finding.\n"
    )


def build_contract_audit_graph(manifest_path: str) -> Graph:
    manifest = load_manifest(manifest_path)
    selected_tracks = AUDIT_TRACKS[: min(manifest.run.parallel_shards, len(AUDIT_TRACKS))]
    poc_workspace_dir = Path(manifest.run.artifacts_dir) / "workspace" / "foundry_project"
    discovery_state_path = Path(manifest.run.artifacts_dir) / "workspace" / _DISCOVERY_STATE_FILENAME
    deployment_context_prompt = _deployment_context_prompt(manifest)

    with Graph(
        "contract-audit-example",
        working_dir=str(REPO_ROOT),
        concurrency=len(selected_tracks),
        max_iterations=_DISCOVERY_MAX_ITERATIONS,
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
        surface_map = python_node(
            task_id="surface_map",
            code=dedent(
                """
                import json
                import re
                from pathlib import Path

                prepared_payload = {{ nodes.prepare_foundry_workspace.output | tojson }}
                prepared = (
                    json.loads(prepared_payload)
                    if isinstance(prepared_payload, str)
                    else prepared_payload
                )
                discovery_state_payload = {{ nodes.load_discovery_state.output | tojson }}
                discovery_state = (
                    json.loads(discovery_state_payload)
                    if isinstance(discovery_state_payload, str)
                    else discovery_state_payload
                )
                workspace_dir = Path(prepared["workspace_dir"])
                src_root = workspace_dir / "src"
                out_root = workspace_dir / "out"

                def _relative(path: Path) -> str:
                    return path.relative_to(workspace_dir).as_posix()

                def _scan_hits(pattern: str, *, max_hits: int = 40) -> list[dict[str, object]]:
                    regex = re.compile(pattern)
                    hits: list[dict[str, object]] = []
                    for path in sorted(src_root.rglob("*.sol")):
                        try:
                            lines = path.read_text(encoding="utf-8").splitlines()
                        except UnicodeDecodeError:
                            continue
                        for idx, line in enumerate(lines, start=1):
                            if not regex.search(line):
                                continue
                            hits.append(
                                {
                                    "file": _relative(path),
                                    "line": idx,
                                    "text": line.strip()[:200],
                                }
                            )
                            if len(hits) >= max_hits:
                                return hits
                    return hits

                contract_methods: list[dict[str, object]] = []
                for artifact_path in sorted(out_root.rglob("*.json")):
                    if "build-info" in artifact_path.parts:
                        continue
                    try:
                        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
                    abi = artifact.get("abi")
                    if not isinstance(abi, list):
                        continue
                    methods = [
                        {
                            "name": item["name"],
                            "stateMutability": item.get("stateMutability"),
                        }
                        for item in abi
                        if isinstance(item, dict) and item.get("type") == "function" and item.get("name")
                    ]
                    if not methods:
                        continue
                    contract_methods.append(
                        {
                            "artifact": artifact_path.relative_to(out_root).as_posix(),
                            "functions": methods[:25],
                        }
                    )
                    if len(contract_methods) >= 20:
                        break

                payload = {
                    "workspace_dir": str(workspace_dir),
                    "foundry_toml_path": prepared["foundry_toml_path"],
                    "remappings_path": prepared.get("remappings_path"),
                    "discovery_state": discovery_state,
                    "source_files": [_relative(path) for path in sorted(src_root.rglob("*.sol"))],
                    "contract_methods": contract_methods,
                    "privileged_entrypoints": _scan_hits(r"\\bonlyOwner\\b|requireIsGlobalOperator\\(|requireIsOperator\\("),
                    "external_call_boundaries": _scan_hits(
                        r"\\.call\\(|transfer\\(|transferFrom\\(|exchange\\(|getExchangeCost\\(|getTradeCost\\(|callFunction\\(|onInternalBalanceChange\\("
                    ),
                    "upgrade_and_init_signals": _scan_hits(
                        r"delegatecall|proxy|implementation|upgrade|initialize\\(|initializer|reinitialize|tx\\.origin"
                    ),
                    "accounting_hotspots": _scan_hits(
                        r"getNewParAndDeltaWei\\(|setPar\\(|setParFromDeltaWei\\(|getNumExcessTokens\\(|weiToPar\\(|parToWei\\("
                    ),
                }
                print(json.dumps(payload, indent=2))
                """
            ).strip(),
        )
        audit_shard = fanout(
            codex(
                task_id="audit_shard",
                prompt=(
                    "Audit track: {{ item.track }}\n\n"
                    "Surface map:\n{{ nodes.surface_map.output }}\n\n"
                    "Discovery state:\n{{ nodes.load_discovery_state.output }}\n\n"
                    "Return only structured candidate findings with precise source references, "
                    "attack preconditions, and remediation notes.\n"
                    "Keep the pass bounded and efficient: prefer targeted reads, avoid dumping long file contents, "
                    "and do not narrate progress.\n"
                    "Avoid repeating previously accepted or rejected findings unless you have materially new evidence.\n"
                    "Do not write a markdown report."
                ),
                tools="read_only",
                extra_args=CODEX_BYPASS_EXTRA_ARGS,
                retries=_AUDIT_CODEX_RETRIES,
                retry_backoff_seconds=_AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
                skills=[
                    "entry-point-analyzer::default",
                    "static-analysis::default",
                    "building-secure-contracts::default",
                    "variant-analysis::default",
                    "sharp-edges::default",
                    "insecure-defaults::default",
                ],
            ),
            [{"track": track} for track in selected_tracks],
        )
        finding_prepare = merge(
            python_node(
                task_id="finding_prepare",
                code=dedent(
                    '''
                    import json

                    from agentflow.audit.reporting import normalize_shard_findings

                    shard_outputs = json.loads(r"""{{ item.scope.with_output.nodes | tojson }}""")
                    print(json.dumps(normalize_shard_findings(shard_outputs), indent=2))
                    '''
                ).strip(),
            ),
            audit_shard,
            size=len(selected_tracks),
        )
        finding_reduce = codex(
            task_id="finding_reduce",
            prompt=(
                "Merge these normalized track-specific outputs into a canonical candidate finding set.\n"
                "Deduplicate by root cause and exploit path, normalize severity, and keep the "
                "best evidence references.\n\n"
                "{{ nodes.finding_prepare_0.output }}"
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
                "confirm each item with explicit source-grounded reasoning.\n\n"
                f"{deployment_context_prompt}\n"
                "Discovery state:\n{{ nodes.load_discovery_state.output }}\n\n"
                "{{ nodes.finding_reduce.output }}"
            ),
            tools="read_only",
            extra_args=CODEX_BYPASS_EXTRA_ARGS,
            retries=_AUDIT_CODEX_RETRIES,
            retry_backoff_seconds=_AUDIT_CODEX_RETRY_BACKOFF_SECONDS,
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
                evidence_gate_output = {{{{ nodes.evidence_gate.output | tojson }}}}
                if not isinstance(evidence_gate_output, str):
                    evidence_gate_output = json.dumps(evidence_gate_output)
                findings = findings_from_text(evidence_gate_output)
                state, decision = advance_discovery_state(
                    state_path,
                    findings,
                    no_progress_patience={_DISCOVERY_NO_PROGRESS_PATIENCE},
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

        intake_target >> materialize_target >> prepare_foundry_workspace >> load_discovery_state >> surface_map >> audit_shard >> finding_prepare >> finding_reduce
        finding_reduce >> evidence_review >> evidence_gate >> novelty_gate >> discovery_finalize >> poc_author >> poc_verify >> final_adjudication
        novelty_gate.on_failure >> load_discovery_state
        final_adjudication >> report_build >> report_review >> report_finalize_build >> publish_artifacts

    return graph
