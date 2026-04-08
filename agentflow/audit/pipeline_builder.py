from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from agentflow import Graph, codex, fanout, merge, python_node


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


def _python_call(module: str, function_name: str, *args: str) -> str:
    rendered_args = ", ".join(repr(arg) for arg in args)
    return dedent(
        f"""
        from {module} import {function_name}

        {function_name}({rendered_args})
        """
    ).strip()


def build_contract_audit_graph(manifest_path: str) -> Graph:
    with Graph(
        "contract-audit-example",
        working_dir=str(REPO_ROOT),
        concurrency=len(AUDIT_TRACKS),
    ) as graph:
        intake_target = python_node(
            task_id="intake_target",
            code=_python_call("agentflow.audit.intake", "emit_normalized_manifest", manifest_path),
        )
        materialize_target = python_node(
            task_id="materialize_target",
            code=dedent(
                f"""
                import json
                from pathlib import Path

                from agentflow.audit.intake import load_manifest
                from agentflow.audit.materialize import materialize_source

                manifest = load_manifest({manifest_path!r})
                materialized = materialize_source(manifest, Path(manifest.run.artifacts_dir))
                print(
                    json.dumps(
                        {{
                            "snapshot_dir": str(materialized.snapshot_dir),
                            "source_identifier": materialized.source_identifier,
                            "source_mode": materialized.source_mode,
                            "source_inventory": materialized.source_inventory,
                        }},
                        indent=2,
                    )
                )
                """
            ).strip(),
        )
        prepare_foundry_workspace = python_node(
            task_id="prepare_foundry_workspace",
            code=dedent(
                f"""
                import json
                from pathlib import Path

                from agentflow.audit.foundry import prepare_foundry_workspace
                from agentflow.audit.intake import load_manifest
                from agentflow.audit.materialize import materialize_source

                manifest = load_manifest({manifest_path!r})
                materialized = materialize_source(manifest, Path(manifest.run.artifacts_dir))
                prepared = prepare_foundry_workspace(materialized, Path(manifest.run.artifacts_dir))
                print(
                    json.dumps(
                        {{
                            "workspace_dir": str(prepared.workspace_dir),
                            "source_snapshot_dir": str(prepared.source_snapshot_dir),
                            "foundry_toml_path": str(prepared.foundry_toml_path),
                            "remappings_path": (
                                str(prepared.remappings_path) if prepared.remappings_path else None
                            ),
                        }},
                        indent=2,
                    )
                )
                """
            ).strip(),
        )
        surface_map = codex(
            task_id="surface_map",
            prompt=(
                "Inspect the prepared Foundry workspace and produce a structured surface map.\n"
                "Cover privileged entrypoints, initialization paths, external call boundaries, "
                "delegatecall surfaces, upgrade or migration hooks, and accounting-critical state.\n\n"
                "Prepared workspace metadata:\n{{ nodes.prepare_foundry_workspace.output }}"
            ),
            tools="read_only",
            skills=[
                "entry-point-analyzer::default",
                "static-analysis::default",
                "building-secure-contracts::default",
            ],
        )
        audit_shard = fanout(
            codex(
                task_id="audit_shard",
                prompt=(
                    "Audit track: {{ item.track }}\n\n"
                    "Surface map:\n{{ nodes.surface_map.output }}\n\n"
                    "Return only structured candidate findings with precise source references, "
                    "attack preconditions, and remediation notes. Do not write a markdown report."
                ),
                tools="read_only",
                skills=[
                    "entry-point-analyzer::default",
                    "static-analysis::default",
                    "building-secure-contracts::default",
                    "variant-analysis::default",
                    "sharp-edges::default",
                    "insecure-defaults::default",
                ],
            ),
            [{"track": track} for track in AUDIT_TRACKS],
        )
        finding_reduce = merge(
            codex(
                task_id="finding_reduce",
                prompt=(
                    "Merge these track-specific outputs into a canonical candidate finding set.\n"
                    "Deduplicate by root cause and exploit path, normalize severity, and keep the "
                    "best evidence references.\n\n"
                    "{% for shard in item.scope.with_output.nodes %}\n"
                    "## {{ shard.track }}\n"
                    "{{ shard.output }}\n\n"
                    "{% endfor %}"
                ),
                tools="read_only",
            ),
            audit_shard,
            size=len(AUDIT_TRACKS),
        )
        evidence_review = codex(
            task_id="evidence_review",
            prompt=(
                "Review the reduced candidate findings against the source and narrow, reject, or "
                "confirm each item with explicit source-grounded reasoning.\n\n"
                "{{ nodes.finding_reduce_0.output }}"
            ),
            tools="read_only",
            skills=[
                "differential-review::default",
                "spec-to-code-compliance::default",
            ],
        )
        evidence_gate = codex(
            task_id="evidence_gate",
            prompt=(
                "Produce the validated findings set for the first-version pipeline.\n"
                "Keep only confirmed items, assign validation status, and mark PoC eligibility.\n\n"
                "{{ nodes.evidence_review.output }}"
            ),
            tools="read_only",
        )
        poc_author = codex(
            task_id="poc_author",
            prompt=(
                "Author Foundry PoC tests for the highest-value PoC-eligible validated findings.\n"
                "Keep changes limited to test assets and the minimum harness support needed.\n\n"
                "{{ nodes.evidence_gate.output }}"
            ),
            tools="read_write",
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

                prepared = json.loads(\"\"\"{{ nodes.prepare_foundry_workspace.output }}\"\"\")
                workspace_dir = Path(prepared["workspace_dir"])
                build = subprocess.run(["forge", "build"], cwd=workspace_dir, capture_output=True, text=True)
                test = subprocess.run(["forge", "test", "-vvv"], cwd=workspace_dir, capture_output=True, text=True)
                print(
                    json.dumps(
                        {
                            "workspace": str(workspace_dir),
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
                "Combine the validated findings with the PoC verification results and return the "
                "final canonical findings JSON.\n\n"
                "Validated findings:\n{{ nodes.evidence_gate.output }}\n\n"
                "PoC verification:\n{{ nodes.poc_verify.output }}"
            ),
            tools="read_only",
        )
        report_build = python_node(
            task_id="report_build",
            code=dedent(
                f"""
                import json
                from pathlib import Path

                from agentflow.audit.intake import build_report_manifest, load_manifest
                from agentflow.audit.models import FindingRecord
                from agentflow.audit.reporting import write_report_bundle

                manifest = load_manifest({manifest_path!r})
                materialized = json.loads(\"\"\"{{{{ nodes.materialize_target.output }}}}\"\"\")
                findings = [
                    FindingRecord.model_validate(item)
                    for item in json.loads(\"\"\"{{{{ nodes.final_adjudication.output }}}}\"\"\")
                ]
                report_manifest = build_report_manifest(
                    manifest,
                    source_identifier=materialized["source_identifier"],
                )
                report_dir = Path(manifest.run.artifacts_dir) / "report"
                write_report_bundle(report_dir, report_manifest, findings)
                print((report_dir / "AUDIT_REPORT.md").read_text(encoding="utf-8"))
                """
            ).strip(),
        )
        publish_artifacts = python_node(
            task_id="publish_artifacts",
            code=dedent(
                f"""
                import json
                from pathlib import Path

                from agentflow.audit.intake import load_manifest

                manifest = load_manifest({manifest_path!r})
                report_dir = Path(manifest.run.artifacts_dir) / "report"
                print(
                    json.dumps(
                        {{
                            "report_dir": str(report_dir.resolve()),
                            "report": str((report_dir / "AUDIT_REPORT.md").resolve()),
                            "findings": str((report_dir / "findings.json").resolve()),
                            "summary": str((report_dir / "audit_summary.json").resolve()),
                        }},
                        indent=2,
                    )
                )
                """
            ).strip(),
        )

        intake_target >> materialize_target >> prepare_foundry_workspace >> surface_map >> audit_shard >> finding_reduce
        finding_reduce >> evidence_review >> evidence_gate >> poc_author >> poc_verify >> final_adjudication
        final_adjudication >> report_build >> publish_artifacts

    return graph
