from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from agentflow.audit.pipeline_builder import AUDIT_MANIFEST_ENV, AUDIT_TRACKS, build_contract_audit_graph
from agentflow.audit.reporting import normalize_shard_findings
from agentflow.loader import load_pipeline_from_text


def test_build_contract_audit_graph_contains_expected_nodes(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        """{
          "target": {
            "source": {"kind": "local", "local_path": "."},
            "report": {"project_name": "Example Vault", "audit_scope": "src/contracts/vault"}
          },
          "run": {"artifacts_dir": ".agentflow/audits/example-vault", "parallel_shards": 6},
          "policy": {"allow_source_confirmed_without_poc": true, "max_poc_candidates": 5}
        }""",
        encoding="utf-8",
    )

    graph = build_contract_audit_graph(str(manifest_path))
    payload = graph.to_payload()
    node_ids = [node["id"] for node in payload["nodes"]]

    assert payload["name"] == "contract-audit-example"
    assert payload["max_iterations"] == 100
    assert node_ids == [
        "intake_target",
        "materialize_target",
        "prepare_foundry_workspace",
        "load_discovery_state",
        "surface_map",
        "audit_shard",
        "finding_prepare",
        "finding_reduce",
        "evidence_review",
        "evidence_gate",
        "novelty_gate",
        "discovery_finalize",
        "load_finding_curation_state",
        "finding_curation_review",
        "finding_curation_gate",
        "finding_curation_finalize",
        "poc_author",
        "poc_verify",
        "final_adjudication",
        "report_build",
        "report_review",
        "report_finalize_build",
        "package_readme_build",
        "publish_artifacts",
    ]

    audit_shard = next(node for node in payload["nodes"] if node["id"] == "audit_shard")
    surface_map = next(node for node in payload["nodes"] if node["id"] == "surface_map")
    assert audit_shard["fanout"]["values"] == [{"track": track} for track in AUDIT_TRACKS]
    assert surface_map["agent"] == "python"
    assert "entry-point-analyzer::default" in audit_shard["skills"]
    assert "static-analysis::default" in audit_shard["skills"]


def test_builder_exports_stable_manifest_env_name() -> None:
    assert AUDIT_MANIFEST_ENV == "AGENTFLOW_CONTRACT_AUDIT_MANIFEST"


def test_validated_pipeline_uses_expanded_merge_node_reference_and_shared_filesystem(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    graph = build_contract_audit_graph(str(manifest_path))
    spec = load_pipeline_from_text(graph.to_json(), base_dir=tmp_path)

    assert spec.use_worktree is False
    assert "finding_prepare_0" in spec.node_map
    assert "{{ nodes.finding_prepare_0.output }}" in spec.node_map["finding_reduce"].prompt
    assert "{{ nodes.finding_reduce.output }}" in spec.node_map["evidence_review"].prompt
    assert "{{ nodes.finding_reduce_0.output }}" not in spec.node_map["evidence_review"].prompt


def test_finding_prepare_embeds_shard_json_as_raw_python_string(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    graph = build_contract_audit_graph(str(manifest_path))
    payload = graph.to_payload()
    finding_prepare = next(node for node in payload["nodes"] if node["id"] == "finding_prepare")

    assert 'json.loads(r"""{{ item.scope.with_output.nodes | tojson }}""")' in finding_prepare["prompt"]


def test_evidence_gate_requires_structured_findings_json_output(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    graph = build_contract_audit_graph(str(manifest_path))
    payload = graph.to_payload()
    evidence_gate = next(node for node in payload["nodes"] if node["id"] == "evidence_gate")

    assert "Return only a JSON array of findings." in evidence_gate["prompt"]
    assert '"validation_status": "poc_confirmed|source_confirmed|rejected"' in evidence_gate["prompt"]
    assert "Do not use alternative keys like finding_id, review_notes, poc_eligibility, or verdict." in evidence_gate["prompt"]
    assert "every finding that survives to the final report must have a Foundry PoC" in evidence_gate["prompt"]


def test_novelty_gate_embeds_evidence_output_via_tojson(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    graph = build_contract_audit_graph(str(manifest_path))
    payload = graph.to_payload()
    novelty_gate = next(node for node in payload["nodes"] if node["id"] == "novelty_gate")

    assert 'evidence_gate_output = {{ nodes.evidence_gate.output | tojson }}' in novelty_gate["prompt"]


def test_surface_map_embeds_structured_payloads_via_raw_tojson(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    graph = build_contract_audit_graph(str(manifest_path))
    payload = graph.to_payload()
    surface_map = next(node for node in payload["nodes"] if node["id"] == "surface_map")

    assert 'prepared_payload = {{ nodes.prepare_foundry_workspace.output | tojson }}' in surface_map["prompt"]
    assert 'discovery_state_payload = {{ nodes.load_discovery_state.output | tojson }}' in surface_map["prompt"]


def test_python_nodes_embed_structured_outputs_via_tojson(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    spec = build_contract_audit_graph(str(manifest_path)).to_spec()

    assert "{{ nodes.finding_curation_finalize.output }}" in spec.node_map["poc_author"].prompt
    assert "{{ nodes.discovery_finalize.output }}" not in spec.node_map["poc_author"].prompt
    assert 'prepared_payload = {{ nodes.prepare_foundry_workspace.output | tojson }}' in spec.node_map["poc_verify"].prompt
    assert 'findings_payload = {{ nodes.finding_curation_finalize.output | tojson }}' in spec.node_map["poc_verify"].prompt
    assert 'authored_payload = {{ nodes.poc_author.output | tojson }}' in spec.node_map["poc_verify"].prompt
    assert 'findings_payload = {{ nodes.finding_curation_finalize.output | tojson }}' in spec.node_map["final_adjudication"].prompt
    assert 'materialized_payload = {{ nodes.materialize_target.output | tojson }}' in spec.node_map["report_build"].prompt
    assert 'final_adjudication_payload = {{ nodes.final_adjudication.output | tojson }}' in spec.node_map["report_build"].prompt
    assert 'materialized_payload = {{ nodes.materialize_target.output | tojson }}' in spec.node_map["report_finalize_build"].prompt
    assert 'report_review_payload = {{ nodes.report_review.output | tojson }}' in spec.node_map["report_finalize_build"].prompt
    assert 'poc_verify_payload = {{ nodes.poc_verify.output | tojson }}' in spec.node_map["package_readme_build"].prompt
    assert '"readme": "README.md"' in spec.node_map["publish_artifacts"].prompt


def test_finding_curation_gate_embeds_review_output_via_tojson(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    graph = build_contract_audit_graph(str(manifest_path))
    payload = graph.to_payload()
    finding_curation_gate = next(
        node for node in payload["nodes"] if node["id"] == "finding_curation_gate"
    )

    assert 'review_output = {{ nodes.finding_curation_review.output | tojson }}' in finding_curation_gate["prompt"]


def test_report_review_is_delivery_qa_only(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    graph = build_contract_audit_graph(str(manifest_path))
    payload = graph.to_payload()
    report_review = next(node for node in payload["nodes"] if node["id"] == "report_review")

    assert "Do not add, remove, merge, split, reject, or re-scope findings." in report_review["prompt"]
    assert "Only improve wording, ordering, report-safe phrasing, and citation clarity." in report_review["prompt"]


def test_public_example_prints_contract_audit_graph(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                    "chain_context": {
                        "chain": "ethereum",
                        "contract_address_url": "https://etherscan.io/address/0x1111111111111111111111111111111111111111",
                        "creation_tx_url": "https://etherscan.io/tx/0x2222222222222222222222222222222222222222222222222222222222222222",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )
    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env[AUDIT_MANIFEST_ENV] = str(manifest_path)

    completed = subprocess.run(
        [sys.executable, str(repo_root / "examples" / "contract_audit.py")],
        check=True,
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )

    payload = json.loads(completed.stdout)
    assert payload["name"] == "contract-audit-example"


def test_finalize_from_saved_review_example_includes_package_readme_stage(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": str(tmp_path / "artifacts"),
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    reviewed_findings = tmp_path / "reviewed.json"
    reviewed_findings.write_text("[]", encoding="utf-8")
    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env[AUDIT_MANIFEST_ENV] = str(manifest_path)
    env["AGENTFLOW_CONTRACT_AUDIT_REVIEWED_FINDINGS_PATH"] = str(reviewed_findings)

    completed = subprocess.run(
        [sys.executable, str(repo_root / "examples" / "contract_audit_finalize_from_saved_review.py")],
        check=True,
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )

    payload = json.loads(completed.stdout)
    node_ids = [node["id"] for node in payload["nodes"]]

    assert payload["name"] == "contract-audit-finalize-from-saved-review"
    assert "package_readme_build" in node_ids
    publish_node = next(node for node in payload["nodes"] if node["id"] == "publish_artifacts")
    assert '"readme": "README.md"' in publish_node["prompt"]
    assert "\nprint(\n" in publish_node["prompt"]
    load_saved_poc_verify = next(node for node in payload["nodes"] if node["id"] == "load_saved_poc_verify")
    assert "from agentflow.audit.intake import load_manifest" in load_saved_poc_verify["prompt"]
    assert "manifest = load_manifest(resolved_manifest_path)" in load_saved_poc_verify["prompt"]


def test_continue_from_existing_pocs_example_skips_poc_author_and_derives_mappings(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": str(tmp_path / "artifacts"),
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env[AUDIT_MANIFEST_ENV] = str(manifest_path)

    completed = subprocess.run(
        [sys.executable, str(repo_root / "examples" / "contract_audit_continue_from_existing_pocs.py")],
        check=True,
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )

    payload = json.loads(completed.stdout)
    node_ids = [node["id"] for node in payload["nodes"]]

    assert payload["name"] == "contract-audit-continue-from-existing-pocs"
    assert "derive_poc_mappings" in node_ids
    assert "poc_author" not in node_ids


def test_continue_from_saved_final_adjudication_publish_artifacts_snippet_executes(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": str(tmp_path / "artifacts"),
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env[AUDIT_MANIFEST_ENV] = str(manifest_path)

    completed = subprocess.run(
        [sys.executable, str(repo_root / "examples" / "contract_audit_continue_from_saved_final_adjudication.py")],
        check=True,
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )

    payload = json.loads(completed.stdout)
    publish_node = next(node for node in payload["nodes"] if node["id"] == "publish_artifacts")

    executed = subprocess.run(
        [sys.executable, "-c", publish_node["prompt"]],
        check=False,
        capture_output=True,
        text=True,
        cwd=repo_root,
    )

    assert executed.returncode == 0, executed.stderr


def test_public_example_resolves_repo_root_working_dir_for_python_utility_nodes() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    pipeline_path = repo_root / "examples" / "contract_audit.py"

    completed = subprocess.run(
        [sys.executable, str(pipeline_path)],
        check=False,
        capture_output=True,
        text=True,
        cwd=repo_root,
        env={**os.environ, AUDIT_MANIFEST_ENV: str(repo_root / "examples" / "contract_audit_manifest.example.json")},
    )

    assert completed.returncode == 0, completed.stderr

    spec = load_pipeline_from_text(
        completed.stdout,
        base_dir=pipeline_path.parent,
    )

    assert spec.working_dir == str(repo_root.resolve())


def test_publish_artifacts_summary_uses_report_relative_paths() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = Path(tmp) / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "target": {
                        "source": {
                            "kind": "github",
                            "repo_url": "https://github.com/example/contracts",
                            "commit": "0123456789abcdef0123456789abcdef01234567",
                        },
                        "report": {
                            "project_name": "Example Vault",
                            "audit_scope": "src/contracts/vault",
                        },
                    },
                    "run": {
                        "artifacts_dir": ".agentflow/audits/example-vault",
                        "parallel_shards": 6,
                    },
                    "policy": {
                        "allow_source_confirmed_without_poc": True,
                        "max_poc_candidates": 5,
                    },
                }
            ),
            encoding="utf-8",
        )

        graph = build_contract_audit_graph(str(manifest_path))
        payload = graph.to_payload()
        publish_artifacts = next(node for node in payload["nodes"] if node["id"] == "publish_artifacts")

        completed = subprocess.run(
            [sys.executable, "-c", publish_artifacts["prompt"]],
            check=False,
            capture_output=True,
            text=True,
            cwd=repo_root,
        )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "package_root": ".",
        "artifacts_root": "artifacts",
        "readme": "README.md",
        "audit_report": "AUDIT_REPORT.md",
        "report_dir": "artifacts/report",
        "findings": "artifacts/report/findings.json",
        "summary": "artifacts/report/audit_summary.json",
    }


def test_public_example_does_not_inline_manifest_path_in_emitted_graph_json(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 6,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )
    repo_root = Path(__file__).resolve().parents[1]
    pipeline_path = repo_root / "examples" / "contract_audit.py"

    completed = subprocess.run(
        [sys.executable, str(pipeline_path)],
        check=False,
        capture_output=True,
        text=True,
        cwd=repo_root,
        env={**os.environ, AUDIT_MANIFEST_ENV: str(manifest_path)},
    )

    assert completed.returncode == 0, completed.stderr
    assert str(manifest_path.resolve()) not in completed.stdout


def test_build_contract_audit_graph_limits_tracks_with_parallel_shards(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 2,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    payload = build_contract_audit_graph(str(manifest_path)).to_payload()
    audit_shard = next(node for node in payload["nodes"] if node["id"] == "audit_shard")
    finding_prepare = next(node for node in payload["nodes"] if node["id"] == "finding_prepare")
    finding_reduce = next(node for node in payload["nodes"] if node["id"] == "finding_reduce")

    assert payload["concurrency"] == 2
    assert audit_shard["fanout"]["values"] == [
        {"track": "access-control-and-init"},
        {"track": "accounting-and-rounding"},
    ]
    assert finding_prepare["fanout"]["batches"]["size"] == 2
    assert "fanout" not in finding_reduce


def test_build_contract_audit_graph_threads_policy_and_locks_poc_author_cwd(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                    "deployment_context": "The deployed vault intentionally keeps slasher at zero.",
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 4,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": False,
                    "max_poc_candidates": 2,
                },
            }
        ),
        encoding="utf-8",
    )

    spec = build_contract_audit_graph(str(manifest_path)).to_spec()

    assert spec.node_map["poc_author"].target.cwd == ".agentflow/audits/example-vault/workspace/foundry_project"
    assert spec.node_map["report_review"].target.cwd == ".agentflow/audits/example-vault/workspace/foundry_project"
    assert "allow_source_confirmed_without_poc=False" in spec.node_map["evidence_gate"].prompt
    assert "max_poc_candidates=2" in spec.node_map["poc_author"].prompt
    assert "every non-rejected validated finding" in spec.node_map["poc_author"].prompt
    assert spec.node_map["final_adjudication"].agent.value == "python"
    assert 'if build_status != "passed" or test_status != "passed":' in spec.node_map["final_adjudication"].prompt
    assert 'validation_status": "poc_confirmed"' in spec.node_map["final_adjudication"].prompt
    assert "Do not add, remove, merge, split, reject, or re-scope findings." in spec.node_map["report_review"].prompt
    assert "Only improve wording, ordering, report-safe phrasing, and citation clarity." in spec.node_map["report_review"].prompt
    assert "intentionally keeps slasher at zero" in spec.node_map["evidence_review"].prompt
    assert spec.node_map["novelty_gate"].on_failure_restart == ["load_discovery_state"]
    assert spec.node_map["finding_curation_gate"].on_failure_restart == ["load_finding_curation_state"]
    assert 'evidence_gate_output = {{ nodes.evidence_gate.output | tojson }}' in spec.node_map["novelty_gate"].prompt
    assert 'findings = findings_from_text(evidence_gate_output)' in spec.node_map["novelty_gate"].prompt
    assert "{{ nodes.finding_curation_finalize.output }}" in spec.node_map["poc_author"].prompt
    assert 'authored_payload = {{ nodes.poc_author.output | tojson }}' in spec.node_map["final_adjudication"].prompt
    assert "{{ nodes.report_build.output }}" in spec.node_map["report_review"].prompt
    assert 'report_review_payload = {{ nodes.report_review.output | tojson }}' in spec.node_map["report_finalize_build"].prompt


def test_poc_verify_tracks_authored_test_coverage(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 4,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": False,
                    "max_poc_candidates": 2,
                },
            }
        ),
        encoding="utf-8",
    )

    spec = build_contract_audit_graph(str(manifest_path)).to_spec()

    assert 'authored_payload = {{ nodes.poc_author.output | tojson }}' in spec.node_map["poc_verify"].prompt
    assert 'findings_payload = {{ nodes.finding_curation_finalize.output | tojson }}' in spec.node_map["poc_verify"].prompt
    assert "missing_mappings" in spec.node_map["poc_verify"].prompt
    assert "nonexistent_test_paths" in spec.node_map["poc_verify"].prompt


def test_final_adjudication_is_deterministic_python_filter_that_allows_partial_poc_coverage(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": ".agentflow/audits/example-vault",
                    "parallel_shards": 4,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": False,
                    "max_poc_candidates": 2,
                },
            }
        ),
        encoding="utf-8",
    )

    spec = build_contract_audit_graph(str(manifest_path)).to_spec()

    assert spec.node_map["final_adjudication"].agent.value == "python"
    prompt = spec.node_map["final_adjudication"].prompt
    assert 'findings_payload = {{ nodes.finding_curation_finalize.output | tojson }}' in prompt
    assert 'authored_payload = {{ nodes.poc_author.output | tojson }}' in prompt
    assert 'verification_payload = {{ nodes.poc_verify.output | tojson }}' in prompt
    assert 'if build_status != "passed" or test_status != "passed":' in prompt
    assert 'if not test_path or finding.id in missing_test_paths:' in prompt


def test_build_contract_audit_graph_accepts_absolute_artifacts_dir_for_poc_workspace(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    artifacts_dir = tmp_path / "cap-vault-reports" / "artifacts"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": str(artifacts_dir),
                    "parallel_shards": 4,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 3,
                },
            }
        ),
        encoding="utf-8",
    )

    spec = build_contract_audit_graph(str(manifest_path)).to_spec()

    assert spec.node_map["poc_author"].target.cwd == str(
        artifacts_dir / "workspace" / "foundry_project"
    )


def test_python_utility_node_prompts_compile_without_indentation_errors(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    artifacts_dir = tmp_path / "cap-vault-reports" / "artifacts"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "local",
                        "local_path": str(tmp_path),
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": str(artifacts_dir),
                    "parallel_shards": 2,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 2,
                },
            }
        ),
        encoding="utf-8",
    )

    payload = build_contract_audit_graph(str(manifest_path)).to_payload()

    for node in payload["nodes"]:
        if node["agent"] != "python":
            continue
        compile(node["prompt"], f"{node['id']}.py", "exec")


def test_contract_audit_codex_nodes_bypass_local_codex_sandbox(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": str(tmp_path / "artifacts"),
                    "parallel_shards": 3,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 2,
                },
            }
        ),
        encoding="utf-8",
    )

    payload = build_contract_audit_graph(str(manifest_path)).to_payload()

    for node in payload["nodes"]:
        if node["agent"] != "codex":
            continue
        assert node["extra_args"] == ["--dangerously-bypass-approvals-and-sandbox"]


def test_contract_audit_codex_nodes_retry_transient_provider_failures(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "target": {
                    "source": {
                        "kind": "github",
                        "repo_url": "https://github.com/example/contracts",
                        "commit": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "report": {
                        "project_name": "Example Vault",
                        "audit_scope": "src/contracts/vault",
                    },
                },
                "run": {
                    "artifacts_dir": str(tmp_path / "artifacts"),
                    "parallel_shards": 3,
                },
                "policy": {
                    "allow_source_confirmed_without_poc": True,
                    "max_poc_candidates": 2,
                },
            }
        ),
        encoding="utf-8",
    )

    payload = build_contract_audit_graph(str(manifest_path)).to_payload()

    for node in payload["nodes"]:
        if node["agent"] != "codex":
            continue
        assert node["retries"] == 5
        assert node["retry_backoff_seconds"] == 5.0


def test_normalize_shard_findings_extracts_structured_candidate_lists() -> None:
    normalized = normalize_shard_findings(
        [
            {
                "track": "access-control-and-init",
                "output": (
                    "progress message\n"
                    "another line\n"
                    '[{"id":"A-1","title":"Issue A"},{"id":"A-2","title":"Issue B"}]'
                ),
            },
            {
                "track": "state-machine-and-epoch-flow",
                "output": "status update\n[{\"id\":\"S-1\",\"title\":\"Issue C\"}]",
            },
        ]
    )

    assert normalized == [
        {
            "track": "access-control-and-init",
            "findings": [
                {"id": "A-1", "title": "Issue A"},
                {"id": "A-2", "title": "Issue B"},
            ],
        },
        {
            "track": "state-machine-and-epoch-flow",
            "findings": [
                {"id": "S-1", "title": "Issue C"},
            ],
        },
    ]


def test_normalize_shard_findings_falls_back_to_stdout_agent_message_json() -> None:
    normalized = normalize_shard_findings(
        [
            {
                "track": "access-control-and-init",
                "output": "progress only",
                "stdout": "\n".join(
                    [
                        '{"type":"item.completed","item":{"id":"item_1","type":"agent_message","text":"thinking..."}}',
                        '{"type":"item.completed","item":{"id":"item_2","type":"agent_message","text":"[{\\"id\\":\\"A-1\\",\\"title\\":\\"Issue A\\"}]"}}',
                    ]
                ),
            }
        ]
    )

    assert normalized == [
        {
            "track": "access-control-and-init",
            "findings": [
                {"id": "A-1", "title": "Issue A"},
            ],
        }
    ]


def test_normalize_shard_findings_falls_back_to_trace_events_json() -> None:
    normalized = normalize_shard_findings(
        [
            {
                "track": "accounting-and-rounding",
                "output": "progress only",
                "trace_events": [
                    {"kind": "assistant_message", "content": "thinking..."},
                    {
                        "kind": "assistant_message",
                        "content": '[{"id":"A-2","title":"Issue B"}]',
                    },
                ],
            }
        ]
    )

    assert normalized == [
        {
            "track": "accounting-and-rounding",
            "findings": [
                {"id": "A-2", "title": "Issue B"},
            ],
        }
    ]


def test_normalize_shard_findings_reads_item_completed_agent_message_from_trace_events() -> None:
    normalized = normalize_shard_findings(
        [
            {
                "track": "state-machine-and-epoch-flow",
                "output": "progress only",
                "trace_events": [
                    {
                        "kind": "item_completed",
                        "raw": {
                            "type": "item.completed",
                            "item": {
                                "id": "item_91",
                                "type": "agent_message",
                                "text": '[{"id":"S-1","title":"Issue C"}]',
                            },
                        },
                    }
                ],
            }
        ]
    )

    assert normalized == [
        {
            "track": "state-machine-and-epoch-flow",
            "findings": [
                {"id": "S-1", "title": "Issue C"},
            ],
        }
    ]
