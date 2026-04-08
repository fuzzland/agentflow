from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from agentflow.audit.pipeline_builder import AUDIT_MANIFEST_ENV, AUDIT_TRACKS, build_contract_audit_graph
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
    assert node_ids == [
        "intake_target",
        "materialize_target",
        "prepare_foundry_workspace",
        "surface_map",
        "audit_shard",
        "finding_reduce",
        "evidence_review",
        "evidence_gate",
        "poc_author",
        "poc_verify",
        "final_adjudication",
        "report_build",
        "publish_artifacts",
    ]

    audit_shard = next(node for node in payload["nodes"] if node["id"] == "audit_shard")
    assert audit_shard["fanout"]["values"] == [{"track": track} for track in AUDIT_TRACKS]
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
    assert "finding_reduce_0" in spec.node_map
    assert "{{ nodes.finding_reduce_0.output }}" in spec.node_map["evidence_review"].prompt
    assert "{{ nodes.finding_reduce.output }}" not in spec.node_map["evidence_review"].prompt


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
