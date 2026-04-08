# Contract Audit Example

`examples/contract_audit.py` is the first public AgentFlow contract-audit example. The first version is intentionally narrow: `EVM + Solidity + Foundry` only.

## Inputs

The example reads its manifest path from `AGENTFLOW_CONTRACT_AUDIT_MANIFEST`.

The bundled file at `examples/contract_audit_manifest.example.json` is a placeholder manifest for structural validation and shape reference. Its GitHub repo and commit values are synthetic, so it is not a real end-to-end audit target by itself.

Supported source modes:

- Local source tree:

```json
{
  "target": {
    "source": {
      "kind": "local",
      "local_path": "/replace/me/locally"
    }
  }
}
```

- GitHub repo pinned to a commit:

```json
{
  "target": {
    "source": {
      "kind": "github",
      "repo_url": "https://github.com/example/contracts",
      "commit": "0123456789abcdef0123456789abcdef01234567"
    }
  }
}
```

Optional chain context fields:

- `chain`
- `contract_address_url`
- `creation_tx_url`

## Run

Structural validation with the bundled placeholder manifest:

```bash
AGENTFLOW_CONTRACT_AUDIT_MANIFEST=examples/contract_audit_manifest.example.json python -m agentflow.cli validate examples/contract_audit.py
```

Real audit run with a user-supplied manifest:

1. Copy `examples/contract_audit_manifest.example.json`.
2. Replace the placeholder GitHub values with a real `github + commit` target, or switch to a real local source tree manifest.
3. Point `AGENTFLOW_CONTRACT_AUDIT_MANIFEST` at that edited file.

```bash
AGENTFLOW_CONTRACT_AUDIT_MANIFEST=path/to/real-contract-audit-manifest.json agentflow run examples/contract_audit.py --output summary
```

There is no dedicated `agentflow audit-contract` command yet. The public entrypoint is this manifest-driven example.

## Artifact Layout

Artifacts are written under `run.artifacts_dir`. A typical run layout is:

```text
.agentflow/audits/example-vault/
  workspace/
    source_clone/
    source_snapshot/
    foundry_project/
  report/
    AUDIT_REPORT.md
    findings.json
    audit_summary.json
    report_manifest.json
```

`workspace/source_clone/` is created only for `github + commit` intake. Local-source manifests skip that directory and materialize directly into `workspace/source_snapshot/`.

## Safety

- The report renders only `target.report.audit_scope` for scope-path text.
- `AUDIT_REPORT.md` never renders absolute local filesystem paths.
- Real local debug paths and real chain context should stay only in `reference/`.

## First-Version Limits

- Only `EVM + Solidity + Foundry` are supported in this version.
- Source intake supports local trees and `github + commit` manifests.
- Explorer-based source reconstruction is out of scope for this version.
