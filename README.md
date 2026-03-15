# AgentFlow

AgentFlow orchestrates `codex`, `claude`, and `kimi` as dependency-aware DAGs that can run locally, in containers, or on AWS Lambda.

## Quickstart

Requirements:

- Python 3.11+
- The agent CLIs your pipeline uses (`codex`, `claude`, and/or `kimi`)

Install:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

Scaffold and run a starter pipeline:

```bash
agentflow templates
agentflow init > pipeline.yaml
agentflow init repo-sweep.yaml --template codex-fanout-repo-sweep
agentflow init fuzz-matrix.yaml --template codex-fuzz-matrix
agentflow init fuzz-matrix-128.yaml --template codex-fuzz-matrix-128
agentflow init fuzz-swarm.yaml --template codex-fuzz-swarm
agentflow init fuzz-128.yaml --template codex-fuzz-swarm --set shards=128 --set concurrency=32
agentflow validate pipeline.yaml
agentflow run pipeline.yaml
```

Useful next commands:

```bash
agentflow inspect pipeline.yaml
agentflow serve --host 127.0.0.1 --port 8000
agentflow smoke
```

Choose a starter:

- `codex-fanout-repo-sweep` for repo review and audit fanout
- `codex-fuzz-matrix` for heterogeneous campaigns built from reusable axes
- `codex-fuzz-matrix-128` for a full 128-shard matrix reference
- `codex-fuzz-swarm` for homogeneous shard swarms you resize with `--set shards=...`

## Example

`examples/pipeline.yaml`

```yaml
name: parallel-code-orchestration
description: Codex plans, Claude implements, and Kimi reviews in parallel before a final Codex merge.
working_dir: .
concurrency: 3
nodes:
  - id: plan
    agent: codex
    model: gpt-5-codex
    tools: read_only
    capture: final
    prompt: |
      Inspect the repository and create a short implementation plan.

  - id: implement
    agent: claude
    model: claude-sonnet-4-5
    tools: read_write
    capture: final
    depends_on: [plan]
    prompt: |
      Use the plan below and implement the requested change.

      Plan:
      {{ nodes.plan.output }}

  - id: review
    agent: kimi
    model: kimi-k2-turbo-preview
    tools: read_only
    capture: trace
    depends_on: [plan]
    prompt: |
      Review the proposed implementation plan.

      Plan:
      {{ nodes.plan.output }}

  - id: merge
    agent: codex
    model: gpt-5-codex
    tools: read_only
    depends_on: [implement, review]
    success_criteria:
      - kind: output_contains
        value: success
    prompt: |
      Combine these two perspectives into a final release summary and include the word success.

      Implementation output:
      {{ nodes.implement.output }}

      Review trace:
      {{ nodes.review.output }}
```

For larger swarms, use node-level `fanout` to keep the YAML compact while still running a concrete DAG:

```yaml
nodes:
  - id: fuzzer
    fanout:
      count: 128
      as: shard
    agent: codex
    prompt: |
      You are shard {{ shard.number }} of {{ shard.count }}.

  - id: merge
    agent: codex
    depends_on: [fuzzer]
    prompt: |
      {% for shard in fanouts.fuzzer.nodes %}
      ## {{ shard.id }}
      {{ shard.output or "(no output)" }}

      {% endfor %}
```

When shards need explicit per-member metadata instead of just an index, use `fanout.values`:

```yaml
nodes:
  - id: fuzzer
    fanout:
      as: shard
      values:
        - target: libpng
          sanitizer: asan
          seed: 1101
        - target: sqlite
          sanitizer: ubsan
          seed: 2202
    agent: codex
    prompt: |
      Fuzz {{ shard.target }} with {{ shard.sanitizer }} using seed {{ shard.seed }}.
```

When the metadata itself is naturally multi-axis, use `fanout.matrix` to build the cartesian product and keep reducer prompts aware of each member's fields:

```yaml
nodes:
  - id: fuzzer
    fanout:
      as: shard
      matrix:
        family:
          - target: libpng
            corpus: png
          - target: sqlite
            corpus: sql
        variant:
          - sanitizer: asan
            seed: 1101
          - sanitizer: ubsan
            seed: 2202
    agent: codex
    prompt: |
      Fuzz {{ shard.target }} with {{ shard.sanitizer }} using seed {{ shard.seed }}.

  - id: merge
    agent: codex
    depends_on: [fuzzer]
    prompt: |
      {% for shard in fanouts.fuzzer.nodes %}
      ## {{ shard.id }} :: {{ shard.target }} / {{ shard.sanitizer }} / {{ shard.seed }}
      {{ shard.output or "(no output)" }}

      {% endfor %}
```

See `examples/codex-fanout-repo-sweep.yaml` for a bundled maintainer-friendly review template, `examples/fuzz/codex-fuzz-matrix.yaml` for an adaptation-friendly `fanout.matrix` fuzz starter, `examples/fuzz/codex-fuzz-matrix-128.yaml` for a 128-shard matrix reference, `examples/fuzz/fuzz_codex_32.yaml` for the default right-sized Codex fuzz swarm, and `examples/fuzz/fuzz_codex_128.yaml` for the fixed 128-shard homogeneous reference swarm. The fuzz starters are scaffoldable via `agentflow init --template codex-fuzz-matrix`, `agentflow init --template codex-fuzz-matrix-128`, `agentflow init --template codex-fuzz-swarm`, and `agentflow init --template codex-fuzz-swarm --set shards=128 --set concurrency=32`.

## Docs

- [Docs index](docs/README.md)
- [CLI and operations](docs/cli.md)
- [Pipeline reference](docs/pipelines.md)
- [Testing and maintainer workflows](docs/testing.md)
- [Background and sources](docs/background.md)
