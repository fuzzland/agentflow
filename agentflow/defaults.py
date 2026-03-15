from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Mapping


@dataclass(frozen=True)
class BundledTemplateParameter:
    name: str
    description: str
    default: str


@dataclass(frozen=True)
class BundledTemplate:
    name: str
    example_name: str
    description: str
    parameters: tuple[BundledTemplateParameter, ...] = ()


_DEFAULT_FUZZ_SWARM_SHARDS = 32
_DEFAULT_FUZZ_SWARM_CONCURRENCY = 8


def _parse_positive_template_int(template_name: str, field_name: str, raw_value: str) -> int:
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"template `{template_name}` expects `{field_name}` to be an integer, got `{raw_value}`") from exc
    if value < 1:
        raise ValueError(f"template `{template_name}` expects `{field_name}` to be at least 1, got `{raw_value}`")
    return value


def _render_codex_fuzz_swarm_template(values: Mapping[str, str] | None = None) -> str:
    template_name = "codex-fuzz-swarm"
    raw_values = dict(values or {})
    allowed = {"shards", "concurrency", "name", "working_dir"}
    unknown = sorted(set(raw_values) - allowed)
    if unknown:
        supported = ", ".join(f"`{name}`" for name in sorted(allowed))
        unknown_display = ", ".join(f"`{name}`" for name in unknown)
        raise ValueError(
            f"template `{template_name}` does not recognize {unknown_display}; supported settings: {supported}"
        )

    shards = _parse_positive_template_int(
        template_name,
        "shards",
        raw_values.get("shards", str(_DEFAULT_FUZZ_SWARM_SHARDS)),
    )
    concurrency = _parse_positive_template_int(
        template_name,
        "concurrency",
        raw_values.get("concurrency", str(_DEFAULT_FUZZ_SWARM_CONCURRENCY)),
    )
    name = raw_values.get("name", f"codex-fuzz-swarm-{shards}").strip()
    if not name:
        raise ValueError(f"template `{template_name}` expects `name` to be a non-empty string")
    working_dir = raw_values.get("working_dir", f"./codex_fuzz_swarm_{shards}").strip()
    if not working_dir:
        raise ValueError(f"template `{template_name}` expects `working_dir` to be a non-empty string")

    suffix_width = max(1, len(str(shards - 1)))
    suffix_start = f"{0:0{suffix_width}d}"
    suffix_end = f"{shards - 1:0{suffix_width}d}"

    return Template(
        """# Configurable Codex fuzzing swarm
#
# This scaffold is the easiest way to right-size a Codex fuzz campaign for the
# machine and budget you actually have. Start with the default 32-shard layout,
# then scale it up or down with `agentflow init --set shards=...`.
#
# Usage:
#   agentflow init fuzz-swarm.yaml --template codex-fuzz-swarm
#   agentflow init fuzz-128.yaml --template codex-fuzz-swarm --set shards=128 --set concurrency=32
#   agentflow inspect fuzz-swarm.yaml
#   agentflow run fuzz-swarm.yaml --preflight never

name: $name
description: Configurable $shards-shard Codex fuzzing swarm with shared init, retries, per-shard workdirs, and a merge reducer.
working_dir: $working_dir
concurrency: $concurrency

nodes:
  - id: init
    agent: codex
    tools: read_write
    timeout_seconds: 60
    prompt: |
      Create the following directory structure silently if it does not already exist:
        mkdir -p docs crashes locks agents
      For each shard suffix from $suffix_start through $suffix_end, create agents/agent_<suffix>.
      If crashes/README.md is missing or empty, create it with:
        # Crash Registry
        | Timestamp | Shard | Target | Evidence | Artifact |
        |---|---|---|---|---|
      If docs/global_lessons.md is missing or empty, create it with:
        # Shared Lessons
        Use this file only for reusable campaign-wide notes.
      Then respond with exactly: INIT_OK

    success_criteria:
      - kind: output_contains
        value: INIT_OK

  - id: fuzzer
    fanout:
      count: $shards
      as: shard
    agent: codex
    model: gpt-5-codex
    tools: read_write
    depends_on: [init]
    target:
      kind: local
      cwd: agents/agent_{{ shard.suffix }}
    timeout_seconds: 3600
    retries: 2
    retry_backoff_seconds: 2
    extra_args:
      - "--search"
      - "-c"
      - 'model_reasoning_effort="high"'
    prompt: |
      You are Codex fuzz shard {{ shard.number }} of {{ shard.count }} in an authorized campaign.

      Shared workspace:
      - Root: {{ pipeline.working_dir }}
      - Shard dir: agents/agent_{{ shard.suffix }}
      - Crash registry: crashes/README.md
      - Shared notes: docs/global_lessons.md

      Shard contract:
      - Own only files under agents/agent_{{ shard.suffix }} unless you are appending to the shared docs or crash registry with locking.
      - Keep your inputs and notes deterministic so another engineer can replay them.
      - Use shard id `{{ shard.suffix }}` to vary corpus slices, seeds, flags, or target areas.
      - Focus on deep, high-signal failure modes rather than shallow lint or unit-test noise.
      - When you confirm a real issue, copy the minimal reproducer into `crashes/` and append a one-line entry to the registry.
      - When a target area looks exhausted, write concise lessons to `docs/`.
      - Continue searching until timeout.

  - id: merge
    agent: codex
    model: gpt-5-codex
    tools: read_only
    depends_on: [fuzzer]
    timeout_seconds: 300
    prompt: |
      Consolidate this $shards-shard fuzzing campaign into a maintainer handoff.
      Summarize the strongest crash families first, then recurring lessons, then quiet shards that need retargeting.

      {% for shard in fanouts.fuzzer.nodes %}
      ### {{ shard.id }} (status: {{ shard.status }})
      {{ shard.output or "(no output)" }}

      {% endfor %}
"""
    ).substitute(
        name=name,
        shards=shards,
        working_dir=working_dir,
        concurrency=concurrency,
        suffix_start=suffix_start,
        suffix_end=suffix_end,
    )


_BUNDLED_TEMPLATES = (
    BundledTemplate(
        name="pipeline",
        example_name="pipeline.yaml",
        description="Generic Codex/Claude/Kimi starter DAG.",
    ),
    BundledTemplate(
        name="codex-fanout-repo-sweep",
        example_name="codex-fanout-repo-sweep.yaml",
        description="Codex repo sweep that fans out one plan into 8 review shards and a final merge.",
    ),
    BundledTemplate(
        name="codex-fuzz-matrix",
        example_name="fuzz/codex-fuzz-matrix.yaml",
        description="Codex fuzz starter that uses `fanout.matrix` for target families and sanitizer/seed variants.",
    ),
    BundledTemplate(
        name="codex-fuzz-matrix-128",
        example_name="fuzz/codex-fuzz-matrix-128.yaml",
        description="128-shard Codex fuzz matrix that uses `fanout.matrix` for target families, strategies, and seed buckets.",
    ),
    BundledTemplate(
        name="codex-fuzz-swarm",
        example_name="fuzz/fuzz_codex_32.yaml",
        description="Configurable Codex fuzz swarm scaffold; defaults to 32 shards and scales cleanly to larger campaigns.",
        parameters=(
            BundledTemplateParameter(
                name="shards",
                description="Number of Codex fuzz workers to fan out.",
                default=str(_DEFAULT_FUZZ_SWARM_SHARDS),
            ),
            BundledTemplateParameter(
                name="concurrency",
                description="Maximum number of shards to run in parallel.",
                default=str(_DEFAULT_FUZZ_SWARM_CONCURRENCY),
            ),
            BundledTemplateParameter(
                name="name",
                description="Pipeline name override.",
                default="codex-fuzz-swarm-<shards>",
            ),
            BundledTemplateParameter(
                name="working_dir",
                description="Pipeline working directory override.",
                default="./codex_fuzz_swarm_<shards>",
            ),
        ),
    ),
    BundledTemplate(
        name="codex-fuzz-swarm-128",
        example_name="fuzz/fuzz_codex_128.yaml",
        description="128-shard Codex fuzzing swarm with init, retries, per-shard workdirs, and a merge reducer.",
    ),
    BundledTemplate(
        name="local-kimi-smoke",
        example_name="local-real-agents-kimi-smoke.yaml",
        description="Local Codex plus Claude-on-Kimi smoke DAG using `bootstrap: kimi`.",
    ),
    BundledTemplate(
        name="local-kimi-shell-init-smoke",
        example_name="local-real-agents-kimi-shell-init-smoke.yaml",
        description="Local Codex plus Claude-on-Kimi smoke DAG using explicit `shell_init: kimi`.",
    ),
    BundledTemplate(
        name="local-kimi-shell-wrapper-smoke",
        example_name="local-real-agents-kimi-shell-wrapper-smoke.yaml",
        description="Local Codex plus Claude-on-Kimi smoke DAG using an explicit `target.shell` Kimi wrapper.",
    ),
)

_BUNDLED_TEMPLATE_FILES = {template.name: template.example_name for template in _BUNDLED_TEMPLATES}
_BUNDLED_TEMPLATE_RENDERERS = {
    "codex-fuzz-swarm": _render_codex_fuzz_swarm_template,
}

DEFAULT_PIPELINE_YAML = """name: parallel-code-orchestration
description: Codex plans, Claude implements, and Kimi reviews in parallel before a final Codex merge.
working_dir: .
concurrency: 3
nodes:
  - id: plan
    agent: codex
    model: gpt-5-codex
    tools: read_only
    capture: final
    retries: 1
    retry_backoff_seconds: 1
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
"""


def load_default_pipeline_yaml() -> str:
    example_path = bundled_example_path("pipeline.yaml")
    if example_path.exists():
        return example_path.read_text(encoding="utf-8")
    return DEFAULT_PIPELINE_YAML


def bundled_example_path(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / "examples" / name


def bundled_templates() -> tuple[BundledTemplate, ...]:
    return _BUNDLED_TEMPLATES


def bundled_template_names() -> tuple[str, ...]:
    return tuple(template.name for template in bundled_templates())


def bundled_template_path(name: str) -> Path:
    try:
        example_name = _BUNDLED_TEMPLATE_FILES[name]
    except KeyError as exc:
        available = ", ".join(f"`{template}`" for template in bundled_template_names())
        raise ValueError(
            f"unknown bundled template `{name}` (available: {available}; see `agentflow templates`)"
        ) from exc
    return bundled_example_path(example_name)


def load_bundled_template_yaml(name: str, values: Mapping[str, str] | None = None) -> str:
    template_values = dict(values or {})
    if name == "pipeline":
        if template_values:
            raise ValueError("template `pipeline` does not accept `--set` values")
        return load_default_pipeline_yaml()

    renderer = _BUNDLED_TEMPLATE_RENDERERS.get(name)
    if renderer is not None:
        return renderer(template_values)

    template_path = bundled_template_path(name)
    if template_values:
        raise ValueError(f"template `{name}` does not accept `--set` values")

    return template_path.read_text(encoding="utf-8")


def default_smoke_pipeline_path() -> str:
    return str(bundled_example_path("local-real-agents-kimi-smoke.yaml"))
