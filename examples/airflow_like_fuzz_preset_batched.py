from agentflow import DAG, codex, fanout_batches, fanout_preset


with DAG(
    "airflow-like-fuzz-preset-batched-128",
    description="Python-authored 128-shard browser-surface Codex fuzz campaign using the native preset helper.",
    working_dir="./codex_fuzz_python_preset_batched_128",
    concurrency=32,
    fail_fast=True,
    node_defaults={
        "tools": "read_only",
        "capture": "final",
    },
    agent_defaults={
        "codex": {
            "model": "gpt-5-codex",
            "retries": 1,
            "retry_backoff_seconds": 2,
        }
    },
) as dag:
    init = codex(
        task_id="init",
        tools="read_write",
        timeout_seconds=60,
        success_criteria=[
            {
                "kind": "output_contains",
                "value": "INIT_OK",
            }
        ],
        prompt=(
            "Create the following directory structure silently if it does not already exist:\n"
            "  mkdir -p docs crashes\n"
            "If crashes/README.md is missing or empty, create it with:\n"
            "  # Crash Registry\n"
            "  | Timestamp | Label | Surface | Evidence | Artifact |\n"
            "  |---|---|---|---|---|\n"
            "If docs/campaign_notes.md is missing or empty, create it with:\n"
            "  # Campaign Notes\n"
            "  Use this file only for cross-shard lessons and retargeting guidance.\n"
            "Then respond with exactly: INIT_OK"
        ),
    )

    fuzzer = codex(
        task_id="fuzzer",
        fanout=fanout_preset(
            preset="browser-surface",
            bucket_count=8,
            as_="shard",
        ),
        tools="read_write",
        target={"cwd": "{{ shard.workspace }}"},
        timeout_seconds=3600,
        retries=2,
        prompt=(
            "You are Codex fuzz shard {{ shard.number }} of {{ shard.count }} in an authorized browser-surface campaign.\n\n"
            "Campaign inputs:\n"
            "- Label: {{ shard.label }}\n"
            "- Target: {{ shard.target }}\n"
            "- Corpus family: {{ shard.corpus }}\n"
            "- Sanitizer: {{ shard.sanitizer }}\n"
            "- Strategy focus: {{ shard.focus }}\n"
            "- Seed bucket: {{ shard.bucket }}\n"
            "- Seed: {{ shard.seed }}\n"
            "- Workspace: {{ shard.workspace }}\n\n"
            "Shard contract:\n"
            "- Stay within {{ shard.workspace }} unless you are appending to the shared crash registry or notes.\n"
            "- Treat the preset-backed shard metadata as the source of truth for this run.\n"
            "- Prefer high-signal crashers, assertion failures, memory safety bugs, or state corruptions.\n"
            "- Record confirmed findings in `crashes/README.md` and copy minimal repro artifacts into `crashes/`.\n"
            "- Add short cross-shard lessons to `docs/campaign_notes.md` when they help nearby browser surfaces avoid duplicate work."
        ),
    )

    batch_merge = codex(
        task_id="batch_merge",
        fanout=fanout_batches("fuzzer", 16, as_="batch"),
        timeout_seconds=300,
        prompt=(
            "Prepare the maintainer handoff for browser batch {{ current.number }} of {{ current.count }}.\n\n"
            "Batch coverage:\n"
            "- Source group: {{ current.source_group }}\n"
            "- Total source shards: {{ current.source_count }}\n"
            "- Batch size: {{ current.scope.size }}\n"
            "- Shard range: {{ current.start_number }} through {{ current.end_number }}\n"
            "- Shard ids: {{ current.scope.ids | join(', ') }}\n"
            "- Completed shards: {{ current.scope.summary.completed }}\n"
            "- Failed shards: {{ current.scope.summary.failed }}\n"
            "- Silent shards: {{ current.scope.summary.without_output }}\n\n"
            "Group findings by browser surface first, then by sanitizer and focus, and end with quiet shards that need retargeting.\n\n"
            "{% for shard in current.scope.with_output.nodes %}\n"
            "### {{ shard.label }} :: {{ shard.node_id }} (status: {{ shard.status }})\n"
            "Workspace: {{ shard.workspace }}\n"
            "{{ shard.output }}\n\n"
            "{% endfor %}"
            "{% if current.scope.failed.size %}\n"
            "Failed browser shards:\n"
            "{% for shard in current.scope.failed.nodes %}\n"
            "- {{ shard.id }} :: {{ shard.label }}\n"
            "{% endfor %}"
            "{% endif %}"
            "{% if not current.scope.with_output.size %}\n"
            "No shard in this batch produced reducer-ready output. Say that explicitly and use the failed shard list to suggest retargeting.\n"
            "{% endif %}"
        ),
    )

    merge = codex(
        task_id="merge",
        timeout_seconds=300,
        prompt=(
            "Consolidate this 128-shard browser-surface fuzz campaign into a maintainer handoff.\n"
            "Start with campaign-wide status, then the strongest batch-level findings, and end with quiet or failed shards that need retargeting.\n\n"
            "Campaign status:\n"
            "- Total shards: {{ fanouts.fuzzer.size }}\n"
            "- Completed shards: {{ fanouts.fuzzer.summary.completed }}\n"
            "- Failed shards: {{ fanouts.fuzzer.summary.failed }}\n"
            "- Silent shards: {{ fanouts.fuzzer.summary.without_output }}\n"
            "- Batch reducers completed: {{ fanouts.batch_merge.summary.completed }} / {{ fanouts.batch_merge.size }}\n\n"
            "{% for batch in fanouts.batch_merge.with_output.nodes %}\n"
            "## Batch {{ batch.number }} :: {{ batch.start_number }}-{{ batch.end_number }} (status: {{ batch.status }})\n"
            "{{ batch.output }}\n\n"
            "{% endfor %}"
            "{% if fanouts.batch_merge.without_output.size %}\n"
            "Batch reducers needing attention:\n"
            "{% for batch in fanouts.batch_merge.without_output.nodes %}\n"
            "- {{ batch.id }} :: shards {{ batch.start_number }}-{{ batch.end_number }} (status: {{ batch.status }})\n"
            "{% endfor %}"
            "{% endif %}"
        ),
    )

    init >> fuzzer
    fuzzer >> batch_merge
    batch_merge >> merge

print(dag.to_yaml(), end="")
