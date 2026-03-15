from agentflow.defaults import (
    bundled_template_names,
    bundled_template_path,
    bundled_templates,
    default_smoke_pipeline_path,
    load_bundled_template_yaml,
)
from agentflow.loader import load_pipeline_from_path


def test_bundled_templates_expose_descriptions_and_example_files():
    templates = bundled_templates()

    assert tuple(template.name for template in templates) == bundled_template_names()

    by_name = {template.name: template for template in templates}
    assert by_name["pipeline"].example_name == "pipeline.yaml"
    assert by_name["pipeline"].description == "Generic Codex/Claude/Kimi starter DAG."
    assert by_name["codex-fanout-repo-sweep"].example_name == "codex-fanout-repo-sweep.yaml"
    assert "8 review shards" in by_name["codex-fanout-repo-sweep"].description
    assert by_name["codex-fuzz-matrix"].example_name == "fuzz/codex-fuzz-matrix.yaml"
    assert "fanout.matrix" in by_name["codex-fuzz-matrix"].description
    assert by_name["codex-fuzz-matrix-128"].example_name == "fuzz/codex-fuzz-matrix-128.yaml"
    assert "128-shard Codex fuzz matrix" in by_name["codex-fuzz-matrix-128"].description
    assert by_name["codex-fuzz-swarm"].example_name == "fuzz/fuzz_codex_32.yaml"
    assert "defaults to 32 shards" in by_name["codex-fuzz-swarm"].description
    assert tuple(parameter.name for parameter in by_name["codex-fuzz-swarm"].parameters) == (
        "shards",
        "concurrency",
        "name",
        "working_dir",
    )
    assert by_name["codex-fuzz-swarm-128"].example_name == "fuzz/fuzz_codex_128.yaml"
    assert "128-shard Codex fuzzing swarm" in by_name["codex-fuzz-swarm-128"].description
    assert by_name["local-kimi-smoke"].example_name == "local-real-agents-kimi-smoke.yaml"
    assert "bootstrap: kimi" in by_name["local-kimi-smoke"].description
    assert by_name["local-kimi-shell-init-smoke"].example_name == "local-real-agents-kimi-shell-init-smoke.yaml"
    assert "shell_init: kimi" in by_name["local-kimi-shell-init-smoke"].description
    assert by_name["local-kimi-shell-wrapper-smoke"].example_name == "local-real-agents-kimi-shell-wrapper-smoke.yaml"
    assert "target.shell" in by_name["local-kimi-shell-wrapper-smoke"].description


def test_bundled_smoke_pipeline_runs_both_agents_in_shared_kimi_bootstrap():
    pipeline = load_pipeline_from_path(default_smoke_pipeline_path())
    codex_node = next(node for node in pipeline.nodes if node.id == "codex_plan")
    claude_node = next(node for node in pipeline.nodes if node.id == "claude_review")

    assert pipeline.concurrency == 2
    assert codex_node.target.kind == "local"
    assert codex_node.target.bootstrap == "kimi"
    assert codex_node.target.shell == "bash"
    assert codex_node.target.shell_login is True
    assert codex_node.target.shell_interactive is True
    assert codex_node.target.shell_init == ["command -v kimi >/dev/null 2>&1", "kimi"]
    assert codex_node.depends_on == []
    assert claude_node.target.bootstrap == "kimi"
    assert claude_node.target.shell_init == ["command -v kimi >/dev/null 2>&1", "kimi"]
    assert claude_node.depends_on == []


def test_bundled_shell_init_smoke_template_is_available():
    assert "local-kimi-shell-init-smoke" in bundled_template_names()
    assert load_bundled_template_yaml("local-kimi-shell-init-smoke").startswith(
        "name: local-real-agents-kimi-shell-init-smoke\n"
    )


def test_bundled_shell_init_smoke_pipeline_runs_both_agents_in_explicit_shell_init_mode():
    pipeline = load_pipeline_from_path(str(bundled_template_path("local-kimi-shell-init-smoke")))
    codex_node = next(node for node in pipeline.nodes if node.id == "codex_plan")
    claude_node = next(node for node in pipeline.nodes if node.id == "claude_review")

    assert pipeline.concurrency == 2
    assert codex_node.target.kind == "local"
    assert codex_node.target.bootstrap is None
    assert codex_node.target.shell == "bash"
    assert codex_node.target.shell_login is True
    assert codex_node.target.shell_interactive is True
    assert codex_node.target.shell_init == "kimi"
    assert codex_node.depends_on == []
    assert claude_node.target.bootstrap is None
    assert claude_node.target.shell_init == "kimi"
    assert claude_node.depends_on == []


def test_bundled_shell_wrapper_smoke_template_is_available():
    assert "local-kimi-shell-wrapper-smoke" in bundled_template_names()
    assert load_bundled_template_yaml("local-kimi-shell-wrapper-smoke").startswith(
        "name: local-real-agents-kimi-shell-wrapper-smoke\n"
    )


def test_bundled_codex_fanout_repo_sweep_template_is_available():
    assert "codex-fanout-repo-sweep" in bundled_template_names()
    assert load_bundled_template_yaml("codex-fanout-repo-sweep").startswith(
        "name: codex-fanout-repo-sweep\n"
    )


def test_bundled_codex_fuzz_matrix_template_is_available():
    assert "codex-fuzz-matrix" in bundled_template_names()
    assert "\nname: codex-fuzz-matrix\n" in f"\n{load_bundled_template_yaml('codex-fuzz-matrix')}"


def test_bundled_codex_fuzz_matrix_128_template_is_available():
    assert "codex-fuzz-matrix-128" in bundled_template_names()
    assert "\nname: codex-fuzz-matrix-128\n" in f"\n{load_bundled_template_yaml('codex-fuzz-matrix-128')}"


def test_bundled_codex_fuzz_swarm_template_is_available():
    assert "codex-fuzz-swarm" in bundled_template_names()
    assert "\nname: codex-fuzz-swarm-32\n" in f"\n{load_bundled_template_yaml('codex-fuzz-swarm')}"


def test_bundled_codex_fuzz_swarm_template_matches_default_example_file():
    expected = bundled_template_path("codex-fuzz-swarm").read_text(encoding="utf-8")

    assert load_bundled_template_yaml("codex-fuzz-swarm") == expected


def test_bundled_codex_fuzz_swarm_template_accepts_overrides_and_preserves_runtime_placeholders(tmp_path):
    rendered = load_bundled_template_yaml(
        "codex-fuzz-swarm",
        values={
            "shards": "128",
            "concurrency": "24",
            "name": "custom-fuzz-128",
            "working_dir": "./custom_swarm",
        },
    )

    assert "name: custom-fuzz-128\n" in rendered
    assert "working_dir: ./custom_swarm\n" in rendered
    assert "concurrency: 24\n" in rendered
    assert "For each shard suffix from 000 through 127" in rendered
    assert "count: 128" in rendered
    assert "{{ shard.number }}" in rendered
    assert "{{ pipeline.working_dir }}" in rendered
    assert "{% for shard in fanouts.fuzzer.nodes %}" in rendered

    pipeline_path = tmp_path / "custom-fuzz.yaml"
    pipeline_path.write_text(rendered, encoding="utf-8")
    pipeline = load_pipeline_from_path(str(pipeline_path))

    assert pipeline.concurrency == 24
    assert len(pipeline.fanouts["fuzzer"]) == 128
    assert pipeline.fanouts["fuzzer"][:3] == ["fuzzer_000", "fuzzer_001", "fuzzer_002"]
    assert pipeline.fanouts["fuzzer"][-1] == "fuzzer_127"
    assert pipeline.node_map["merge"].depends_on[0] == "fuzzer_000"
    assert pipeline.node_map["merge"].depends_on[-1] == "fuzzer_127"
    assert "000 through 127" in pipeline.node_map["init"].prompt


def test_bundled_codex_fuzz_matrix_pipeline_expands_matrix_fanout_nodes():
    pipeline = load_pipeline_from_path(str(bundled_template_path("codex-fuzz-matrix")))

    assert pipeline.concurrency == 8
    assert pipeline.fanouts == {
        "fuzzer": ["fuzzer_0", "fuzzer_1", "fuzzer_2", "fuzzer_3", "fuzzer_4", "fuzzer_5", "fuzzer_6", "fuzzer_7"]
    }
    assert [node.id for node in pipeline.nodes[:3]] == ["init", "fuzzer_0", "fuzzer_1"]
    assert pipeline.node_map["fuzzer_0"].prompt.startswith("You are Codex fuzz shard 1 of 8.")
    assert "Target: libpng" in pipeline.node_map["fuzzer_0"].prompt
    assert pipeline.node_map["fuzzer_0"].fanout_member is not None
    assert pipeline.node_map["fuzzer_0"].fanout_member["family"] == {"target": "libpng", "corpus": "png"}
    assert pipeline.node_map["fuzzer_0"].fanout_member["variant"] == {"sanitizer": "asan", "seed": 1101}
    assert pipeline.node_map["fuzzer_0"].target.cwd.endswith("codex_fuzz_matrix/agents/libpng_asan_0")
    assert pipeline.node_map["merge"].depends_on == [
        "fuzzer_0",
        "fuzzer_1",
        "fuzzer_2",
        "fuzzer_3",
        "fuzzer_4",
        "fuzzer_5",
        "fuzzer_6",
        "fuzzer_7",
    ]


def test_bundled_codex_fuzz_matrix_128_pipeline_expands_into_128_concrete_nodes():
    pipeline = load_pipeline_from_path(str(bundled_template_path("codex-fuzz-matrix-128")))

    assert pipeline.concurrency == 32
    assert len(pipeline.fanouts["fuzzer"]) == 128
    assert pipeline.fanouts["fuzzer"][:3] == ["fuzzer_000", "fuzzer_001", "fuzzer_002"]
    assert pipeline.fanouts["fuzzer"][-1] == "fuzzer_127"
    assert pipeline.node_map["fuzzer_000"].fanout_member is not None
    assert pipeline.node_map["fuzzer_000"].fanout_member["target"] == "libpng"
    assert pipeline.node_map["fuzzer_000"].fanout_member["sanitizer"] == "asan"
    assert pipeline.node_map["fuzzer_000"].target.cwd.endswith("codex_fuzz_matrix_128/agents/libpng_asan_seed_a_000")
    assert pipeline.node_map["merge"].depends_on[0] == "fuzzer_000"
    assert pipeline.node_map["merge"].depends_on[-1] == "fuzzer_127"


def test_bundled_codex_fanout_repo_sweep_pipeline_expands_into_concrete_nodes():
    pipeline = load_pipeline_from_path(str(bundled_template_path("codex-fanout-repo-sweep")))

    assert pipeline.concurrency == 8
    assert pipeline.fanouts == {
        "sweep": ["sweep_0", "sweep_1", "sweep_2", "sweep_3", "sweep_4", "sweep_5", "sweep_6", "sweep_7"]
    }
    assert [node.id for node in pipeline.nodes[:3]] == ["prepare", "sweep_0", "sweep_1"]
    assert pipeline.node_map["merge"].depends_on == [
        "sweep_0",
        "sweep_1",
        "sweep_2",
        "sweep_3",
        "sweep_4",
        "sweep_5",
        "sweep_6",
        "sweep_7",
    ]


def test_bundled_codex_fuzz_swarm_128_template_is_available():
    assert "codex-fuzz-swarm-128" in bundled_template_names()
    assert "\nname: codex-fuzz-swarm-128\n" in f"\n{load_bundled_template_yaml('codex-fuzz-swarm-128')}"


def test_bundled_codex_fuzz_swarm_128_pipeline_expands_into_128_concrete_nodes():
    pipeline = load_pipeline_from_path(str(bundled_template_path("codex-fuzz-swarm-128")))

    assert pipeline.concurrency == 32
    assert len(pipeline.fanouts["fuzzer"]) == 128
    assert pipeline.fanouts["fuzzer"][:3] == ["fuzzer_000", "fuzzer_001", "fuzzer_002"]
    assert pipeline.fanouts["fuzzer"][-1] == "fuzzer_127"
    assert pipeline.node_map["merge"].depends_on[0] == "fuzzer_000"
    assert pipeline.node_map["merge"].depends_on[-1] == "fuzzer_127"


def test_bundled_shell_wrapper_smoke_pipeline_runs_both_agents_in_explicit_shell_wrapper_mode():
    pipeline = load_pipeline_from_path(str(bundled_template_path("local-kimi-shell-wrapper-smoke")))
    codex_node = next(node for node in pipeline.nodes if node.id == "codex_plan")
    claude_node = next(node for node in pipeline.nodes if node.id == "claude_review")

    assert pipeline.concurrency == 2
    assert codex_node.target.kind == "local"
    assert codex_node.target.bootstrap is None
    assert codex_node.target.shell == "bash -lic 'command -v kimi >/dev/null 2>&1 && kimi && {command}'"
    assert codex_node.target.shell_login is False
    assert codex_node.target.shell_interactive is False
    assert codex_node.target.shell_init is None
    assert codex_node.depends_on == []
    assert claude_node.target.bootstrap is None
    assert claude_node.target.shell == "bash -lic 'command -v kimi >/dev/null 2>&1 && kimi && {command}'"
    assert claude_node.target.shell_init is None
    assert claude_node.depends_on == []
