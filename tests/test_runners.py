from __future__ import annotations

from pathlib import Path

import pytest

from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.runners.aws_lambda import AwsLambdaRunner
from agentflow.runners.container import ContainerRunner
from agentflow.runners.local import LocalRunner
from agentflow.specs import NodeSpec


def _paths(tmp_path: Path) -> ExecutionPaths:
    runtime_dir = tmp_path / ".runtime"
    return ExecutionPaths(
        host_workdir=tmp_path,
        host_runtime_dir=runtime_dir,
        target_workdir=str(tmp_path),
        target_runtime_dir=str(runtime_dir),
        app_root=tmp_path,
    )


@pytest.mark.asyncio
async def test_local_runner_uses_configured_shell(tmp_path: Path):
    shell_env = tmp_path / "shell.env"
    shell_env.write_text("myagent(){ printf 'shell wrapper ok\\n'; }\n", encoding="utf-8")

    node = NodeSpec.model_validate(
        {
            "id": "alpha",
            "agent": "codex",
            "prompt": "hi",
            "target": {"kind": "local", "shell": f"env BASH_ENV={shell_env} bash -c"},
        }
    )
    prepared = PreparedExecution(
        command=["myagent"],
        env={},
        cwd=str(tmp_path),
        trace_kind="codex",
    )

    result = await LocalRunner().execute(node, prepared, _paths(tmp_path), _noop_output, lambda: False)

    assert result.exit_code == 0
    assert result.stdout_lines == ["shell wrapper ok"]
    assert result.stderr_lines == []


@pytest.mark.asyncio
async def test_local_runner_shell_template_bootstraps_command(tmp_path: Path):
    shell_env = tmp_path / "shell.env"
    shell_env.write_text("kimi(){ export WRAPPED_VALUE='template ok'; }\n", encoding="utf-8")

    node = NodeSpec.model_validate(
        {
            "id": "beta",
            "agent": "codex",
            "prompt": "hi",
            "target": {
                "kind": "local",
                "shell": f"env BASH_ENV={shell_env} bash -c 'kimi; {{command}}'",
            },
        }
    )
    prepared = PreparedExecution(
        command=["bash", "-lc", 'printf "%s" "$WRAPPED_VALUE"'],
        env={},
        cwd=str(tmp_path),
        trace_kind="codex",
    )

    result = await LocalRunner().execute(node, prepared, _paths(tmp_path), _noop_output, lambda: False)

    assert result.exit_code == 0
    assert result.stdout_lines == ["template ok"]
    assert result.stderr_lines == []


@pytest.mark.asyncio
async def test_local_runner_shell_template_without_explicit_command_flag_defaults_to_c(tmp_path: Path):
    shell_env = tmp_path / "shell.env"
    shell_env.write_text("myagent(){ printf 'template default ok\\n'; }\n", encoding="utf-8")

    node = NodeSpec.model_validate(
        {
            "id": "beta-default-c",
            "agent": "codex",
            "prompt": "hi",
            "target": {
                "kind": "local",
                "shell": f"env BASH_ENV={shell_env} bash {{command}}",
            },
        }
    )
    prepared = PreparedExecution(
        command=["myagent"],
        env={},
        cwd=str(tmp_path),
        trace_kind="codex",
    )

    result = await LocalRunner().execute(node, prepared, _paths(tmp_path), _noop_output, lambda: False)

    assert result.exit_code == 0
    assert result.stdout_lines == ["template default ok"]
    assert result.stderr_lines == []


@pytest.mark.asyncio
async def test_local_runner_shell_init_runs_in_login_interactive_shell(tmp_path: Path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".hushlogin").write_text("", encoding="utf-8")
    (fake_home / ".profile").write_text(
        'if [ -f "$HOME/.bashrc" ]; then\n  . "$HOME/.bashrc"\nfi\n',
        encoding="utf-8",
    )
    (fake_home / ".bashrc").write_text(
        "case $- in\n"
        "  *i*) ;;\n"
        "  *) return;;\n"
        "esac\n"
        "kimi(){ export WRAPPED_VALUE=interactive-ok; }\n",
        encoding="utf-8",
    )

    node = NodeSpec.model_validate(
        {
            "id": "gamma",
            "agent": "claude",
            "prompt": "hi",
            "target": {
                "kind": "local",
                "shell": "bash",
                "shell_login": True,
                "shell_interactive": True,
                "shell_init": "kimi",
            },
        }
    )
    prepared = PreparedExecution(
        command=["bash", "-lc", 'printf "%s" "$WRAPPED_VALUE"'],
        env={"HOME": str(fake_home)},
        cwd=str(tmp_path),
        trace_kind="claude",
    )

    result = await LocalRunner().execute(node, prepared, _paths(tmp_path), _noop_output, lambda: False)

    assert result.exit_code == 0
    assert result.stdout_lines[-1] == "interactive-ok"
    assert result.stderr_lines == []


@pytest.mark.asyncio
async def test_local_runner_explicit_bash_lic_suppresses_job_control_noise(tmp_path: Path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".hushlogin").write_text("", encoding="utf-8")
    (fake_home / ".profile").write_text(
        """if [ -f "$HOME/.bashrc" ]; then
  . "$HOME/.bashrc"
fi
""",
        encoding="utf-8",
    )
    (fake_home / ".bashrc").write_text(
        """case $- in
  *i*) ;;
  *) return;;
esac
export WRAPPED_VALUE=explicit-lic-ok
""",
        encoding="utf-8",
    )

    node = NodeSpec.model_validate(
        {
            "id": "gamma-explicit-shell",
            "agent": "claude",
            "prompt": "hi",
            "target": {
                "kind": "local",
                "shell": "bash -lic",
            },
        }
    )
    prepared = PreparedExecution(
        command=["python3", "-c", 'import os; print(os.getenv("WRAPPED_VALUE", ""), end="")'],
        env={"HOME": str(fake_home)},
        cwd=str(tmp_path),
        trace_kind="claude",
    )

    result = await LocalRunner().execute(node, prepared, _paths(tmp_path), _noop_output, lambda: False)

    assert result.exit_code == 0
    assert result.stdout_lines[-1] == "explicit-lic-ok"
    assert result.stderr_lines == []


@pytest.mark.asyncio
async def test_local_runner_shell_init_failure_stops_wrapped_command(tmp_path: Path):
    node = NodeSpec.model_validate(
        {
            "id": "gamma-fail",
            "agent": "claude",
            "prompt": "hi",
            "target": {
                "kind": "local",
                "shell": "bash",
                "shell_init": "missing_helper",
            },
        }
    )
    prepared = PreparedExecution(
        command=["python3", "-c", 'print("wrapped command should not run", end="")'],
        env={},
        cwd=str(tmp_path),
        trace_kind="claude",
    )

    result = await LocalRunner().execute(node, prepared, _paths(tmp_path), _noop_output, lambda: False)

    assert result.exit_code != 0
    assert result.stdout_lines == []
    assert result.stderr_lines == ["bash: line 1: missing_helper: command not found"]


@pytest.mark.asyncio
async def test_local_runner_plain_shell_does_not_enable_login_mode(tmp_path: Path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".profile").write_text("export WRAPPED_VALUE=from-profile\n", encoding="utf-8")

    node = NodeSpec.model_validate(
        {
            "id": "delta",
            "agent": "codex",
            "prompt": "hi",
            "target": {
                "kind": "local",
                "shell": "bash",
            },
        }
    )
    prepared = PreparedExecution(
        command=["python3", "-c", "import os; print(os.getenv('WRAPPED_VALUE', 'missing'), end='')"],
        env={"HOME": str(fake_home)},
        cwd=str(tmp_path),
        trace_kind="codex",
    )

    result = await LocalRunner().execute(node, prepared, _paths(tmp_path), _noop_output, lambda: False)

    assert result.exit_code == 0
    assert result.stdout_lines == ["missing"]
    assert result.stderr_lines == []


def test_local_runner_plan_execution_includes_shell_wrapper(tmp_path: Path):
    node = NodeSpec.model_validate(
        {
            "id": "plan-local",
            "agent": "claude",
            "prompt": "hi",
            "target": {
                "kind": "local",
                "shell": "bash",
                "shell_login": True,
                "shell_interactive": True,
                "shell_init": "kimi",
            },
        }
    )
    prepared = PreparedExecution(
        command=["claude", "-p", "hello world"],
        env={"ANTHROPIC_BASE_URL": "https://example.test"},
        cwd=str(tmp_path),
        trace_kind="claude",
        runtime_files={"claude-mcp.json": "{}"},
    )

    plan = LocalRunner().plan_execution(node, prepared, _paths(tmp_path))

    assert plan.kind == "process"
    assert plan.command == ["bash", "-l", "-i", "-c", 'kimi && eval "$AGENTFLOW_TARGET_COMMAND"']
    assert plan.cwd == str(tmp_path)
    assert plan.runtime_files == ["claude-mcp.json"]
    assert plan.env == {
        "ANTHROPIC_BASE_URL": "https://example.test",
        "AGENTFLOW_TARGET_COMMAND": "claude -p 'hello world'",
    }


def test_container_runner_plan_execution_shows_host_and_container_context(tmp_path: Path):
    node = NodeSpec.model_validate(
        {
            "id": "plan-container",
            "agent": "codex",
            "prompt": "hi",
            "target": {
                "kind": "container",
                "image": "ghcr.io/example/agentflow:test",
                "extra_args": ["--network", "host"],
            },
        }
    )
    prepared = PreparedExecution(
        command=["codex", "exec", "ping"],
        env={"OPENAI_API_KEY": "secret"},
        cwd="/workspace/task",
        trace_kind="codex",
        runtime_files={"codex_home/config.toml": "model = 'gpt-5'\n"},
    )

    plan = ContainerRunner().plan_execution(node, prepared, _paths(tmp_path))

    assert plan.kind == "container"
    assert plan.command[:6] == [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{tmp_path}:/workspace",
        "-v",
    ]
    assert plan.cwd == str(tmp_path)
    assert plan.runtime_files == ["codex_home/config.toml"]
    assert plan.payload == {
        "image": "ghcr.io/example/agentflow:test",
        "engine": "docker",
        "workdir": "/workspace/task",
        "env": {"OPENAI_API_KEY": "secret"},
    }


def test_aws_lambda_runner_plan_execution_captures_invocation_request(tmp_path: Path):
    node = NodeSpec.model_validate(
        {
            "id": "plan-lambda",
            "agent": "kimi",
            "prompt": "hi",
            "timeout_seconds": 45,
            "target": {
                "kind": "aws_lambda",
                "function_name": "agentflow-runner",
                "region": "us-west-2",
                "qualifier": "live",
            },
        }
    )
    prepared = PreparedExecution(
        command=["python3", "-m", "agentflow.remote.kimi_bridge", "/tmp/request.json"],
        env={"KIMI_API_KEY": "secret"},
        cwd="/workspace/task",
        trace_kind="kimi",
        runtime_files={"kimi-request.json": "{}"},
        stdin="input",
    )

    plan = AwsLambdaRunner().plan_execution(node, prepared, _paths(tmp_path))

    assert plan.kind == "aws_lambda"
    assert plan.runtime_files == ["kimi-request.json"]
    assert plan.payload == {
        "function_name": "agentflow-runner",
        "region": "us-west-2",
        "qualifier": "live",
        "invocation_type": "RequestResponse",
        "request": {
            "command": ["python3", "-m", "agentflow.remote.kimi_bridge", "/tmp/request.json"],
            "env": {"KIMI_API_KEY": "secret"},
            "cwd": "/tmp/workspace",
            "stdin": "input",
            "timeout_seconds": 45,
            "runtime_files": {"kimi-request.json": "{}"},
        },
    }


async def _noop_output(stream_name: str, text: str) -> None:
    return None
