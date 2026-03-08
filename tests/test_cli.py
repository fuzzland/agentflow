from __future__ import annotations

import json
from types import SimpleNamespace

from typer.testing import CliRunner

import agentflow.cli
from agentflow.cli import app
from agentflow.doctor import DoctorCheck, DoctorReport

runner = CliRunner()


def _capture_pipeline_loader(captured: dict[str, object], fake_pipeline: object):
    def _load(path: str):
        captured["loaded_path"] = path
        return fake_pipeline

    return _load


def _doctor_report(status: str = "ok", detail: str = "ready") -> DoctorReport:
    check_status = "failed" if status == "failed" else "ok"
    return DoctorReport(
        status=status,
        checks=[DoctorCheck(name="kimi_shell_helper", status=check_status, detail=detail)],
    )


def test_validate_command_outputs_normalized_pipeline(tmp_path):
    pipeline_path = tmp_path / "pipeline.yaml"
    pipeline_path.write_text(
        """name: cli
working_dir: .
nodes:
  - id: alpha
    agent: codex
    prompt: hi
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["validate", str(pipeline_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["name"] == "cli"
    assert payload["nodes"][0]["id"] == "alpha"


def test_validate_resolves_working_dir_relative_to_pipeline_file(tmp_path, monkeypatch):
    pipeline_dir = tmp_path / "pipelines"
    pipeline_dir.mkdir()
    workdir = pipeline_dir / "workspace"
    workdir.mkdir()
    task_dir = workdir / "task"
    task_dir.mkdir()
    pipeline_path = pipeline_dir / "pipeline.yaml"
    pipeline_path.write_text(
        """name: cli
working_dir: workspace
nodes:
  - id: alpha
    agent: codex
    prompt: hi
    target:
      kind: local
      cwd: task
""",
        encoding="utf-8",
    )
    other_dir = tmp_path / "elsewhere"
    other_dir.mkdir()
    monkeypatch.chdir(other_dir)

    result = runner.invoke(app, ["validate", str(pipeline_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["working_dir"] == str(workdir.resolve())
    assert payload["nodes"][0]["target"]["cwd"] == str(task_dir.resolve())


def test_serve_uses_runtime_env_vars(monkeypatch):
    captured: dict[str, object] = {}

    monkeypatch.setenv("AGENTFLOW_RUNS_DIR", "/tmp/agentflow-env-runs")
    monkeypatch.setenv("AGENTFLOW_MAX_CONCURRENT_RUNS", "7")

    def fake_build_runtime(runs_dir: str, max_concurrent_runs: int):
        captured["runs_dir"] = runs_dir
        captured["max_concurrent_runs"] = max_concurrent_runs
        return object(), object()

    monkeypatch.setattr(agentflow.cli, "_build_runtime", fake_build_runtime)
    monkeypatch.setattr(agentflow.cli, "create_app", lambda store, orchestrator: "fake-app")
    monkeypatch.setattr(agentflow.cli.uvicorn, "run", lambda app, host, port: captured.update({"app": app, "host": host, "port": port}))

    result = runner.invoke(app, ["serve"])

    assert result.exit_code == 0
    assert captured == {
        "runs_dir": "/tmp/agentflow-env-runs",
        "max_concurrent_runs": 7,
        "app": "fake-app",
        "host": "127.0.0.1",
        "port": 8000,
    }


def test_run_uses_runtime_env_vars(monkeypatch):
    captured: dict[str, object] = {}

    monkeypatch.setenv("AGENTFLOW_RUNS_DIR", "/tmp/agentflow-env-runs")
    monkeypatch.setenv("AGENTFLOW_MAX_CONCURRENT_RUNS", "9")

    class FakeOrchestrator:
        async def submit(self, pipeline: object):
            captured["submitted_pipeline"] = pipeline
            return SimpleNamespace(id="run-123")

        async def wait(self, run_id: str, timeout: float | None = None):
            captured["wait_run_id"] = run_id
            captured["wait_timeout"] = timeout
            return SimpleNamespace(
                status=SimpleNamespace(value="completed"),
                model_dump=lambda mode="json": {"id": run_id, "status": "completed"},
            )

    def fake_build_runtime(runs_dir: str, max_concurrent_runs: int):
        captured["runs_dir"] = runs_dir
        captured["max_concurrent_runs"] = max_concurrent_runs
        return object(), FakeOrchestrator()

    fake_pipeline = object()
    monkeypatch.setattr(agentflow.cli, "_build_runtime", fake_build_runtime)
    monkeypatch.setattr(agentflow.cli, "load_pipeline_from_path", lambda path: fake_pipeline)

    result = runner.invoke(app, ["run", "pipeline.yaml"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"id": "run-123", "status": "completed"}
    assert captured["runs_dir"] == "/tmp/agentflow-env-runs"
    assert captured["max_concurrent_runs"] == 9
    assert captured["submitted_pipeline"] is fake_pipeline
    assert captured["wait_run_id"] == "run-123"
    assert captured["wait_timeout"] is None


def test_smoke_uses_bundled_pipeline_by_default(monkeypatch):
    captured: dict[str, object] = {}

    monkeypatch.setenv("AGENTFLOW_RUNS_DIR", "/tmp/agentflow-smoke-runs")
    monkeypatch.setenv("AGENTFLOW_MAX_CONCURRENT_RUNS", "5")

    class FakeOrchestrator:
        async def submit(self, pipeline: object):
            captured["submitted_pipeline"] = pipeline
            return SimpleNamespace(id="smoke-123")

        async def wait(self, run_id: str, timeout: float | None = None):
            captured["wait_run_id"] = run_id
            captured["wait_timeout"] = timeout
            return SimpleNamespace(
                status=SimpleNamespace(value="completed"),
                model_dump=lambda mode="json": {"id": run_id, "status": "completed"},
            )

    def fake_build_runtime(runs_dir: str, max_concurrent_runs: int):
        captured["runs_dir"] = runs_dir
        captured["max_concurrent_runs"] = max_concurrent_runs
        return object(), FakeOrchestrator()

    fake_pipeline = object()
    monkeypatch.setattr(agentflow.cli, "build_local_smoke_doctor_report", lambda: _doctor_report())
    monkeypatch.setattr(agentflow.cli, "_build_runtime", fake_build_runtime)
    monkeypatch.setattr(agentflow.cli, "default_smoke_pipeline_path", lambda: "examples/local-real-agents-kimi-smoke.yaml")
    monkeypatch.setattr(agentflow.cli, "load_pipeline_from_path", _capture_pipeline_loader(captured, fake_pipeline))

    result = runner.invoke(app, ["smoke"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"id": "smoke-123", "status": "completed"}
    assert captured["loaded_path"] == "examples/local-real-agents-kimi-smoke.yaml"
    assert captured["runs_dir"] == "/tmp/agentflow-smoke-runs"
    assert captured["max_concurrent_runs"] == 5
    assert captured["submitted_pipeline"] is fake_pipeline
    assert captured["wait_run_id"] == "smoke-123"
    assert captured["wait_timeout"] is None


def test_smoke_accepts_explicit_pipeline_path(monkeypatch):
    captured: dict[str, object] = {}

    class FakeOrchestrator:
        async def submit(self, pipeline: object):
            captured["submitted_pipeline"] = pipeline
            return SimpleNamespace(id="smoke-custom")

        async def wait(self, run_id: str, timeout: float | None = None):
            captured["wait_run_id"] = run_id
            captured["wait_timeout"] = timeout
            return SimpleNamespace(
                status=SimpleNamespace(value="completed"),
                model_dump=lambda mode="json": {"id": run_id, "status": "completed"},
            )

    monkeypatch.setattr(agentflow.cli, "build_local_smoke_doctor_report", lambda: (_ for _ in ()).throw(AssertionError("doctor should not run")))
    monkeypatch.setattr(agentflow.cli, "_build_runtime", lambda runs_dir, max_concurrent_runs: (object(), FakeOrchestrator()))
    fake_pipeline = object()
    monkeypatch.setattr(agentflow.cli, "load_pipeline_from_path", _capture_pipeline_loader(captured, fake_pipeline))

    result = runner.invoke(app, ["smoke", "custom-smoke.yaml"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"id": "smoke-custom", "status": "completed"}
    assert captured["loaded_path"] == "custom-smoke.yaml"
    assert captured["submitted_pipeline"] is fake_pipeline
    assert captured["wait_run_id"] == "smoke-custom"
    assert captured["wait_timeout"] is None


def test_doctor_outputs_json_report(monkeypatch):
    monkeypatch.setattr(agentflow.cli, "build_local_smoke_doctor_report", lambda: _doctor_report())

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "status": "ok",
        "checks": [{"name": "kimi_shell_helper", "status": "ok", "detail": "ready"}],
    }


def test_smoke_stops_when_bundled_preflight_fails(monkeypatch):
    monkeypatch.setattr(agentflow.cli, "build_local_smoke_doctor_report", lambda: _doctor_report(status="failed", detail="missing"))
    monkeypatch.setattr(agentflow.cli, "default_smoke_pipeline_path", lambda: "examples/local-real-agents-kimi-smoke.yaml")
    monkeypatch.setattr(agentflow.cli, "load_pipeline_from_path", lambda path: (_ for _ in ()).throw(AssertionError("pipeline should not load")))

    result = runner.invoke(app, ["smoke"])

    assert result.exit_code == 1
    assert json.loads(result.stdout) == {
        "status": "failed",
        "checks": [{"name": "kimi_shell_helper", "status": "failed", "detail": "missing"}],
    }
