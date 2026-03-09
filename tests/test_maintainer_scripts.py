from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path


def _write_executable(path: Path, body: str) -> None:
    path.write_text(f"#!/usr/bin/env bash\nset -euo pipefail\n{body}", encoding="utf-8")
    path.chmod(0o755)


def _write_fake_agentflow_module(root: Path, body: str) -> Path:
    package_dir = root / "agentflow"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "__main__.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return root


def _copy_script(source: Path, destination: Path) -> Path:
    destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    destination.chmod(0o755)
    return destination


def _repo_python(repo_root: Path) -> str:
    python_bin = repo_root / ".venv" / "bin" / "python"
    return str(python_bin if python_bin.exists() else Path(sys.executable))


def _run_script(script_path: Path, *, repo_root: Path, home: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(script_path)],
        capture_output=True,
        cwd=repo_root,
        env={
            **os.environ,
            "AGENTFLOW_PYTHON": _repo_python(repo_root),
            "HOME": str(home),
            **env,
        },
        text=True,
        timeout=5,
    )


def _write_fake_shell_home(home: Path, *, kimi_body: str, startup_file: str = ".profile") -> None:
    bin_dir = home / "bin"
    bin_dir.mkdir(parents=True)
    (home / startup_file).write_text(
        'if [ -f "$HOME/.bashrc" ]; then . "$HOME/.bashrc"; fi\n',
        encoding="utf-8",
    )
    (home / ".bashrc").write_text(
        'export PATH="$HOME/bin:$PATH"\n'
        "kimi() {\n"
        f"{textwrap.indent(kimi_body.rstrip(), '  ')}\n"
        "}\n",
        encoding="utf-8",
    )
    _write_executable(
        bin_dir / "codex",
        'if [ "${1:-}" = "login" ] && [ "${2:-}" = "status" ]; then\n'
        "  exit 0\n"
        "fi\n"
        'printf "codex-cli 0.0.0\\n"\n',
    )
    _write_executable(bin_dir / "claude", 'printf "Claude Code 0.0.0\\n"\n')


def test_verify_local_kimi_shell_script_reports_bash_profile_startup_when_present(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _write_fake_shell_home(
        home,
        startup_file=".bash_profile",
        kimi_body=(
            "export ANTHROPIC_BASE_URL=https://api.kimi.com/coding/\n"
            "export ANTHROPIC_API_KEY=test-kimi-key\n"
        ),
    )

    repo_root = Path(__file__).resolve().parents[1]
    script_path = repo_root / "scripts" / "verify-local-kimi-shell.sh"

    completed = _run_script(script_path, repo_root=repo_root, home=home, OPENAI_API_KEY="")

    assert completed.returncode == 0
    assert "~/.bash_profile: present" in completed.stdout
    assert "~/.bash_login: missing" in completed.stdout
    assert "~/.profile: missing" in completed.stdout
    assert "bash login startup: ~/.bash_profile -> ~/.bashrc" in completed.stdout
    assert "bash login bridge: not needed" in completed.stdout
    assert "ANTHROPIC_BASE_URL=https://api.kimi.com/coding/" in completed.stdout
    assert "codex auth: login" in completed.stdout
    assert f"codex: {home / 'bin' / 'codex'} (codex-cli 0.0.0)" in completed.stdout
    assert f"claude: {home / 'bin' / 'claude'} (Claude Code 0.0.0)" in completed.stdout
    assert completed.stderr == ""


def test_verify_local_kimi_shell_script_requires_kimi_to_export_anthropic_env(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _write_fake_shell_home(home, kimi_body=":")

    repo_root = Path(__file__).resolve().parents[1]
    script_path = repo_root / "scripts" / "verify-local-kimi-shell.sh"

    completed = _run_script(
        script_path,
        repo_root=repo_root,
        home=home,
        ANTHROPIC_API_KEY="ambient-kimi-key",
        ANTHROPIC_BASE_URL="https://api.kimi.com/coding/",
        OPENAI_API_KEY="",
    )

    assert completed.returncode == 1
    assert "~/.profile: present" in completed.stdout
    assert "kimi did not export ANTHROPIC_API_KEY" in completed.stderr


def test_verify_custom_local_kimi_shell_init_wrapper_forces_shell_init_mode(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()

    wrapper_path = _copy_script(
        repo_root / "scripts" / "verify-custom-local-kimi-shell-init.sh",
        scripts_dir / "verify-custom-local-kimi-shell-init.sh",
    )
    _write_executable(
        scripts_dir / "verify-custom-local-kimi-pipeline.sh",
        'printf "%s\\n" "${AGENTFLOW_KIMI_PIPELINE_MODE:-}"\n',
    )

    completed = subprocess.run(
        ["bash", str(wrapper_path)],
        capture_output=True,
        cwd=tmp_path,
        env={**os.environ, "AGENTFLOW_KIMI_PIPELINE_MODE": "shell-wrapper"},
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == "shell-init"
    assert completed.stderr == ""


def test_verify_local_kimi_shell_script_times_out_when_kimi_hangs(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _write_fake_shell_home(home, kimi_body="sleep 5\n")

    repo_root = Path(__file__).resolve().parents[1]
    script_path = repo_root / "scripts" / "verify-local-kimi-shell.sh"

    started_at = time.monotonic()
    completed = _run_script(
        script_path,
        repo_root=repo_root,
        home=home,
        AGENTFLOW_LOCAL_VERIFY_TIMEOUT_SECONDS="0.2",
    )
    elapsed = time.monotonic() - started_at

    assert completed.returncode == 124
    assert "~/.profile: present" in completed.stdout
    assert "Timed out after 0.2s: env" in completed.stderr
    assert elapsed < 3


def test_verify_custom_local_kimi_run_script_times_out_when_agentflow_hangs(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()

    run_path = _copy_script(
        repo_root / "scripts" / "verify-custom-local-kimi-run.sh",
        scripts_dir / "verify-custom-local-kimi-run.sh",
    )
    _copy_script(
        repo_root / "scripts" / "custom-local-kimi-helpers.sh",
        scripts_dir / "custom-local-kimi-helpers.sh",
    )
    fake_pythonpath = _write_fake_agentflow_module(
        tmp_path / "fake-pythonpath",
        """
        from __future__ import annotations

        import sys
        import time

        if len(sys.argv) > 1 and sys.argv[1] == "run":
            print("run-stdout", flush=True)
            print("run-stderr", file=sys.stderr, flush=True)
            time.sleep(5)
        """,
    )

    started_at = time.monotonic()
    completed = subprocess.run(
        ["bash", str(run_path)],
        capture_output=True,
        cwd=tmp_path,
        env={
            **os.environ,
            "AGENTFLOW_PYTHON": sys.executable,
            "PYTHONPATH": str(fake_pythonpath),
            "AGENTFLOW_LOCAL_VERIFY_TIMEOUT_SECONDS": "0.2",
        },
        text=True,
        timeout=5,
    )
    elapsed = time.monotonic() - started_at

    assert completed.returncode == 124
    assert "custom run pipeline path:" in completed.stdout
    assert "Timed out after 0.2s:" in completed.stderr
    assert "agentflow run stderr:" in completed.stderr
    assert "run-stderr" in completed.stderr
    assert "agentflow run stdout:" in completed.stderr
    assert "run-stdout" in completed.stderr
    assert elapsed < 3


def test_verify_local_kimi_stack_script_runs_steps_in_expected_order(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()

    stack_path = _copy_script(
        repo_root / "scripts" / "verify-local-kimi-stack.sh",
        scripts_dir / "verify-local-kimi-stack.sh",
    )
    _copy_script(
        repo_root / "scripts" / "custom-local-kimi-helpers.sh",
        scripts_dir / "custom-local-kimi-helpers.sh",
    )
    log_path = tmp_path / "calls.log"
    fake_pythonpath = _write_fake_agentflow_module(
        tmp_path / "fake-pythonpath",
        """
        from __future__ import annotations

        import os
        import sys

        with open(os.environ["AGENTFLOW_TEST_LOG"], "a", encoding="utf-8") as handle:
            handle.write(f"agentflow:{' '.join(sys.argv[1:])}\\n")
        """,
    )

    for script_name in (
        "verify-local-kimi-shell.sh",
        "verify-custom-local-kimi-doctor.sh",
        "verify-custom-local-kimi-inspect.sh",
        "verify-custom-local-kimi-pipeline.sh",
        "verify-custom-local-kimi-shell-init.sh",
        "verify-custom-local-kimi-run.sh",
    ):
        _write_executable(
            scripts_dir / script_name,
            'printf "%s mode=%s\\n" "${0##*/}" "${AGENTFLOW_KIMI_PIPELINE_MODE:-}" >>"$AGENTFLOW_TEST_LOG"\n',
        )

    completed = subprocess.run(
        ["bash", str(stack_path)],
        capture_output=True,
        cwd=tmp_path,
        env={
            **os.environ,
            "AGENTFLOW_PYTHON": sys.executable,
            "AGENTFLOW_TEST_LOG": str(log_path),
            "PYTHONPATH": str(fake_pythonpath),
        },
        text=True,
        timeout=5,
    )

    bundled_smoke_pipeline = tmp_path / "examples" / "local-real-agents-kimi-smoke.yaml"

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert log_path.read_text(encoding="utf-8").splitlines() == [
        "verify-local-kimi-shell.sh mode=",
        "agentflow:toolchain-local --output summary",
        f"agentflow:inspect {bundled_smoke_pipeline} --output summary",
        f"agentflow:doctor {bundled_smoke_pipeline} --output summary",
        "verify-custom-local-kimi-doctor.sh mode=",
        "verify-custom-local-kimi-doctor.sh mode=shell-init",
        "verify-custom-local-kimi-doctor.sh mode=shell-wrapper",
        "verify-custom-local-kimi-inspect.sh mode=",
        "verify-custom-local-kimi-inspect.sh mode=shell-init",
        "verify-custom-local-kimi-inspect.sh mode=shell-wrapper",
        "agentflow:check-local --output summary",
        "verify-custom-local-kimi-pipeline.sh mode=",
        "verify-custom-local-kimi-shell-init.sh mode=",
        "verify-custom-local-kimi-pipeline.sh mode=shell-wrapper",
        "verify-custom-local-kimi-run.sh mode=",
        "verify-custom-local-kimi-run.sh mode=shell-init",
        "verify-custom-local-kimi-run.sh mode=shell-wrapper",
    ]
    assert completed.stdout.count("== ") == 17
    assert "== Shell toolchain ==" in completed.stdout
    assert "== Bundled toolchain-local ==" in completed.stdout
    assert "== Bundled inspect-local ==" in completed.stdout
    assert "== Bundled doctor-local ==" in completed.stdout
    assert "== Bundled check-local ==" in completed.stdout
    assert "== External custom run (target.shell) ==" in completed.stdout
