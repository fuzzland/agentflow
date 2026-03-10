.DEFAULT_GOAL := help

.PHONY: help python test inspect-local inspect-local-shell-init inspect-local-shell-wrapper doctor-local doctor-local-shell-init doctor-local-shell-wrapper smoke-local smoke-local-shell-init smoke-local-shell-wrapper run-local run-local-shell-init run-local-shell-wrapper check-local check-local-shell-init check-local-shell-wrapper toolchain-local probe-claude-local doctor-local-custom doctor-local-custom-shell-init doctor-local-custom-shell-wrapper inspect-local-custom inspect-local-custom-shell-init inspect-local-custom-shell-wrapper smoke-local-custom smoke-local-custom-shell-init smoke-local-custom-shell-wrapper check-local-custom check-local-custom-shell-init check-local-custom-shell-wrapper run-local-custom run-local-custom-shell-init run-local-custom-shell-wrapper verify-local

PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

help:
	@printf '%s\n' \
	  'Available targets:' \
	  '  python        Print the Python interpreter used by repo shortcuts (.venv/bin/python when available, else python3)' \
	  '  test          Run the Python test suite' \
	  '  toolchain-local Run `agentflow toolchain-local --output summary` for the local bash/Kimi/Codex/Claude readiness check' \
	  '  probe-claude-local Run a minimal live Claude-on-Kimi request through the local bash + kimi bootstrap and preserve provider-side errors' \
	  '  verify-local  Run the full local Codex + Claude-on-Kimi verification stack across bundled bootstrap/shell_init/target.shell inspect/doctor/smoke/run/check-local coverage, bundled toolchain-local, the live Claude-on-Kimi probe, plus external custom doctor, inspect, smoke, check-local, and run paths (shared timeout via AGENTFLOW_LOCAL_VERIFY_TIMEOUT_SECONDS)' \
	  '  doctor-local-custom Verify a temporary external Codex + Claude-on-Kimi pipeline through `agentflow doctor`' \
	  '  doctor-local-custom-shell-init Verify a temporary external Codex + Claude-on-Kimi `shell_init: kimi` pipeline through `agentflow doctor`' \
	  '  doctor-local-custom-shell-wrapper Verify a temporary external Codex + Claude-on-Kimi `target.shell` wrapper pipeline through `agentflow doctor`' \
	  '  inspect-local-custom Verify a temporary external Codex + Claude-on-Kimi pipeline through `agentflow inspect`' \
	  '  inspect-local-custom-shell-init Verify a temporary external Codex + Claude-on-Kimi `shell_init: kimi` pipeline through `agentflow inspect`' \
	  '  inspect-local-custom-shell-wrapper Verify a temporary external Codex + Claude-on-Kimi `target.shell` wrapper pipeline through `agentflow inspect`' \
	  '  smoke-local-custom Verify a temporary external Codex + Claude-on-Kimi pipeline through `agentflow smoke`' \
	  '  smoke-local-custom-shell-init Verify a temporary external Codex + Claude-on-Kimi `shell_init: kimi` pipeline through `agentflow smoke`' \
	  '  smoke-local-custom-shell-wrapper Verify a temporary external Codex + Claude-on-Kimi `target.shell` wrapper pipeline through `agentflow smoke`' \
	  '  check-local-custom Verify a temporary external Codex + Claude-on-Kimi pipeline through `agentflow check-local`' \
	  '  check-local-custom-shell-init Verify a temporary external Codex + Claude-on-Kimi `shell_init: kimi` pipeline through `agentflow check-local`' \
	  '  check-local-custom-shell-wrapper Verify a temporary external Codex + Claude-on-Kimi `target.shell` wrapper pipeline through `agentflow check-local`' \
	  '  run-local-custom Verify a temporary external Codex + Claude-on-Kimi pipeline through `agentflow run`' \
	  '  run-local-custom-shell-init Verify a temporary external Codex + Claude-on-Kimi `shell_init: kimi` pipeline through `agentflow run`' \
	  '  run-local-custom-shell-wrapper Verify a temporary external Codex + Claude-on-Kimi `target.shell` wrapper pipeline through `agentflow run`' \
	  '  inspect-local Inspect the bundled local Kimi-backed smoke pipeline' \
	  '  inspect-local-shell-init Inspect the bundled local Codex + Claude-on-Kimi `shell_init: kimi` smoke pipeline' \
	  '  inspect-local-shell-wrapper Inspect the bundled local Codex + Claude-on-Kimi `target.shell` wrapper smoke pipeline' \
	  '  doctor-local  Check local Codex/Claude/Kimi smoke prerequisites' \
	  '  doctor-local-shell-init Check the bundled local Codex + Claude-on-Kimi `shell_init: kimi` smoke prerequisites' \
	  '  doctor-local-shell-wrapper Check the bundled local Codex + Claude-on-Kimi `target.shell` wrapper smoke prerequisites' \
	  '  smoke-local   Run the bundled local Codex + Claude-on-Kimi smoke test' \
	  '  smoke-local-shell-init Run the bundled local Codex + Claude-on-Kimi `shell_init: kimi` smoke test' \
	  '  smoke-local-shell-wrapper Run the bundled local Codex + Claude-on-Kimi `target.shell` wrapper smoke test' \
	  '  run-local     Run the bundled local Codex + Claude-on-Kimi pipeline through `agentflow run`' \
	  '  run-local-shell-init Run the bundled local Codex + Claude-on-Kimi `shell_init: kimi` pipeline through `agentflow run`' \
	  '  run-local-shell-wrapper Run the bundled local Codex + Claude-on-Kimi `target.shell` wrapper pipeline through `agentflow run`' \
	  '  check-local   Run the single-pass doctor-then-smoke CLI shortcut with summary output' \
	  '  check-local-shell-init Run the bundled local Codex + Claude-on-Kimi `shell_init: kimi` pipeline through `agentflow check-local`' \
	  '  check-local-shell-wrapper Run the bundled local Codex + Claude-on-Kimi `target.shell` wrapper pipeline through `agentflow check-local`'

python:
	@$(PYTHON) -c "import sys; print(sys.executable)"

test:
	$(PYTHON) -m pytest -q

toolchain-local:
	$(PYTHON) -m agentflow toolchain-local --output summary

probe-claude-local:
	bash scripts/verify-local-kimi-claude-live.sh

verify-local:
	bash scripts/verify-local-kimi-stack.sh

doctor-local-custom:
	bash scripts/verify-custom-local-kimi-doctor.sh

doctor-local-custom-shell-init:
	AGENTFLOW_KIMI_PIPELINE_MODE=shell-init bash scripts/verify-custom-local-kimi-doctor.sh

doctor-local-custom-shell-wrapper:
	AGENTFLOW_KIMI_PIPELINE_MODE=shell-wrapper bash scripts/verify-custom-local-kimi-doctor.sh

inspect-local-custom:
	bash scripts/verify-custom-local-kimi-inspect.sh

inspect-local-custom-shell-init:
	AGENTFLOW_KIMI_PIPELINE_MODE=shell-init bash scripts/verify-custom-local-kimi-inspect.sh

inspect-local-custom-shell-wrapper:
	AGENTFLOW_KIMI_PIPELINE_MODE=shell-wrapper bash scripts/verify-custom-local-kimi-inspect.sh

smoke-local-custom:
	bash scripts/verify-custom-local-kimi-smoke.sh

smoke-local-custom-shell-init:
	AGENTFLOW_KIMI_PIPELINE_MODE=shell-init bash scripts/verify-custom-local-kimi-smoke.sh

smoke-local-custom-shell-wrapper:
	AGENTFLOW_KIMI_PIPELINE_MODE=shell-wrapper bash scripts/verify-custom-local-kimi-smoke.sh

check-local-custom:
	bash scripts/verify-custom-local-kimi-pipeline.sh

check-local-custom-shell-init:
	bash scripts/verify-custom-local-kimi-shell-init.sh

check-local-custom-shell-wrapper:
	AGENTFLOW_KIMI_PIPELINE_MODE=shell-wrapper bash scripts/verify-custom-local-kimi-pipeline.sh

run-local-custom:
	bash scripts/verify-custom-local-kimi-run.sh

run-local-custom-shell-init:
	AGENTFLOW_KIMI_PIPELINE_MODE=shell-init bash scripts/verify-custom-local-kimi-run.sh

run-local-custom-shell-wrapper:
	AGENTFLOW_KIMI_PIPELINE_MODE=shell-wrapper bash scripts/verify-custom-local-kimi-run.sh

inspect-local:
	$(PYTHON) -m agentflow inspect examples/local-real-agents-kimi-smoke.yaml --output summary

inspect-local-shell-init:
	$(PYTHON) -m agentflow inspect examples/local-real-agents-kimi-shell-init-smoke.yaml --output summary

inspect-local-shell-wrapper:
	$(PYTHON) -m agentflow inspect examples/local-real-agents-kimi-shell-wrapper-smoke.yaml --output summary

doctor-local:
	$(PYTHON) -m agentflow doctor examples/local-real-agents-kimi-smoke.yaml --output summary

doctor-local-shell-init:
	$(PYTHON) -m agentflow doctor examples/local-real-agents-kimi-shell-init-smoke.yaml --output summary

doctor-local-shell-wrapper:
	$(PYTHON) -m agentflow doctor examples/local-real-agents-kimi-shell-wrapper-smoke.yaml --output summary

smoke-local:
	$(PYTHON) -m agentflow smoke --output summary --show-preflight

smoke-local-shell-init:
	$(PYTHON) -m agentflow smoke examples/local-real-agents-kimi-shell-init-smoke.yaml --output summary --show-preflight

smoke-local-shell-wrapper:
	$(PYTHON) -m agentflow smoke examples/local-real-agents-kimi-shell-wrapper-smoke.yaml --output summary --show-preflight

run-local:
	$(PYTHON) -m agentflow run examples/local-real-agents-kimi-smoke.yaml --output summary

run-local-shell-init:
	$(PYTHON) -m agentflow run examples/local-real-agents-kimi-shell-init-smoke.yaml --output summary

run-local-shell-wrapper:
	$(PYTHON) -m agentflow run examples/local-real-agents-kimi-shell-wrapper-smoke.yaml --output summary

check-local:
	$(PYTHON) -m agentflow check-local --output summary

check-local-shell-init:
	$(PYTHON) -m agentflow check-local examples/local-real-agents-kimi-shell-init-smoke.yaml --output summary

check-local-shell-wrapper:
	$(PYTHON) -m agentflow check-local examples/local-real-agents-kimi-shell-wrapper-smoke.yaml --output summary
