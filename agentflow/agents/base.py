from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.specs import AgentKind, NodeSpec, ProviderConfig, resolve_execution_provider


class AgentAdapter(ABC):
    @abstractmethod
    def prepare(self, node: NodeSpec, prompt: str, paths: ExecutionPaths) -> PreparedExecution:
        raise NotImplementedError

    def provider_config(self, value: str | ProviderConfig | None, agent: AgentKind) -> ProviderConfig | None:
        return resolve_execution_provider(value, agent)

    def merge_env(self, *parts: dict[str, str]) -> dict[str, str]:
        merged: dict[str, str] = {}
        for part in parts:
            merged.update({key: value for key, value in part.items() if value is not None})
        return merged

    def quote_json(self, value: Any) -> str:
        import json

        return json.dumps(value, ensure_ascii=False)

    def relative_runtime_file(self, *parts: str) -> str:
        return str(Path(*parts))
