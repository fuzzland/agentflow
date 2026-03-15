from __future__ import annotations

from copy import deepcopy
from contextvars import ContextVar
from dataclasses import dataclass, field
import json
from os import PathLike
from typing import Any

import yaml

from agentflow.specs import AgentKind, LocalTarget, NodeSpec, PipelineSpec


_CURRENT_DAG: ContextVar["DAG | None"] = ContextVar("_CURRENT_DAG", default=None)


@dataclass
class NodeBuilder:
    dag: "DAG"
    id: str
    agent: AgentKind
    prompt: str
    kwargs: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.dag._register(self)

    def __rshift__(self, other: "NodeBuilder | list[NodeBuilder]") -> "NodeBuilder | list[NodeBuilder]":
        if isinstance(other, list):
            for item in other:
                item.depends_on.append(self.id)
            return other
        other.depends_on.append(self.id)
        return other

    def __rrshift__(self, other: list["NodeBuilder"]) -> "NodeBuilder":
        if isinstance(other, list):
            for item in other:
                self.depends_on.append(item.id)
            return self
        raise TypeError(f"unsupported dependency source {type(other)!r}")

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "agent": self.agent,
            "prompt": self.prompt,
            "depends_on": self.depends_on,
            **_normalize_node_kwargs(self.kwargs),
        }

    def to_spec(self) -> NodeSpec:
        return NodeSpec.model_validate(self.to_payload())


class DAG:
    def __init__(
        self,
        name: str,
        *,
        description: str | None = None,
        working_dir: str = ".",
        concurrency: int = 4,
        fail_fast: bool = False,
        node_defaults: dict[str, Any] | None = None,
        agent_defaults: dict[str | AgentKind, dict[str, Any]] | None = None,
        local_target_defaults: dict[str, Any] | LocalTarget | None = None,
    ):
        self.name = name
        self.description = description
        self.working_dir = working_dir
        self.concurrency = concurrency
        self.fail_fast = fail_fast
        self.node_defaults = node_defaults
        self.agent_defaults = agent_defaults
        self.local_target_defaults = local_target_defaults
        self._nodes: dict[str, NodeBuilder] = {}
        self._token = None

    def __enter__(self) -> "DAG":
        self._token = _CURRENT_DAG.set(self)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._token is not None:
            _CURRENT_DAG.reset(self._token)

    def _register(self, node: NodeBuilder) -> None:
        if node.id in self._nodes:
            raise ValueError(f"node {node.id!r} already exists")
        self._nodes[node.id] = node

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
        }
        if self.description is not None:
            payload["description"] = self.description
        payload["working_dir"] = self.working_dir
        payload["concurrency"] = self.concurrency
        payload["fail_fast"] = self.fail_fast
        if self.node_defaults is not None:
            payload["node_defaults"] = _normalize_node_defaults(self.node_defaults)
        if self.agent_defaults:
            payload["agent_defaults"] = _normalize_agent_defaults(self.agent_defaults)
        if self.local_target_defaults is not None:
            payload["local_target_defaults"] = self.local_target_defaults
        payload["nodes"] = [node.to_payload() for node in self._nodes.values()]
        return payload

    def to_spec(self) -> PipelineSpec:
        return PipelineSpec.model_validate(self.to_payload())

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_payload(), indent=indent)

    def to_yaml(self) -> str:
        payload = json.loads(self.to_json(indent=None))
        return yaml.dump(
            payload,
            Dumper=_ReadableYamlDumper,
            sort_keys=False,
            allow_unicode=False,
        )


class _ReadableYamlDumper(yaml.SafeDumper):
    pass


def _represent_readable_yaml_string(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_ReadableYamlDumper.add_representer(str, _represent_readable_yaml_string)


def _normalize_local_target(value: Any) -> Any:
    if not isinstance(value, dict):
        return deepcopy(value)
    if "kind" in value:
        return deepcopy(value)
    return {"kind": "local", **deepcopy(value)}


def _normalize_node_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(kwargs)
    if "target" in normalized:
        normalized["target"] = _normalize_local_target(normalized.get("target"))
    return normalized


def _normalize_node_defaults(defaults: dict[str, Any] | None) -> dict[str, Any] | None:
    if defaults is None:
        return None
    return _normalize_node_kwargs(defaults)


def _normalize_agent_defaults(
    defaults: dict[str | AgentKind, dict[str, Any]] | None,
) -> dict[str | AgentKind, dict[str, Any]] | None:
    if defaults is None:
        return None
    return {
        agent: _normalize_node_kwargs(agent_defaults)
        for agent, agent_defaults in deepcopy(defaults).items()
    }


def _current_dag() -> DAG:
    dag = _CURRENT_DAG.get()
    if dag is None:
        raise RuntimeError("No active DAG context. Use `with DAG(...):`.")
    return dag


def _node(agent: AgentKind, *, task_id: str, prompt: str, **kwargs: Any) -> NodeBuilder:
    return NodeBuilder(dag=_current_dag(), id=task_id, agent=agent, prompt=prompt, kwargs=kwargs)


def _fanout_payload(
    mode: dict[str, Any],
    *,
    as_: str = "item",
    derive: dict[str, Any] | None = None,
    include: list[dict[str, Any]] | None = None,
    exclude: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload = {"as": as_, **deepcopy(mode)}
    if derive is not None:
        payload["derive"] = deepcopy(derive)
    if include is not None:
        payload["include"] = deepcopy(include)
    if exclude is not None:
        payload["exclude"] = deepcopy(exclude)
    return payload


def fanout_count(count: int, *, as_: str = "item", derive: dict[str, Any] | None = None) -> dict[str, Any]:
    return _fanout_payload({"count": count}, as_=as_, derive=derive)


def fanout_values(values: list[Any], *, as_: str = "item", derive: dict[str, Any] | None = None) -> dict[str, Any]:
    return _fanout_payload({"values": values}, as_=as_, derive=derive)


def fanout_values_path(
    path: str | PathLike[str],
    *,
    as_: str = "item",
    derive: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _fanout_payload({"values_path": str(path)}, as_=as_, derive=derive)


def fanout_matrix(
    matrix: dict[str, list[Any]],
    *,
    as_: str = "item",
    derive: dict[str, Any] | None = None,
    include: list[dict[str, Any]] | None = None,
    exclude: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return _fanout_payload(
        {"matrix": matrix},
        as_=as_,
        derive=derive,
        include=include,
        exclude=exclude,
    )


def fanout_matrix_path(
    path: str | PathLike[str],
    *,
    as_: str = "item",
    derive: dict[str, Any] | None = None,
    include: list[dict[str, Any]] | None = None,
    exclude: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return _fanout_payload(
        {"matrix_path": str(path)},
        as_=as_,
        derive=derive,
        include=include,
        exclude=exclude,
    )


def fanout_group_by(
    from_: str,
    fields: list[str],
    *,
    as_: str = "item",
    derive: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _fanout_payload({"group_by": {"from": from_, "fields": list(fields)}}, as_=as_, derive=derive)


def fanout_batches(
    from_: str,
    size: int,
    *,
    as_: str = "item",
    derive: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _fanout_payload({"batches": {"from": from_, "size": size}}, as_=as_, derive=derive)


def codex(*, task_id: str, prompt: str, **kwargs: Any) -> NodeBuilder:
    return _node(AgentKind.CODEX, task_id=task_id, prompt=prompt, **kwargs)


def claude(*, task_id: str, prompt: str, **kwargs: Any) -> NodeBuilder:
    return _node(AgentKind.CLAUDE, task_id=task_id, prompt=prompt, **kwargs)


def kimi(*, task_id: str, prompt: str, **kwargs: Any) -> NodeBuilder:
    return _node(AgentKind.KIMI, task_id=task_id, prompt=prompt, **kwargs)
