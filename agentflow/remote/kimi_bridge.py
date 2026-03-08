from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx


def _emit(event_type: str, payload: dict[str, Any] | None = None) -> None:
    envelope = {
        "jsonrpc": "2.0",
        "method": "event",
        "params": {
            "type": event_type,
            "payload": payload or {},
        },
    }
    print(json.dumps(envelope, ensure_ascii=False), flush=True)


def _safe_path(working_dir: Path, requested: str, *, write: bool = False) -> Path:
    path = Path(requested).expanduser()
    if not path.is_absolute():
        path = working_dir / path
    root = working_dir.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes working dir: {requested}") from exc
    if write:
        resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _tool_definitions(mode: str) -> list[dict[str, Any]]:
    tools = [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a UTF-8 text file inside the working directory.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_dir",
                "description": "List files in a directory inside the working directory.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string", "default": "."}},
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "glob",
                "description": "Find files with a glob pattern.",
                "parameters": {
                    "type": "object",
                    "properties": {"pattern": {"type": "string"}},
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep",
                "description": "Search files for a regex pattern.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "path": {"type": "string", "default": "."},
                    },
                    "required": ["pattern"],
                },
            },
        },
    ]
    if mode == "read_write":
        tools.extend(
            [
                {
                    "type": "function",
                    "function": {
                        "name": "write_file",
                        "description": "Write a UTF-8 text file inside the working directory.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "content": {"type": "string"},
                            },
                            "required": ["path", "content"],
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "run_shell",
                        "description": "Run a shell command inside the working directory.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "command": {"type": "string"},
                                "timeout_seconds": {"type": "integer", "default": 60},
                            },
                            "required": ["command"],
                        },
                    },
                },
            ]
        )
    return tools


def _tool_call_payload(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "id": f"call_{uuid.uuid4().hex[:10]}",
        "function": {"name": name, "arguments": json.dumps(arguments, ensure_ascii=False)},
    }


def _tool_result_payload(tool_call_id: str, output: str, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "tool_call_id": tool_call_id,
        "return_value": {
            "is_error": is_error,
            "output": output,
            "message": "tool finished" if not is_error else "tool failed",
            "display": [],
        },
    }


def _execute_tool(name: str, arguments: dict[str, Any], working_dir: Path) -> str:
    match name:
        case "read_file":
            path = _safe_path(working_dir, arguments["path"])
            return path.read_text(encoding="utf-8")
        case "list_dir":
            path = _safe_path(working_dir, arguments.get("path", "."))
            return "\n".join(sorted(entry.name for entry in path.iterdir()))
        case "glob":
            root = working_dir.resolve()
            matches: list[str] = []
            for path in working_dir.glob(arguments["pattern"]):
                resolved = _safe_path(working_dir, str(path))
                matches.append(str(resolved.relative_to(root)))
            return "\n".join(sorted(matches))
        case "grep":
            regex = re.compile(arguments["pattern"])
            base = _safe_path(working_dir, arguments.get("path", "."))
            matches: list[str] = []
            candidates = [base] if base.is_file() else [path for path in base.rglob("*") if path.is_file()]
            for file_path in candidates:
                try:
                    for line_number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
                        if regex.search(line):
                            matches.append(f"{file_path.relative_to(working_dir)}:{line_number}:{line}")
                except UnicodeDecodeError:
                    continue
            return "\n".join(matches[:200])
        case "write_file":
            path = _safe_path(working_dir, arguments["path"], write=True)
            path.write_text(arguments["content"], encoding="utf-8")
            return f"wrote {path.relative_to(working_dir)}"
        case "run_shell":
            completed = subprocess.run(
                arguments["command"],
                cwd=working_dir,
                shell=True,
                text=True,
                capture_output=True,
                timeout=int(arguments.get("timeout_seconds", 60)),
                check=False,
            )
            return f"exit_code={completed.returncode}\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}".strip()
        case _:
            raise ValueError(f"unsupported tool: {name}")


def _extract_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.extend(
                    value
                    for value in [item.get("text"), item.get("content")]
                    if isinstance(value, str)
                )
        return "\n".join(parts)
    if isinstance(content, dict):
        return _extract_text(content.get("text") or content.get("content"))
    return str(content)


def _call_chat_completion(request: dict[str, Any], messages: list[dict[str, Any]]) -> dict[str, Any]:
    provider = request["provider"]
    base_url = (provider.get("base_url") or "https://api.moonshot.ai/v1").rstrip("/")
    api_key_env = provider.get("api_key_env") or "KIMI_API_KEY"
    api_key = os.getenv(api_key_env)
    if not api_key:
        raise RuntimeError(f"Missing API key env var: {api_key_env}")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **provider.get("headers", {}),
    }
    payload = {
        "model": request["model"],
        "messages": messages,
        "tools": _tool_definitions(request["tools_mode"]),
        "tool_choice": "auto",
        "stream": False,
    }
    with httpx.Client(timeout=request.get("timeout_seconds", 1800)) as client:
        response = client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        return response.json()


def run(request_path: str) -> int:
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    working_dir = Path(request["working_dir"]).resolve()
    mock_response = os.getenv("AGENTFLOW_KIMI_MOCK_RESPONSE")

    _emit("TurnBegin", {"user_input": request["prompt"]})
    if request.get("mcps"):
        _emit("MCPLoadingBegin", {})
        _emit("MCPLoadingEnd", {})

    if mock_response:
        _emit("StepBegin", {"n": 1})
        _emit("ContentPart", {"type": "text", "text": mock_response})
        _emit("TurnEnd", {})
        return 0

    system_prompt = (
        "You are Kimi running inside AgentFlow. "
        "If tools are available, use them deliberately and summarize concrete results."
    )
    if request.get("mcps"):
        server_names = ", ".join(server["name"] for server in request["mcps"])
        system_prompt += f" Configured MCP servers: {server_names}."

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": request["prompt"]},
    ]

    for step in range(1, 9):
        _emit("StepBegin", {"n": step})
        response = _call_chat_completion(request, messages)
        message = response["choices"][0]["message"]
        tool_calls = message.get("tool_calls") or []
        content = _extract_text(message.get("content"))
        if content:
            _emit("ContentPart", {"type": "text", "text": content})
        if not tool_calls:
            _emit("TurnEnd", {})
            return 0

        messages.append({
            "role": "assistant",
            "content": message.get("content") or "",
            "tool_calls": tool_calls,
        })
        for tool_call in tool_calls:
            name = tool_call["function"]["name"]
            arguments = json.loads(tool_call["function"].get("arguments") or "{}")
            tool_payload = _tool_call_payload(name, arguments)
            tool_payload["id"] = tool_call.get("id", tool_payload["id"])
            _emit("ToolCall", tool_payload)
            try:
                result = _execute_tool(name, arguments, working_dir)
                _emit("ToolResult", _tool_result_payload(tool_payload["id"], result))
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_payload["id"],
                    "content": result,
                })
            except Exception as exc:  # pragma: no cover - error path still exercised by tests via output
                text = f"tool error: {exc}"
                _emit("ToolResult", _tool_result_payload(tool_payload["id"], text, is_error=True))
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_payload["id"],
                    "content": text,
                })

    _emit("ContentPart", {"type": "text", "text": "Kimi did not finish within the maximum tool steps."})
    _emit("TurnEnd", {})
    return 1


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1]))
