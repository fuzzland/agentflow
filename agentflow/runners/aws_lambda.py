"""AWS Lambda runner for AgentFlow nodes."""

from __future__ import annotations

import asyncio
import json

from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.runners.base import (
    CancelCallback,
    LaunchPlan,
    RawExecutionResult,
    Runner,
    StreamCallback,
)
from agentflow.specs import AwsLambdaTarget, NodeSpec


class AwsLambdaRunner(Runner):
    """Execute agent nodes as AWS Lambda invocations.

    Wraps the synchronous boto3 invoke call in ``asyncio.to_thread``
    so it does not block the orchestrator event loop.
    """

    def _payload(self, node: NodeSpec, prepared: PreparedExecution) -> dict[str, object]:
        target = node.target
        if not isinstance(target, AwsLambdaTarget):
            raise TypeError("AwsLambdaRunner requires an AwsLambdaTarget")
        return {
            "command": prepared.command,
            "env": prepared.env,
            "cwd": target.remote_workdir,
            "stdin": prepared.stdin,
            "timeout_seconds": node.timeout_seconds,
            "runtime_files": prepared.runtime_files,
        }

    def plan_execution(
        self,
        node: NodeSpec,
        prepared: PreparedExecution,
        paths: ExecutionPaths,
    ) -> LaunchPlan:
        target = node.target
        if not isinstance(target, AwsLambdaTarget):
            raise TypeError("AwsLambdaRunner requires an AwsLambdaTarget")
        payload = self._payload(node, prepared)
        return LaunchPlan(
            kind="aws_lambda",
            env={},
            cwd=None,
            stdin=prepared.stdin,
            runtime_files=sorted(prepared.runtime_files),
            payload={
                "function_name": target.function_name,
                "region": target.region,
                "qualifier": target.qualifier,
                "invocation_type": target.invocation_type,
                "request": payload,
            },
        )

    def _invoke_sync(self, target: AwsLambdaTarget, payload: dict) -> dict:
        """Synchronous boto3 Lambda invocation, called via to_thread."""
        import boto3

        client = boto3.client("lambda", region_name=target.region)
        invoke_kwargs: dict[str, object] = {
            "FunctionName": target.function_name,
            "InvocationType": target.invocation_type,
            "Payload": json.dumps(payload).encode("utf-8"),
        }
        if target.qualifier:
            invoke_kwargs["Qualifier"] = target.qualifier
        response = client.invoke(**invoke_kwargs)
        raw = response["Payload"].read().decode("utf-8")
        if response.get("FunctionError"):
            return {
                "exit_code": 1,
                "stdout_lines": [],
                "stderr_lines": [f"Lambda function error: {raw}"],
                "timed_out": False,
                "cancelled": False,
            }
        result = json.loads(raw)
        result.setdefault("timed_out", False)
        result.setdefault("cancelled", False)
        return result

    async def execute(
        self,
        node: NodeSpec,
        prepared: PreparedExecution,
        paths: ExecutionPaths,
        on_output: StreamCallback,
        should_cancel: CancelCallback,
    ) -> RawExecutionResult:
        target = node.target
        if not isinstance(target, AwsLambdaTarget):
            raise TypeError("AwsLambdaRunner requires an AwsLambdaTarget")
        if should_cancel():
            return RawExecutionResult(
                exit_code=130,
                stdout_lines=[],
                stderr_lines=["Cancelled before Lambda invocation"],
                timed_out=False,
                cancelled=True,
            )

        payload = self._payload(node, prepared)
        timeout = node.timeout_seconds if node.timeout_seconds and node.timeout_seconds > 0 else None

        try:
            coro = asyncio.to_thread(self._invoke_sync, target, payload)
            if timeout:
                response_payload = await asyncio.wait_for(coro, timeout=timeout + 30)
            else:
                response_payload = await coro
        except asyncio.TimeoutError:
            return RawExecutionResult(
                exit_code=124,
                stdout_lines=[],
                stderr_lines=["Lambda invocation timed out on runner side"],
                timed_out=True,
                cancelled=False,
            )
        except Exception as exc:
            return RawExecutionResult(
                exit_code=1,
                stdout_lines=[],
                stderr_lines=[f"Lambda invocation failed: {exc}"],
                timed_out=False,
                cancelled=False,
            )

        result = RawExecutionResult.model_validate(response_payload)
        for line in result.stdout_lines:
            await on_output("stdout", line)
        for line in result.stderr_lines:
            await on_output("stderr", line)
        return result
