"""EC2 runner: launch instance, SSH execute, terminate."""

from __future__ import annotations

import asyncio
import base64

from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.runners.base import (
    CancelCallback,
    LaunchPlan,
    RawExecutionResult,
    Runner,
    StreamCallback,
)
from agentflow.runners.ssh import SSHRunner
from agentflow.specs import NodeSpec


class EC2Runner(Runner):
    """Launch a fresh EC2 instance, execute via SSH, then terminate."""

    def _launch_instance(self, node: NodeSpec, prepared: PreparedExecution) -> str:
        import boto3

        target = node.target
        ec2 = boto3.client("ec2", region_name=target.region)

        params: dict = {
            "ImageId": target.ami,
            "InstanceType": target.instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": f"agentflow-{node.id}"}],
                }
            ],
        }
        if target.key_name:
            params["KeyName"] = target.key_name
        if target.security_group_ids:
            params["SecurityGroupIds"] = target.security_group_ids
        if target.subnet_id:
            params["SubnetId"] = target.subnet_id

        user_data_parts: list[str] = []
        if target.install_agents:
            from agentflow.cloud.installer import agent_install_script

            user_data_parts.append(agent_install_script(target.install_agents))
        if target.user_data:
            user_data_parts.append(target.user_data)
        if user_data_parts:
            params["UserData"] = base64.b64encode(
                "\n".join(user_data_parts).encode()
            ).decode()

        if target.spot:
            params["InstanceMarketOptions"] = {"MarketType": "spot"}

        response = ec2.run_instances(**params)
        return response["Instances"][0]["InstanceId"]

    def _wait_for_ssh(self, region: str, instance_id: str) -> str:
        import boto3

        ec2 = boto3.client("ec2", region_name=region)
        waiter = ec2.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 5, "MaxAttempts": 60})
        waiter = ec2.get_waiter("instance_status_ok")
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 10, "MaxAttempts": 30})

        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        return instance.get("PublicIpAddress") or instance.get("PrivateIpAddress")

    def _snapshot_instance(self, region: str, instance_id: str, name: str) -> str:
        """Create an AMI from the instance. Returns the AMI ID."""
        import boto3

        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.create_image(
            InstanceId=instance_id,
            Name=name,
            NoReboot=False,
            TagSpecifications=[{
                "ResourceType": "image",
                "Tags": [{"Key": "Name", "Value": name}, {"Key": "CreatedBy", "Value": "agentflow"}],
            }],
        )
        return resp["ImageId"]

    def _terminate_instance(self, region: str, instance_id: str) -> None:
        import boto3

        boto3.client("ec2", region_name=region).terminate_instances(InstanceIds=[instance_id])

    def plan_execution(
        self,
        node: NodeSpec,
        prepared: PreparedExecution,
        paths: ExecutionPaths,
    ) -> LaunchPlan:
        target = node.target
        return LaunchPlan(
            kind="ec2",
            command=prepared.command,
            env=prepared.env,
            cwd=str(paths.target_workdir),
            payload={
                "ami": target.ami,
                "instance_type": target.instance_type,
                "region": target.region,
                "spot": getattr(target, "spot", False),
            },
        )

    async def execute(
        self,
        node: NodeSpec,
        prepared: PreparedExecution,
        paths: ExecutionPaths,
        on_output: StreamCallback,
        should_cancel: CancelCallback,
    ) -> RawExecutionResult:
        target = node.target
        instance_id: str | None = None
        try:
            if should_cancel():
                return RawExecutionResult(
                    exit_code=130, stdout_lines=[], stderr_lines=["Cancelled"],
                    timed_out=False, cancelled=True,
                )

            from types import SimpleNamespace
            from agentflow.cloud.aws import collect_local_credentials, discover_networking

            needs_patch = False

            # Auto-discover AMI if not specified
            if not target.ami:
                from agentflow.cloud.aws import discover_ubuntu_ami
                await on_output("stderr", f"Finding latest Ubuntu AMI in {target.region}...")
                ami = await asyncio.to_thread(discover_ubuntu_ami, target.region)
                target = SimpleNamespace(**{k: getattr(target, k) for k in target.model_fields})
                target.ami = ami
                needs_patch = True
                await on_output("stderr", f"Using AMI {ami}")

            # Auto-create key pair if not specified
            if not target.key_name:
                from agentflow.cloud.aws import ensure_key_pair
                await on_output("stderr", "Ensuring SSH key pair...")
                key_name, identity_file = await asyncio.to_thread(ensure_key_pair, target.region)
                if not needs_patch:
                    target = SimpleNamespace(**{k: getattr(target, k) for k in target.model_fields})
                    needs_patch = True
                target.key_name = key_name
                target.identity_file = identity_file
                await on_output("stderr", f"Using key pair {key_name}")

            # Auto-discover networking if not specified
            if not target.security_group_ids:
                await on_output("stderr", "Auto-discovering VPC networking...")
                net = await asyncio.to_thread(discover_networking, target.region)
                if not needs_patch:
                    target = SimpleNamespace(**{k: getattr(target, k) for k in target.model_fields})
                    needs_patch = True
                target.security_group_ids = net["security_groups"]
                if not target.subnet_id:
                    target.subnet_id = net["subnets"][0]

            if needs_patch:
                node = SimpleNamespace(id=node.id, agent=node.agent, target=target, timeout_seconds=node.timeout_seconds)

            # Auto-forward local credentials
            local_creds = collect_local_credentials(node.agent.value)
            merged_env = {**local_creds, **prepared.env}
            prepared = PreparedExecution(
                command=prepared.command, env=merged_env, cwd=prepared.cwd,
                trace_kind=prepared.trace_kind, runtime_files=prepared.runtime_files, stdin=prepared.stdin,
            )

            await on_output("stderr", f"Launching EC2 {target.instance_type} ({target.ami})...")
            instance_id = await asyncio.to_thread(self._launch_instance, node, prepared)
            await on_output("stderr", f"Instance {instance_id} launched, waiting for SSH...")

            if should_cancel():
                return RawExecutionResult(
                    exit_code=130, stdout_lines=[], stderr_lines=["Cancelled during launch"],
                    timed_out=False, cancelled=True,
                )

            ip = await asyncio.to_thread(self._wait_for_ssh, target.region, instance_id)
            await on_output("stderr", f"Instance ready at {ip}")

            from types import SimpleNamespace

            ssh_target = SimpleNamespace(
                kind="ssh", host=ip, port=22,
                username=target.username,
                identity_file=target.identity_file,
                remote_workdir=None,
            )
            ssh_runner = SSHRunner()

            # Wait for cloud-init to finish if agents are being installed
            if target.install_agents:
                await on_output("stderr", "Waiting for agent installation (cloud-init)...")
                wait_node = SimpleNamespace(
                    id=node.id, target=ssh_target, timeout_seconds=600,
                )
                wait_prepared = PreparedExecution(
                    command=["cloud-init", "status", "--wait"],
                    env={}, cwd="/tmp", trace_kind="setup",
                    runtime_files={}, stdin=None,
                )
                wait_result = await ssh_runner.execute(
                    wait_node, wait_prepared, paths,
                    lambda s, l: on_output("stderr", f"  [cloud-init] {l}"),
                    should_cancel,
                )
                if wait_result.exit_code != 0:
                    await on_output("stderr", "cloud-init may have failed, proceeding anyway...")

            # Inject agent auth setup into the command
            from agentflow.cloud.installer import agent_auth_setup

            auth_setup = agent_auth_setup(node.agent.value, prepared.env)
            if auth_setup:
                import shlex
                original_cmd = " ".join(shlex.quote(p) for p in prepared.command)
                auth_prepared = PreparedExecution(
                    command=["bash", "-c", f"{auth_setup} && {original_cmd}"],
                    env=prepared.env,
                    cwd=prepared.cwd,
                    trace_kind=prepared.trace_kind,
                    runtime_files=prepared.runtime_files,
                    stdin=prepared.stdin,
                )
            else:
                auth_prepared = prepared

            await on_output("stderr", "Executing agent command...")
            ssh_node = SimpleNamespace(
                id=node.id, target=ssh_target,
                timeout_seconds=node.timeout_seconds,
            )
            return await ssh_runner.execute(ssh_node, auth_prepared, paths, on_output, should_cancel)
        except Exception as exc:
            return RawExecutionResult(
                exit_code=1, stdout_lines=[],
                stderr_lines=[f"EC2 execution failed: {exc}"],
                timed_out=False, cancelled=False,
            )
        finally:
            if instance_id:
                try:
                    if getattr(target, "snapshot", False):
                        snap_name = f"agentflow-{node.id}-{instance_id}"
                        await on_output("stderr", f"Creating snapshot {snap_name}...")
                        ami_id = await asyncio.to_thread(
                            self._snapshot_instance, target.region, instance_id, snap_name,
                        )
                        await on_output("stderr", f"Snapshot AMI: {ami_id}")

                    if getattr(target, "terminate", True):
                        await on_output("stderr", f"Terminating {instance_id}...")
                        await asyncio.to_thread(self._terminate_instance, target.region, instance_id)
                        await on_output("stderr", f"Instance {instance_id} terminated.")
                    else:
                        await on_output("stderr", f"Instance {instance_id} left running (terminate=false).")
                except Exception as exc:
                    await on_output("stderr", f"Warning: cleanup failed for {instance_id}: {exc}")
