from __future__ import annotations

import json
import os
import re
from pathlib import Path, PureWindowsPath

from agentflow.audit.models import ContractAuditManifest, FindingRecord, ReportManifest

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")
_VALIDATION_LABELS = {
    "poc_confirmed": "PoC Confirmed",
    "source_confirmed": "Source Confirmed",
    "rejected": "Rejected",
}
_FREE_TEXT_PATH_PATTERNS = (
    re.compile(r'(^|[\s([{"\'])((?:[A-Za-z]:\\|\\\\)[^\s]+)', re.MULTILINE),
    re.compile(r'(^|[\s([{"\'])(/[^\s]+)', re.MULTILINE),
)
_TRAILING_PATH_PUNCTUATION = ".,:;)]}"
_FOUNDRY_SUITE_PATTERNS = (
    re.compile(r"(\d+)\s+passed[;,]\s*(\d+)\s+failed[;,]\s*(\d+)\s+skipped", re.IGNORECASE),
    re.compile(r"(\d+)\s+passed,\s*(\d+)\s+failed,\s*(\d+)\s+skipped", re.IGNORECASE),
)


def customer_visible_findings(findings: list[FindingRecord]) -> list[FindingRecord]:
    return sort_findings(
        [finding for finding in findings if finding.validation_status != "rejected"]
    )


def sort_findings(findings: list[FindingRecord]) -> list[FindingRecord]:
    return sorted(findings, key=lambda finding: (_SEVERITY_ORDER[finding.severity], finding.id))


def _safe_component_file(path: str) -> str:
    posix_path = Path(path)
    windows_path = PureWindowsPath(path)
    is_absolute = posix_path.is_absolute() or windows_path.is_absolute()
    has_parent_traversal = ".." in posix_path.parts or ".." in windows_path.parts
    if is_absolute or has_parent_traversal:
        if "\\" in path:
            return windows_path.name
        return posix_path.name
    return path


def _sanitize_text_paths(text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        prefix = match.group(1)
        raw_path = match.group(2)
        trimmed = raw_path
        trailing = ""
        while trimmed and trimmed[-1] in _TRAILING_PATH_PUNCTUATION:
            trailing = trimmed[-1] + trailing
            trimmed = trimmed[:-1]
        return prefix + _safe_component_file(trimmed) + trailing

    sanitized = text
    for pattern in _FREE_TEXT_PATH_PATTERNS:
        sanitized = pattern.sub(_replace, sanitized)
    return sanitized


def extract_json_document(text: str) -> object:
    decoder = json.JSONDecoder()
    best_payload: object | None = None
    best_end = -1
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            payload, end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        absolute_end = index + end
        if absolute_end > best_end:
            best_payload = payload
            best_end = absolute_end
    if best_payload is not None:
        return best_payload
    raise ValueError("no JSON document found in text")


def _extract_findings_list(text: str) -> list[object]:
    payload = extract_json_document(text)
    if not isinstance(payload, list):
        raise ValueError("shard findings must decode to a JSON list")
    return payload


def _candidate_json_strings_from_stdout(stdout_text: str) -> list[str]:
    candidates: list[str] = []
    for line in stdout_text.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        item = payload.get("item")
        if isinstance(item, dict):
            item_type = item.get("type")
            if item_type in {"agent_message", "agentMessage"}:
                text = item.get("text")
                if isinstance(text, str):
                    candidates.append(text)
            elif item_type == "command_execution":
                text = item.get("aggregated_output")
                if isinstance(text, str):
                    candidates.append(text)
        if payload.get("type") == "response.output_item.done":
            item = payload.get("item")
            if isinstance(item, dict) and item.get("type") == "message":
                parts = item.get("content")
                if isinstance(parts, list):
                    text_parts = [
                        str(part.get("text"))
                        for part in parts
                        if isinstance(part, dict) and part.get("text") is not None
                    ]
                    if text_parts:
                        candidates.append("\n".join(text_parts))
    return candidates


def _candidate_json_strings_from_trace_events(trace_events: object) -> list[str]:
    candidates: list[str] = []
    if not isinstance(trace_events, list):
        return candidates
    for event in trace_events:
        if not isinstance(event, dict):
            continue
        kind = event.get("kind")
        content = event.get("content")
        if kind in {"assistant_message", "structured_output", "completed"} and isinstance(content, str):
            candidates.append(content)
    return candidates


def normalize_shard_findings(shard_outputs: list[dict[str, object]]) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    for shard in shard_outputs:
        track = str(shard.get("track", "")).strip()
        findings: list[object] | None = None
        for field in ("output", "final_response"):
            candidate = shard.get(field)
            if not isinstance(candidate, str) or not candidate.strip():
                continue
            try:
                findings = _extract_findings_list(candidate)
                break
            except ValueError:
                continue
        if findings is None:
            stdout_text = shard.get("stdout")
            if isinstance(stdout_text, str) and stdout_text.strip():
                for candidate in _candidate_json_strings_from_stdout(stdout_text):
                    try:
                        findings = _extract_findings_list(candidate)
                    except ValueError:
                        continue
        if findings is None:
            for candidate in _candidate_json_strings_from_trace_events(shard.get("trace_events")):
                try:
                    findings = _extract_findings_list(candidate)
                except ValueError:
                    continue
        if findings is None:
            raise ValueError("shard findings must decode to a JSON list")
        normalized.append(
            {
                "track": track,
                "findings": findings,
            }
        )
    return normalized


def public_findings_projection(findings: list[FindingRecord]) -> list[dict[str, object]]:
    projected: list[dict[str, object]] = []
    for finding in customer_visible_findings(findings):
        payload = finding.model_dump(mode="json")
        payload["title"] = _sanitize_text_paths(str(payload["title"]))
        payload["summary"] = _sanitize_text_paths(str(payload["summary"]))
        payload["root_cause"] = _sanitize_text_paths(str(payload["root_cause"]))
        payload["attack_scenario"] = _sanitize_text_paths(str(payload["attack_scenario"]))
        payload["review"] = {
            **dict(payload["review"]),
            "notes": _sanitize_text_paths(str(payload["review"]["notes"])),
        }
        component = dict(payload["component"])
        component["file"] = _safe_component_file(str(component["file"]))
        payload["component"] = component
        evidence_items = [dict(item) for item in payload["evidence"]]
        for evidence_item in evidence_items:
            evidence_item["file"] = _safe_component_file(str(evidence_item["file"]))
            evidence_item["snippet_ref"] = _sanitize_text_paths(str(evidence_item["snippet_ref"]))
        payload["evidence"] = evidence_items
        poc_payload = dict(payload["poc"])
        if poc_payload.get("test_path") is not None:
            poc_payload["test_path"] = _safe_component_file(str(poc_payload["test_path"]))
        payload["poc"] = poc_payload
        projected.append(payload)
    return projected


def _severity_counts(findings: list[FindingRecord]) -> dict[str, int]:
    counts = {severity: 0 for severity in _SEVERITY_LEVELS}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def _validation_counts(findings: list[FindingRecord]) -> dict[str, int]:
    counts = {"poc_confirmed": 0, "source_confirmed": 0, "rejected": 0}
    for finding in findings:
        counts[finding.validation_status] += 1
    return counts


def _display_path(path: str | Path, *, relative_to: Path) -> str:
    value = Path(path)
    if not value.is_absolute():
        return value.as_posix()
    try:
        return value.resolve().relative_to(relative_to.resolve()).as_posix()
    except ValueError:
        relpath = os.path.relpath(value.resolve(), relative_to.resolve())
        return Path(relpath).as_posix()


def _severity_overview(findings: list[FindingRecord]) -> str:
    counts = _severity_counts(findings)
    parts = [
        f"{counts[severity]} {severity.title()}"
        for severity in _SEVERITY_LEVELS
        if counts[severity] > 0
    ]
    if not parts:
        return "0 total"
    return f"{len(findings)} total ({', '.join(parts)})"


def _validation_overview(findings: list[FindingRecord]) -> str:
    counts = _validation_counts(findings)
    parts = [
        f"{counts['poc_confirmed']} PoC Confirmed",
        f"{counts['source_confirmed']} Source Confirmed",
    ]
    if counts["rejected"] > 0:
        parts.append(f"{counts['rejected']} Rejected")
    return ", ".join(parts)


def _extract_foundry_suite_summary(stdout_text: str) -> str | None:
    for pattern in _FOUNDRY_SUITE_PATTERNS:
        match = pattern.search(stdout_text)
        if match:
            passed, failed, skipped = match.groups()
            return f"{passed} passed, {failed} failed, {skipped} skipped"
    return None


def render_package_readme(
    package_dir: str | Path,
    manifest: ContractAuditManifest,
    report_manifest: ReportManifest,
    findings: list[FindingRecord],
    *,
    verification: dict[str, object] | None = None,
) -> str:
    package_root = Path(package_dir).expanduser().resolve()
    ordered_findings = customer_visible_findings(findings)
    report_dir = Path("artifacts") / "report"
    workspace_dir = Path("artifacts") / "workspace" / "foundry_project"
    source = manifest.target.source

    lines: list[str] = []
    lines.append(f"# {report_manifest.project_name} Audit Package")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append("| Overall Status | `Completed` |")
    lines.append(f"| Project | `{report_manifest.project_name}` |")
    lines.append(f"| Audit Scope | `{report_manifest.audit_scope}` |")
    if report_manifest.chain:
        lines.append(f"| Chain | `{report_manifest.chain}` |")
    lines.append(f"| Source Identifier | `{report_manifest.source_identifier}` |")
    if manifest.run.estimated_execution_time:
        lines.append(f"| Estimated Execution Time | `{manifest.run.estimated_execution_time}` |")
    lines.append(f"| Findings Overview | `{_severity_overview(ordered_findings)}` |")
    lines.append(f"| Validation Overview | `{_validation_overview(ordered_findings)}` |")
    lines.append(f"| Final Report | `{(report_dir / 'AUDIT_REPORT.md').as_posix()}` |")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append(f"- Project: `{report_manifest.project_name}`")
    lines.append(f"- Source mode: `{report_manifest.source_mode}`")
    if source.kind == "local":
        lines.append(
            f"- Source directory: `{_display_path(source.local_path, relative_to=package_root)}`"
        )
    else:
        lines.append(f"- Upstream repository: `{source.repo_url}`")
        lines.append(f"- Fetched revision: `{source.commit}`")
    lines.append(f"- Audit scope: `{report_manifest.audit_scope}`")
    if report_manifest.chain:
        lines.append(f"- Chain: `{report_manifest.chain}`")
    if report_manifest.contract_address_url:
        lines.append(f"- Contract address: `{report_manifest.contract_address_url}`")
    if report_manifest.creation_tx_url:
        lines.append(f"- Creation transaction: `{report_manifest.creation_tx_url}`")
    if verification:
        build = verification.get("build") if isinstance(verification.get("build"), dict) else {}
        test = verification.get("test") if isinstance(verification.get("test"), dict) else {}
        verified_workspace = verification.get("workspace")
        workspace_display = (
            _display_path(verified_workspace, relative_to=package_root)
            if isinstance(verified_workspace, str) and verified_workspace.strip()
            else workspace_dir.as_posix()
        )
        lines.append("")
        lines.append("## Verification")
        lines.append("")
        lines.append("```bash")
        lines.append(f"cd {workspace_display}")
        if build.get("command"):
            lines.append(str(build["command"]))
        if test.get("command"):
            lines.append(str(test["command"]))
        lines.append("```")
        lines.append("")
        if build:
            lines.append(
                f"- `{build.get('command', 'build')}`: `{build.get('status', 'unknown')}` (exit `{build.get('exit_code', 'n/a')}`)"
            )
        if test:
            lines.append(
                f"- `{test.get('command', 'test')}`: `{test.get('status', 'unknown')}` (exit `{test.get('exit_code', 'n/a')}`)"
            )
        suite_summary = _extract_foundry_suite_summary(str(verification.get("stdout", "")))
        if suite_summary:
            lines.append(f"- PoC suite: `{suite_summary}`")
    lines.append("")
    lines.append("## Deliverables")
    lines.append("")
    lines.append("| Path | Description |")
    lines.append("| --- | --- |")
    lines.append("| `contract_audit_manifest.json` | Audit manifest consumed by the pipeline |")
    lines.append(f"| `{(report_dir / 'AUDIT_REPORT.md').as_posix()}` | Human-readable audit report |")
    lines.append(f"| `{(report_dir / 'findings.json').as_posix()}` | Machine-readable final findings |")
    lines.append(f"| `{(report_dir / 'audit_summary.json').as_posix()}` | Summary counts and engagement metadata |")
    lines.append(f"| `{(report_dir / 'report_manifest.json').as_posix()}` | Report-safe manifest used for rendering |")
    discovery_state_path = package_root / "artifacts" / "workspace" / "discovery_state.json"
    if discovery_state_path.exists():
        lines.append("| `artifacts/workspace/discovery_state.json` | Final persisted discovery state |")
    lines.append("| `artifacts/workspace/foundry_project/` | Runnable Foundry workspace used for PoC verification |")
    unique_test_paths = []
    seen_test_paths: set[str] = set()
    for finding in ordered_findings:
        test_path = finding.poc.test_path
        if not test_path or test_path in seen_test_paths:
            continue
        seen_test_paths.add(test_path)
        unique_test_paths.append(test_path)
    for test_path in unique_test_paths:
        lines.append(
            f"| `{(workspace_dir / Path(test_path)).as_posix()}` | Foundry PoC test covering shipped findings |"
        )
    lines.append("")
    lines.append("## Key Findings")
    lines.append("")
    for finding in ordered_findings:
        lines.append(f"- `{finding.id}` {finding.severity.title()}: {_sanitize_text_paths(finding.summary)}")
    lines.append("")
    return "\n".join(lines)


def write_package_readme(
    package_dir: str | Path,
    manifest: ContractAuditManifest,
    report_manifest: ReportManifest,
    findings: list[FindingRecord],
    *,
    verification: dict[str, object] | None = None,
) -> None:
    output_dir = Path(package_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    readme_text = render_package_readme(
        output_dir,
        manifest,
        report_manifest,
        findings,
        verification=verification,
    )
    (output_dir / "README.md").write_text(readme_text, encoding="utf-8")
    (output_dir / "execution_summary.md").unlink(missing_ok=True)


def render_audit_report(manifest: ReportManifest, findings: list[FindingRecord]) -> str:
    ordered_findings = customer_visible_findings(findings)
    severity_counts = _severity_counts(ordered_findings)

    lines: list[str] = []
    lines.append(f"# {manifest.project_name} Contract Audit Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(
        f"Reviewed `{manifest.audit_scope}` from `{manifest.source_identifier}` and produced {len(ordered_findings)} validated findings."
    )
    lines.append("")
    lines.append("## Audit Target")
    lines.append(f"- Source Mode: {manifest.source_mode}")
    lines.append(f"- Source Identifier: {manifest.source_identifier}")
    lines.append(f"- Audit Scope: {manifest.audit_scope}")
    if manifest.chain or manifest.contract_address_url or manifest.creation_tx_url:
        lines.append("- Chain Context:")
        if manifest.chain:
            lines.append(f"  - Chain: {manifest.chain}")
        if manifest.contract_address_url:
            lines.append(f"  - Contract Address: {manifest.contract_address_url}")
        if manifest.creation_tx_url:
            lines.append(f"  - Creation Transaction: {manifest.creation_tx_url}")
    lines.append("")
    lines.append("## Validation Model")
    lines.append("- PoC Confirmed: exploit or failing behavior is reproduced via dedicated PoC evidence.")
    lines.append("- Source Confirmed: source-level reasoning confirms exploitability without a full PoC run.")
    lines.append("- Rejected: issue candidate was reviewed and is not a valid vulnerability.")
    lines.append("")
    lines.append("## Severity Overview")
    for severity in _SEVERITY_LEVELS:
        lines.append(f"- {severity}: {severity_counts[severity]}")
    lines.append("")
    lines.append("## Findings")
    for finding in ordered_findings:
        lines.append("")
        lines.append(f"### {finding.id}")
        lines.append(f"- Severity: {finding.severity.title()}")
        lines.append(f"- Validation Status: {_VALIDATION_LABELS[finding.validation_status]}")
        component = _safe_component_file(finding.component.file)
        if finding.component.symbol:
            component = f"{component}::{finding.component.symbol}"
        lines.append(f"- Component: {component}")
        lines.append(f"- Summary: {_sanitize_text_paths(finding.summary)}")
        lines.append(f"- Impact: {_sanitize_text_paths(finding.attack_scenario)}")
        lines.append(f"- Recommendation: {_sanitize_text_paths(finding.root_cause)}")
        if finding.poc.test_path:
            lines.append(f"- PoC / Reproduction: {_safe_component_file(finding.poc.test_path)}")

    lines.append("")
    return "\n".join(lines)


def write_report_bundle(report_dir: str | Path, manifest: ReportManifest, findings: list[FindingRecord]) -> None:
    output_dir = Path(report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ordered_findings = customer_visible_findings(findings)
    projected_findings = public_findings_projection(ordered_findings)
    report_text = render_audit_report(manifest, ordered_findings)
    summary_payload = {
        "project_name": manifest.project_name,
        "audit_scope": manifest.audit_scope,
        "source_mode": manifest.source_mode,
        "source_identifier": manifest.source_identifier,
        "total_findings": len(ordered_findings),
        "severity_counts": _severity_counts(ordered_findings),
        "validation_counts": _validation_counts(ordered_findings),
    }

    (output_dir / "AUDIT_REPORT.md").write_text(report_text, encoding="utf-8")
    (output_dir / "findings.json").write_text(
        json.dumps(projected_findings, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output_dir / "audit_summary.json").write_text(
        json.dumps(summary_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (output_dir / "report_manifest.json").write_text(
        manifest.model_dump_json(indent=2),
        encoding="utf-8",
    )
