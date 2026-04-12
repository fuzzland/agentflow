from __future__ import annotations

import re
from pathlib import Path

from agentflow.audit.models import FindingRecord

_TEST_FUNCTION_RE = re.compile(r"function\s+(test_[A-Za-z0-9_]+)\s*\(")
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {"test", "can", "cf", "iter", "the", "and", "with", "into", "from", "does", "only", "still"}


def _tokens(text: str) -> set[str]:
    return {
        token
        for token in _TOKEN_RE.findall(text.lower())
        if len(token) >= 3 and token not in _STOPWORDS
    }


def _normalize_id(finding_id: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", finding_id.lower()).strip("_")


def _extract_test_entries(workspace_dir: Path) -> list[dict[str, str]]:
    security_dir = workspace_dir / "test" / "security"
    entries: list[dict[str, str]] = []
    if not security_dir.exists():
        return entries
    for path in sorted(security_dir.rglob("*.t.sol")):
        text = path.read_text(encoding="utf-8")
        for test_name in _TEST_FUNCTION_RE.findall(text):
            entries.append(
                {
                    "test_path": path.relative_to(workspace_dir).as_posix(),
                    "test_name": test_name,
                }
            )
    return entries


def _score_mapping(test_name: str, finding: FindingRecord) -> int:
    normalized_id = _normalize_id(finding.id)
    lowered_name = test_name.lower()
    if normalized_id and normalized_id in lowered_name:
        return 100
    name_tokens = _tokens(test_name)
    finding_tokens = _tokens(" ".join([finding.id, finding.title, finding.dedup_fingerprint]))
    overlap = len(name_tokens & finding_tokens)
    return overlap


def derive_poc_mappings(findings: list[FindingRecord], workspace_dir: str | Path) -> list[dict[str, str | None]]:
    workspace = Path(workspace_dir)
    tests = _extract_test_entries(workspace)

    best_by_finding: dict[str, tuple[int, dict[str, str]]] = {}
    used_tests: set[tuple[str, str]] = set()
    candidates: list[tuple[int, str, dict[str, str]]] = []
    for finding in findings:
        for entry in tests:
            score = _score_mapping(entry["test_name"], finding)
            if score >= 3:
                candidates.append((score, finding.id, entry))

    for score, finding_id, entry in sorted(candidates, key=lambda item: (-item[0], item[1], item[2]["test_name"])):
        key = (entry["test_path"], entry["test_name"])
        if key in used_tests or finding_id in best_by_finding:
            continue
        best_by_finding[finding_id] = (score, entry)
        used_tests.add(key)

    mappings: list[dict[str, str | None]] = []
    for finding in findings:
        match = best_by_finding.get(finding.id)
        if match is None:
            mappings.append(
                {
                    "finding_id": finding.id,
                    "test_path": None,
                    "test_name": None,
                    "reason": "no deterministic PoC mapping from existing test/security suite",
                }
            )
            continue
        _, entry = match
        mappings.append(
            {
                "finding_id": finding.id,
                "test_path": entry["test_path"],
                "test_name": entry["test_name"],
                "reason": None,
            }
        )
    return mappings
