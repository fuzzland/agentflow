from __future__ import annotations

from pathlib import Path
from typing import Literal
import re

from pydantic import BaseModel, ConfigDict, Field

from agentflow.audit.models import FindingRecord

_NO_CHANGE_PATIENCE = 3
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "into",
    "when",
    "then",
    "than",
    "over",
    "under",
    "after",
    "before",
    "same",
    "does",
    "doesn",
    "without",
    "through",
    "across",
    "their",
    "have",
    "has",
    "will",
    "only",
    "more",
    "less",
    "than",
    "risk",
    "issue",
    "finding",
}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class CurationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["CONTINUE", "STOP"]
    round: int
    consecutive_no_change: int
    changed: bool
    previous_count: int
    current_count: int


class CurationState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    round: int = 0
    consecutive_no_change: int = 0
    curated_findings: list[FindingRecord] = Field(default_factory=list)
    history: list[CurationDecision] = Field(default_factory=list)


def curated_findings_for_output(findings: list[FindingRecord]) -> list[FindingRecord]:
    return sorted(
        [
            finding
            for finding in findings
            if finding.validation_status != "rejected" and finding.review.disposition != "merged"
        ],
        key=lambda finding: (finding.dedup_fingerprint, finding.id),
    )


def _tokenize(text: str) -> set[str]:
    tokens = {
        token
        for token in _TOKEN_PATTERN.findall(text.lower())
        if len(token) >= 4 and token not in _STOPWORDS
    }
    return tokens


def _fingerprint_family(fingerprint: str) -> tuple[str, ...]:
    normalized = fingerprint.lower().replace("/", "|").replace(":", "|").replace("-", "|")
    parts = [part for part in normalized.split("|") if part and not part.endswith(".sol")]
    return tuple(parts[:4])


def _finding_tokens(finding: FindingRecord) -> set[str]:
    evidence_files = " ".join(item.file for item in finding.evidence)
    return _tokenize(
        " ".join(
            [
                finding.category,
                finding.title,
                finding.summary,
                finding.root_cause,
                finding.attack_scenario,
                finding.component.file,
                evidence_files,
            ]
        )
    )


def _should_merge(left: FindingRecord, right: FindingRecord) -> bool:
    if left.validation_status != right.validation_status:
        return False
    left_family = _fingerprint_family(left.dedup_fingerprint)
    right_family = _fingerprint_family(right.dedup_fingerprint)
    if left_family and right_family and left_family == right_family:
        return True

    if left.category != right.category:
        return False

    left_tokens = _finding_tokens(left)
    right_tokens = _finding_tokens(right)
    if not left_tokens or not right_tokens:
        return False
    overlap = len(left_tokens & right_tokens)
    smallest = min(len(left_tokens), len(right_tokens))
    return overlap >= 4 and overlap / smallest >= 0.55


def _merge_findings(primary: FindingRecord, secondary: FindingRecord) -> FindingRecord:
    severity = primary.severity
    if _SEVERITY_RANK[secondary.severity] < _SEVERITY_RANK[severity]:
        severity = secondary.severity

    evidence_by_key: dict[tuple[str, int, int, str], object] = {}
    for item in [*primary.evidence, *secondary.evidence]:
        key = (item.file, item.start_line, item.end_line, item.snippet_ref)
        evidence_by_key[key] = item

    notes = primary.review.notes.strip()
    merged_note = f"Merged related variant {secondary.id} into {primary.id}."
    if notes:
        notes = f"{notes} {merged_note}"
    else:
        notes = merged_note

    return primary.model_copy(
        update={
            "severity": severity,
            "evidence": list(
                sorted(
                    evidence_by_key.values(),
                    key=lambda item: (item.file, item.start_line, item.end_line, item.snippet_ref),
                )
            ),
            "review": primary.review.model_copy(update={"notes": notes}),
        }
    )


def curate_findings(findings: list[FindingRecord]) -> list[FindingRecord]:
    curated: list[FindingRecord] = []
    for finding in sorted(
        curated_findings_for_output(findings),
        key=lambda item: (_SEVERITY_RANK[item.severity], item.id),
    ):
        merged = False
        for index, existing in enumerate(curated):
            if _should_merge(existing, finding):
                curated[index] = _merge_findings(existing, finding)
                merged = True
                break
        if not merged:
            curated.append(finding)
    deduped_ids: list[FindingRecord] = []
    seen_ids: dict[str, int] = {}
    for finding in curated_findings_for_output(curated):
        count = seen_ids.get(finding.id, 0) + 1
        seen_ids[finding.id] = count
        if count == 1:
            deduped_ids.append(finding)
            continue
        deduped_ids.append(
            finding.model_copy(update={"id": f"{finding.id}-{count}"})
        )
    return deduped_ids


def _comparison_payload(findings: list[FindingRecord]) -> list[dict[str, object]]:
    return [finding.model_dump(mode="json") for finding in curated_findings_for_output(findings)]


def load_curation_state(path: str | Path) -> CurationState:
    state_path = Path(path)
    if not state_path.exists():
        return CurationState()
    return CurationState.model_validate_json(state_path.read_text(encoding="utf-8"))


def write_curation_state(path: str | Path, state: CurationState) -> None:
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(state.model_dump_json(indent=2), encoding="utf-8")


def current_curated_findings(state: CurationState, seed_findings: list[FindingRecord]) -> list[FindingRecord]:
    if state.curated_findings:
        return curated_findings_for_output(state.curated_findings)
    return curated_findings_for_output(seed_findings)


def curation_input_payload(findings: list[FindingRecord]) -> list[dict[str, object]]:
    payload: list[dict[str, object]] = []
    for finding in curated_findings_for_output(findings):
        payload.append(
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "validation_status": finding.validation_status,
                "component": finding.component.model_dump(mode="json"),
                "summary": finding.summary,
                "root_cause": finding.root_cause,
                "attack_scenario": finding.attack_scenario,
                "dedup_fingerprint": finding.dedup_fingerprint,
                "evidence_refs": [
                    f"{item.file}:{item.start_line}-{item.end_line}"
                    for item in finding.evidence
                ],
            }
        )
    return payload


def curation_prompt_payload(
    state: CurationState,
    seed_findings: list[FindingRecord],
) -> dict[str, object]:
    current_findings = current_curated_findings(state, seed_findings)
    return {
        "round": state.round,
        "consecutive_no_change": state.consecutive_no_change,
        "current_findings": curation_input_payload(current_findings),
        "recent_history": [entry.model_dump(mode="json") for entry in state.history[-5:]],
    }


def apply_curation_round(
    state: CurationState,
    findings: list[FindingRecord],
    *,
    no_change_patience: int = _NO_CHANGE_PATIENCE,
) -> tuple[CurationState, CurationDecision]:
    next_findings = curated_findings_for_output(findings)
    changed = _comparison_payload(next_findings) != _comparison_payload(state.curated_findings)
    consecutive_no_change = state.consecutive_no_change + 1
    if changed:
        consecutive_no_change = 0
    decision = CurationDecision(
        status="STOP" if consecutive_no_change >= no_change_patience else "CONTINUE",
        round=state.round + 1,
        consecutive_no_change=consecutive_no_change,
        changed=changed,
        previous_count=len(curated_findings_for_output(state.curated_findings)),
        current_count=len(next_findings),
    )
    next_state = CurationState(
        round=decision.round,
        consecutive_no_change=consecutive_no_change,
        curated_findings=next_findings,
        history=[*state.history, decision],
    )
    return next_state, decision


def advance_curation_state(
    path: str | Path,
    findings: list[FindingRecord],
    *,
    no_change_patience: int = _NO_CHANGE_PATIENCE,
) -> tuple[CurationState, CurationDecision]:
    state = load_curation_state(path)
    next_state, decision = apply_curation_round(
        state,
        findings,
        no_change_patience=no_change_patience,
    )
    write_curation_state(path, next_state)
    return next_state, decision
