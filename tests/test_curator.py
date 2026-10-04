from __future__ import annotations

import json
from pathlib import Path

from vrp_report_curation.curator import (
    Candidate,
    Relationship,
    assess_report_candidate,
    dedupe_evidence,
    dedupe_report_candidates,
    candidate_from_path,
    copy_preserving_source,
    curate,
    is_report_like,
    is_reviewer_safe,
    logical_stem,
    normalized_text_hash,
    route_ticket,
    sha256_file,
)


REPORT_TEXT = """
Title: Synthetic Security Appeal
Summary: A synthetic workflow produced an unexpected result.
Attack scenario: An attacker controls a test input and a victim opens it.
Impact: The synthetic object crosses a defined trust boundary.
Steps to reproduce: Create the fixture, invoke the test, and inspect state.
Observed vs expected: The object changed; it should have remained unchanged.
Evidence: Synthetic logs and an after-state fixture support the result.
Affected product: Example Workspace.
Attacker and victim: Two synthetic principals are used.
Requested action: Review the boundary and correct the behavior.
"""


def make_candidate(path: Path, text: str, sha: str, modified: int = 1) -> Candidate:
    candidate = Candidate(
        path=path,
        ticket_id="CASE-DEMO-001",
        role="report",
        sha256=sha,
        size=len(text),
        modified_ns=modified,
        text=text,
        normalized_text_hash=normalized_text_hash(text),
    )
    return assess_report_candidate(candidate)


def test_report_like_requires_structure_and_reviewer_safety():
    path = Path("CASE-DEMO-001_APPEAL_FINAL_REVIEWED.md")
    assert is_report_like(path, REPORT_TEXT)
    assert is_reviewer_safe(path)
    assert make_candidate(path, REPORT_TEXT, "a" * 64).eligible


def test_support_and_private_artifacts_never_become_leads():
    validation = Path("CASE-DEMO-001_PDF_VALIDATION.txt")
    unredacted = Path("private/CASE-DEMO-001_FINAL_UNREDACTED.docx")
    assert not is_report_like(validation, REPORT_TEXT)
    assert not is_reviewer_safe(unredacted)


def test_logical_stem_removes_only_copy_suffixes():
    names = [
        "CASE-DEMO-001_APPEAL_REPORT.md",
        "CASE-DEMO-001_APPEAL_REPORT - Copy.md",
        "CASE-DEMO-001_APPEAL_REPORT (1).md",
        "CASE-DEMO-001_APPEAL_REPORT_duplicate_2.md",
    ]
    assert len({logical_stem(Path(name)) for name in names}) == 1
    assert logical_stem(Path("CASE-DEMO-001_APPEAL_REPORT_v2.md")).endswith("v2")


def test_same_stem_materially_different_content_keeps_both():
    first = make_candidate(Path("CASE-DEMO-001_APPEAL_REPORT.md"), REPORT_TEXT, "a" * 64)
    second_text = REPORT_TEXT.replace("unexpected result", "different corrected mechanism").replace("object changed", "authorization changed")
    second = make_candidate(Path("CASE-DEMO-001_APPEAL_REPORT - Copy.md"), second_text, "b" * 64)
    kept, collapsed, distinct = dedupe_report_candidates([first, second])
    assert len(kept) == 2
    assert not collapsed
    assert distinct and distinct[0].relationship == Relationship.DISTINCT_VERSION


def test_normalized_content_duplicate_collapses_export_containers():
    docx = make_candidate(Path("CASE-DEMO-001_FINAL_REPORT.docx"), REPORT_TEXT, "a" * 64)
    pdf = make_candidate(Path("CASE-DEMO-001_FINAL_REPORT.pdf"), REPORT_TEXT.upper(), "b" * 64)
    kept, collapsed, _ = dedupe_report_candidates([pdf, docx])
    assert len(kept) == 1
    assert kept[0].path.suffix == ".docx"
    assert collapsed[0].relationship == Relationship.CONTENT_DUPLICATE


def test_same_stem_extremely_similar_text_is_probable_copy():
    first = make_candidate(Path("CASE-DEMO-001_FINAL_REPORT.md"), REPORT_TEXT + "\nAppendix marker alpha.", "c" * 64)
    copy = make_candidate(Path("CASE-DEMO-001_FINAL_REPORT - Copy.md"), REPORT_TEXT + "\nAppendix marker beta.", "d" * 64)
    kept, collapsed, distinct = dedupe_report_candidates([first, copy])
    assert len(kept) == 1
    assert not distinct
    assert collapsed[0].relationship == Relationship.PROBABLE_COPY


def test_evidence_only_collapses_identical_bytes():
    first = Candidate(Path("completion-trace.txt"), "CASE-DEMO-001", "evidence", "a" * 64, 10, 1)
    copy = Candidate(Path("completion-trace-copy.txt"), "CASE-DEMO-001", "evidence", "a" * 64, 10, 2)
    after_state = Candidate(Path("completion-trace-after-state.txt"), "CASE-DEMO-001", "evidence", "b" * 64, 10, 3)
    kept, diagnostics = dedupe_evidence([first, copy, after_state])
    assert len(kept) == 2
    assert diagnostics[0].relationship == Relationship.EXACT_DUPLICATE


def test_multi_ticket_match_is_not_assigned():
    assert route_ticket(Path("mixed.txt"), "CASE-DEMO-001 CASE-DEMO-002", ["CASE-DEMO-001", "CASE-DEMO-002"]) is None


def test_copy_does_not_link_or_modify_source(tmp_path: Path):
    source = tmp_path / "source.txt"
    destination = tmp_path / "output" / "source.txt"
    source.write_text("synthetic", encoding="utf-8")
    mode = copy_preserving_source(source, destination, sha256_file(source))
    assert mode == "copy"
    assert destination.read_text(encoding="utf-8") == "synthetic"
    destination.write_text("changed copy", encoding="utf-8")
    assert source.read_text(encoding="utf-8") == "synthetic"


def test_review_path_ignores_parent_directory_name(tmp_path: Path):
    report = tmp_path / "private" / "CASE-DEMO-001_APPEAL_FINAL_REVIEWED.md"
    report.parent.mkdir()
    report.write_text(REPORT_TEXT, encoding="utf-8")
    candidate = candidate_from_path(report, "CASE-DEMO-001", review_path=Path(report.name))
    assert candidate.eligible


def test_build_keeps_same_name_evidence_separate(tmp_path: Path):
    root = tmp_path / "evidence"
    report = root / "CASE-DEMO-001_APPEAL_FINAL_REVIEWED.md"
    report.parent.mkdir()
    report.write_text(REPORT_TEXT, encoding="utf-8")
    for folder, value in (("first", "alpha"), ("second", "beta")):
        item = root / folder / "CASE-DEMO-001_trace.txt"
        item.parent.mkdir()
        item.write_text(value, encoding="utf-8")
    config = tmp_path / "tickets.json"
    config.write_text(json.dumps({"tickets": [{"id": "CASE-DEMO-001"}]}), encoding="utf-8")
    output = tmp_path / "result"
    result = curate([root], config, output, dry_run=False)
    assert result["tickets"]["CASE-DEMO-001"]["unique_evidence"] == 2
    assert sorted(item.read_text(encoding="utf-8") for item in (output / "CASE-DEMO-001" / "evidence").glob("*/CASE-DEMO-001_trace.txt")) == ["alpha", "beta"]
    assert not (output / ".incomplete").exists()
