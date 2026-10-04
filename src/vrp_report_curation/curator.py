from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from enum import StrEnum
from html import unescape
from pathlib import Path
from typing import Iterable, Sequence


REPORT_EXTENSIONS = {".docx", ".pdf", ".md", ".txt"}
TEXT_EXTENSIONS = {".csv", ".json", ".md", ".txt", ".yaml", ".yml"}
HARD_EXCLUSIONS = {
    "archive", "attachment", "backup", "burp", "checksum", "evidence", "exhibit",
    "har", "hash", "index", "ledger", "manifest", "notes", "original", "private",
    "raw", "readme", "screenshot", "summary", "takeout", "unredacted", "validation",
}
PRIVATE_DIRECTORY_MARKERS = {"original", "originals", "private", "raw", "unredacted"}
FILENAME_SIGNALS = {
    "submit this first": 90,
    "reconsideration": 75,
    "final reviewed": 70,
    "portal ready": 55,
    "steelman": 45,
    "appeal": 40,
    "report": 35,
    "final": 25,
}
SECTION_SIGNALS = {
    "title": ("title", "security report", "appeal", "reconsideration"),
    "summary": ("summary", "executive summary", "overview"),
    "scenario": ("attack scenario", "threat scenario", "exploit scenario"),
    "impact": ("impact", "security impact"),
    "steps": ("steps to reproduce", "reproduction", "repro steps"),
    "expected": ("observed vs expected", "expected behavior", "actual behavior"),
    "evidence": ("evidence", "supporting artifacts", "proof"),
    "product": ("affected product", "affected component", "scope"),
    "roles": ("attacker", "victim", "threat actor"),
    "conclusion": ("requested action", "conclusion", "request for review"),
}
COPY_SUFFIX = re.compile(
    r"(?:\s+(?:copy|duplicate)(?:\s+\d+)?|\s*\(copy\s*\d*\)|\s*\(\d+\))$",
    re.IGNORECASE,
)
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


class Relationship(StrEnum):
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    CONTENT_DUPLICATE = "CONTENT_DUPLICATE"
    PROBABLE_COPY = "PROBABLE_COPY"
    DISTINCT_VERSION = "DISTINCT_VERSION"
    DISTINCT_EVIDENCE = "DISTINCT_EVIDENCE"


@dataclass
class Candidate:
    path: Path
    ticket_id: str
    role: str
    sha256: str
    size: int
    modified_ns: int
    review_path: Path | None = None
    text: str = ""
    normalized_text_hash: str = ""
    report_score: int = 0
    positive_signals: list[str] = field(default_factory=list)
    negative_signals: list[str] = field(default_factory=list)
    hard_exclusions: list[str] = field(default_factory=list)
    report_like: bool = False
    reviewer_safe: bool = False
    eligible: bool = False


@dataclass(frozen=True)
class DedupeDiagnostic:
    ticket_id: str
    kept_file: str
    discarded_file: str
    relationship: str
    sha256_equal: bool
    normalized_text_equal: bool
    similarity: float
    reason_kept: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_text(text: str) -> str:
    return " ".join(TOKEN_PATTERN.findall(text.casefold()))


def normalized_text_hash(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def extract_text(path: Path) -> str:
    suffix = path.suffix.casefold()
    if suffix in TEXT_EXTENSIONS:
        return path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".docx":
        try:
            with zipfile.ZipFile(path) as archive:
                xml = archive.read("word/document.xml").decode("utf-8", errors="replace")
            return unescape(re.sub(r"<[^>]+>", " ", xml))
        except (KeyError, OSError, zipfile.BadZipFile):
            return ""
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader

            return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
        except Exception:
            return ""
    return ""


def normalized_name(path: Path) -> str:
    return " ".join(TOKEN_PATTERN.findall(path.stem.casefold()))


def hard_exclusions(path: Path) -> list[str]:
    haystack = " ".join(TOKEN_PATTERN.findall(str(path).casefold()))
    return sorted(token for token in HARD_EXCLUSIONS if re.search(rf"\b{re.escape(token)}\b", haystack))


def is_reviewer_safe(path: Path) -> bool:
    parts = {token for part in path.parts for token in TOKEN_PATTERN.findall(part.casefold())}
    return not bool(parts & PRIVATE_DIRECTORY_MARKERS) and not bool(hard_exclusions(path))


def report_sections(text: str) -> list[str]:
    lowered = text.casefold()
    return [name for name, signals in SECTION_SIGNALS.items() if any(signal in lowered for signal in signals)]


def is_report_like(path: Path, text: str) -> bool:
    if path.suffix.casefold() not in REPORT_EXTENSIONS or hard_exclusions(path):
        return False
    sections = report_sections(text)
    name_signals = sum(signal in normalized_name(path) for signal in FILENAME_SIGNALS)
    return len(sections) >= 4 and (name_signals >= 1 or len(sections) >= 6)


def assess_report_candidate(candidate: Candidate) -> Candidate:
    review_path = candidate.review_path or candidate.path
    name = normalized_name(review_path)
    candidate.hard_exclusions = hard_exclusions(review_path)
    candidate.reviewer_safe = is_reviewer_safe(review_path)
    candidate.report_like = is_report_like(review_path, candidate.text)
    sections = report_sections(candidate.text)
    candidate.positive_signals = [signal for signal in FILENAME_SIGNALS if signal in name]
    candidate.positive_signals.extend(f"section:{section}" for section in sections)
    candidate.negative_signals = list(candidate.hard_exclusions)
    if not candidate.text.strip():
        candidate.negative_signals.append("no_extractable_text")
    candidate.report_score = sum(FILENAME_SIGNALS[signal] for signal in FILENAME_SIGNALS if signal in name)
    candidate.report_score += len(sections) * 12
    candidate.report_score += 15 if review_path.suffix.casefold() == ".docx" else 10 if review_path.suffix.casefold() == ".pdf" else 0
    candidate.report_score -= len(candidate.negative_signals) * 100
    candidate.eligible = candidate.reviewer_safe and candidate.report_like and not candidate.hard_exclusions
    return candidate


def candidate_from_path(path: Path, ticket_id: str, role: str = "report", review_path: Path | None = None) -> Candidate:
    stat = path.stat()
    text = extract_text(path) if role == "report" else ""
    candidate = Candidate(
        path=path.resolve(),
        ticket_id=ticket_id,
        role=role,
        sha256=sha256_file(path),
        size=stat.st_size,
        modified_ns=stat.st_mtime_ns,
        review_path=review_path,
        text=text,
        normalized_text_hash=normalized_text_hash(text) if text else "",
    )
    return assess_report_candidate(candidate) if role == "report" else candidate


def logical_stem(path: Path) -> str:
    stem = re.sub(r"[_-]+", " ", path.stem).strip()
    previous = None
    while stem != previous:
        previous = stem
        stem = COPY_SUFFIX.sub("", stem).strip()
    return " ".join(TOKEN_PATTERN.findall(stem.casefold()))


def representative_key(candidate: Candidate) -> tuple[int, int, int, int, int]:
    format_score = {".docx": 3, ".pdf": 2, ".md": 1, ".txt": 0}.get(candidate.path.suffix.casefold(), -1)
    return (
        int(candidate.reviewer_safe),
        len(report_sections(candidate.text)),
        candidate.report_score,
        format_score,
        candidate.modified_ns,
    )


def _relationship(left: Candidate, right: Candidate) -> tuple[Relationship, float]:
    if left.sha256 == right.sha256:
        return Relationship.EXACT_DUPLICATE, 1.0
    if left.normalized_text_hash and left.normalized_text_hash == right.normalized_text_hash:
        return Relationship.CONTENT_DUPLICATE, 1.0
    left_text = normalize_text(left.text)
    right_text = normalize_text(right.text)
    similarity = SequenceMatcher(None, left_text, right_text, autojunk=False).ratio() if left_text and right_text else 0.0
    if logical_stem(left.path) == logical_stem(right.path) and similarity >= 0.97:
        return Relationship.PROBABLE_COPY, similarity
    return Relationship.DISTINCT_VERSION, similarity


def dedupe_report_candidates(candidates: Sequence[Candidate]) -> tuple[list[Candidate], list[DedupeDiagnostic], list[DedupeDiagnostic]]:
    kept: list[Candidate] = []
    collapsed: list[DedupeDiagnostic] = []
    distinct: list[DedupeDiagnostic] = []
    for candidate in sorted(candidates, key=representative_key, reverse=True):
        duplicate_of: Candidate | None = None
        relationship = Relationship.DISTINCT_VERSION
        similarity = 0.0
        for existing in kept:
            relationship, similarity = _relationship(existing, candidate)
            if relationship is not Relationship.DISTINCT_VERSION:
                duplicate_of = existing
                break
            if logical_stem(existing.path) == logical_stem(candidate.path):
                distinct.append(
                    DedupeDiagnostic(candidate.ticket_id, str(existing.path), str(candidate.path), relationship, False, False, similarity, "material text differs; both retained")
                )
        if duplicate_of is None:
            kept.append(candidate)
            continue
        collapsed.append(
            DedupeDiagnostic(
                candidate.ticket_id,
                str(duplicate_of.path),
                str(candidate.path),
                relationship,
                duplicate_of.sha256 == candidate.sha256,
                bool(duplicate_of.normalized_text_hash and duplicate_of.normalized_text_hash == candidate.normalized_text_hash),
                similarity,
                "reviewer safety, completeness, content quality, format, then recency",
            )
        )
    kept.sort(key=representative_key, reverse=True)
    return kept, collapsed, distinct


def dedupe_evidence(candidates: Sequence[Candidate]) -> tuple[list[Candidate], list[DedupeDiagnostic]]:
    kept_by_hash: dict[str, Candidate] = {}
    diagnostics: list[DedupeDiagnostic] = []
    for candidate in candidates:
        existing = kept_by_hash.get(candidate.sha256)
        if existing is None:
            kept_by_hash[candidate.sha256] = candidate
            continue
        winner = max((existing, candidate), key=lambda item: (item.size, item.modified_ns))
        loser = candidate if winner is existing else existing
        kept_by_hash[candidate.sha256] = winner
        diagnostics.append(
            DedupeDiagnostic(candidate.ticket_id, str(winner.path), str(loser.path), Relationship.EXACT_DUPLICATE, True, False, 1.0, "identical bytes; retained stable representative")
        )
    return list(kept_by_hash.values()), diagnostics


def load_config(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    tickets = data.get("tickets")
    if not isinstance(tickets, list) or not tickets:
        raise ValueError("configuration requires a non-empty tickets list")
    if any(not isinstance(item, dict) for item in tickets):
        raise ValueError("every ticket must be an object with an id")
    ids = [item.get("id") for item in tickets]
    if any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", item) for item in ids) or len(ids) != len(set(ids)):
        raise ValueError("every ticket requires a unique, path-safe string id")
    return data


def route_ticket(path: Path, text: str, ticket_ids: Sequence[str]) -> str | None:
    haystack = f"{path} {text}"
    matches = [ticket_id for ticket_id in ticket_ids if ticket_id in haystack]
    return matches[0] if len(matches) == 1 else None


def scan_files(roots: Sequence[Path], config: dict) -> tuple[dict[str, list[Candidate]], list[Path]]:
    for root in roots:
        if not root.is_dir():
            raise ValueError(f"evidence root is not a directory: {root}")
    ticket_ids = [item["id"] for item in config["tickets"]]
    buckets = {ticket_id: [] for ticket_id in ticket_ids}
    ambiguous: list[Path] = []
    for root in roots:
        resolved_root = root.resolve()
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(resolved_root) or any(part.startswith("VRP_Best_Versions_") for part in path.parts):
                continue
            text = extract_text(path) if path.suffix.casefold() in REPORT_EXTENSIONS else ""
            ticket_id = route_ticket(path, text, ticket_ids)
            if ticket_id is None:
                if sum(ticket_id in f"{path} {text}" for ticket_id in ticket_ids) > 1:
                    ambiguous.append(path)
                continue
            review_path = path.relative_to(root)
            role = "report" if path.suffix.casefold() in REPORT_EXTENSIONS and is_report_like(review_path, text) else "evidence"
            buckets[ticket_id].append(candidate_from_path(path, ticket_id, role, review_path))
    return buckets, ambiguous


def copy_preserving_source(source: Path, destination: Path, expected_sha256: str) -> str:
    if source.is_symlink():
        raise ValueError(f"refusing a symlinked source: {source}")
    if sha256_file(source) != expected_sha256:
        raise RuntimeError(f"source changed since indexing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        if destination.is_file() and not destination.is_symlink() and sha256_file(destination) == expected_sha256:
            return "existing_copy"
        raise FileExistsError(f"refusing to overwrite an existing output: {destination}")
    with source.open("rb") as original, destination.open("xb") as copied:
        shutil.copyfileobj(original, copied)
    shutil.copystat(source, destination)
    if sha256_file(source) != expected_sha256 or sha256_file(destination) != expected_sha256:
        raise RuntimeError(f"source or copied output changed during copying: {source}")
    return "copy"


def write_diagnostics(path: Path, diagnostics: Iterable[DedupeDiagnostic]) -> None:
    rows = [asdict(item) for item in diagnostics]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(DedupeDiagnostic("", "", "", "", False, False, 0.0, "")).keys()))
        writer.writeheader()
        writer.writerows(rows)


def curate(roots: Sequence[Path], config_path: Path, output: Path | None, dry_run: bool) -> dict:
    if output is not None:
        resolved_output = output.resolve()
        if any((parent / ".git").exists() for parent in (resolved_output, *resolved_output.parents)):
            raise ValueError("output must be outside every Git checkout")
        for root in roots:
            resolved_root = root.resolve()
            if resolved_output.is_relative_to(resolved_root) or resolved_root.is_relative_to(resolved_output):
                raise ValueError("output and evidence roots must be in separate directory trees")
    config = load_config(config_path)
    buckets, ambiguous = scan_files(roots, config)
    if not dry_run and output is not None:
        output.mkdir(parents=True, exist_ok=False)
        (output / ".incomplete").write_text("Build in progress; do not use this bundle yet.\n", encoding="utf-8")
    result: dict = {"tickets": {}, "ambiguous_files": [str(path) for path in ambiguous]}
    all_diagnostics: list[DedupeDiagnostic] = []
    manifest: list[dict] = []
    for ticket in config["tickets"]:
        ticket_id = ticket["id"]
        reports = [candidate for candidate in buckets[ticket_id] if candidate.role == "report" and candidate.eligible]
        evidence = [candidate for candidate in buckets[ticket_id] if candidate.role == "evidence"]
        reports, collapsed, distinct = dedupe_report_candidates(reports)
        evidence, evidence_dupes = dedupe_evidence(evidence)
        all_diagnostics.extend(collapsed + distinct + evidence_dupes)
        lead = reports[0] if reports else None
        result["tickets"][ticket_id] = {
            "canonical": str(lead.path) if lead else "NEEDS_MANUAL_REVIEW",
            "top_10": [str(candidate.path) for candidate in reports[:10]],
            "eligible_reports": len(reports),
            "unique_evidence": len(evidence),
        }
        if dry_run or output is None or lead is None:
            continue
        selected = [("report", lead), *(("evidence", item) for item in evidence)]
        for role, candidate in selected:
            destination = output / ticket_id / role / candidate.sha256 / candidate.path.name
            mode = copy_preserving_source(candidate.path, destination, candidate.sha256)
            manifest.append({
                "ticket_id": ticket_id,
                "role": role,
                "source": str(candidate.path),
                "output": str(destination),
                "sha256": candidate.sha256,
                "mode": mode,
            })
    if not dry_run and output is not None:
        (output / "curation_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        with (output / "manifest.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["ticket_id", "role", "source", "output", "sha256", "mode"])
            writer.writeheader()
            writer.writerows(manifest)
        write_diagnostics(output / "dedupe_diagnostics.csv", all_diagnostics)
        (output / ".incomplete").unlink()
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Curate reviewer-safe canonical reports without dropping unique evidence.")
    parser.add_argument("--roots", nargs="+", type=Path, required=True)
    parser.add_argument("--tickets", type=Path, required=True, help="Local ticket configuration JSON")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.dry_run and args.output is None:
        print("--output is required unless --dry-run is set", file=sys.stderr)
        return 2
    result = curate(args.roots, args.tickets, args.output, args.dry_run)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
