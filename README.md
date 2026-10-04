# Evidence Ledger

[![Validate synthetic portfolio](https://github.com/Josh-Shultis/evidence-ledger/actions/workflows/validate.yml/badge.svg)](https://github.com/Josh-Shultis/evidence-ledger/actions/workflows/validate.yml)

Evidence Ledger is a local Python tool for organizing security-report evidence without silently throwing away important differences between files.

I built it because real research folders get messy fast: multiple report drafts, repeated filenames, revised screenshots, exported PDFs, and several files tied to the same ticket. A filename or ticket number is not enough to decide that two artifacts are the same.

## What this demonstrates

- Exact file identity with SHA-256.
- Report-version comparison using extracted text.
- Evidence deduplication only when the underlying bytes are identical.
- Manual-review states when the tool cannot make a safe choice.
- Copy-based bundle creation that leaves the original evidence untouched.
- Manifests and diagnostics that show why each file was selected or kept separate.

The public example is entirely synthetic.

## Try the synthetic example

Requires Python 3.11 or later.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\vrp-curate.exe --roots examples/corpus --tickets examples/tickets.synthetic.json --dry-run
```

Linux or macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/vrp-curate --roots examples/corpus --tickets examples/tickets.synthetic.json --dry-run
```

The synthetic corpus contains one case with an eligible report and multiple distinct supporting artifacts. A second case deliberately has no eligible lead report so the tool takes the `NEEDS_MANUAL_REVIEW` path instead of inventing a choice.

No model, API key, vendor account, or real evidence is required.

## Build a bundle

Use a new absolute output directory outside this repository and outside every other Git checkout:

```sh
vrp-curate \
  --roots examples/corpus \
  --tickets examples/tickets.synthetic.json \
  --output /absolute/local/path/evidence-ledger-demo-001
```

The build writes:

- `curation_result.json`
- `manifest.csv`
- `dedupe_diagnostics.csv`
- copied selected artifacts

Copied files are nested under their source SHA-256, so different files with the same filename cannot overwrite each other.

The tool does not hardlink to originals and does not overwrite an existing output directory. An interrupted or failed build leaves `.incomplete`, which is intentionally not treated as a completed bundle.

## Review the implementation

| Question | Where to look |
| --- | --- |
| Which report can lead a case? | `is_report_like`, `is_reviewer_safe`, and `assess_report_candidate` in `src/vrp_report_curation/curator.py` |
| When are report versions collapsed? | `dedupe_report_candidates` and `tests/test_curator.py` |
| When is evidence collapsed? | `dedupe_evidence` — identical SHA-256 only |
| How are originals protected? | `copy_preserving_source`, output-root checks, and `manifest.csv` |
| What is kept for human review? | `top_10`, `ambiguous_files`, and `NEEDS_MANUAL_REVIEW` in the JSON result |

## Why this matters for security research

The tool is deliberately conservative. If two files are different, it keeps that difference visible. If report selection is ambiguous, it stops and asks for human review.

That matters because evidence handling can change the conclusion of a case. A newer draft is not automatically a better report, two files with the same name are not automatically duplicates, and a hash proves byte identity rather than truth or importance.

## Scope

This is a single-user local research aid. PDF and DOCX text extraction can miss layout details, and report selection still requires human review. The tool does not decide whether a vendor finding is valid or what severity it deserves.

Keep raw Burp captures, HAR files, real reports, generated bundles, credentials, and other originals outside all Git checkouts. The publication checker and `.gitignore` are additional safeguards, not substitutes for reviewing what is staged before a public push.

## License

MIT; see [LICENSE](LICENSE).
