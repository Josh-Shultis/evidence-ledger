# Evidence Ledger

A local Python tool for reviewing report versions and preserving distinct evidence. It proposes one lead report per case, keeps materially different versions visible, and records which files were selected. The included example is entirely synthetic.

## Why I built it

Security research can produce many drafts and supporting files with similar names. A shared filename or ticket ID does not prove two files are the same. Evidence Ledger uses file hashes for exact identity, extracted report text for report-version comparisons, and explicit manual-review results when it cannot make a safe choice.

## Try the synthetic example

Requires Python 3.11 or later. From a fresh clone on Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\vrp-curate.exe --roots examples/corpus --tickets examples/tickets.synthetic.json --dry-run
```

On Linux or macOS, use `.venv/bin/python` and `.venv/bin/vrp-curate` in the last two lines. Installation downloads `pypdf`; the example needs no model, API key, vendor account, or real evidence. The synthetic corpus has one structured report and two different supporting artifacts for `CASE-DEMO-001`. `CASE-DEMO-002` deliberately has no eligible report, illustrating the `NEEDS_MANUAL_REVIEW` path.

To build a bundle, supply a **new**, absolute output directory outside this repository and every other Git checkout:

```sh
vrp-curate --roots examples/corpus --tickets examples/tickets.synthetic.json --output /absolute/local/path/evidence-ledger-demo-001
```

The build writes `curation_result.json`, `manifest.csv`, and `dedupe_diagnostics.csv`, plus copied selected files. Each copied filename is nested under its source SHA-256 so different files with the same name cannot overwrite each other. The build does not hardlink to originals or overwrite an existing output directory. An interrupted or failed build leaves `.incomplete`; do not treat that directory as a finished bundle.

## Review the implementation

| Question | Where to look |
| --- | --- |
| Which report can lead a case? | `is_report_like`, `is_reviewer_safe`, and `assess_report_candidate` in `src/vrp_report_curation/curator.py` |
| When are reports collapsed? | `dedupe_report_candidates` and `tests/test_curator.py` |
| When is evidence collapsed? | `dedupe_evidence` (identical SHA-256 only) |
| How are originals protected? | `copy_preserving_source`, output-root checks, and `manifest.csv` |
| What is kept for human review? | `top_10`, `ambiguous_files`, and `NEEDS_MANUAL_REVIEW` in the JSON result |

## Scope and limits

This is a single-user, local research aid. Report eligibility and text similarity are heuristics; a human must inspect the chosen report and every important supporting artifact. SHA-256 proves byte identity, not source authority or a security claim. PDF and DOCX extraction may miss layout or text. The tool does not validate a vendor finding, infer impact, or decide whether a report should be submitted.

Keep raw Burp captures, HAR files, real reports, generated bundles, credentials, and other originals in local directories outside **all** Git checkouts. The `.gitignore` and publication checker are extra guards. Review every staged file and Git history before any public release.

## License

MIT; see [LICENSE](LICENSE).
