# Changelog

## 2026-10-20: fixes found by a source read

These were found by reading the source against its own documentation after release, not by the earlier test and review passes. Each fix has a regression test in
`tests/test_findings_20261020.py` that failed before the fix, and each fix was checked by undoing it and confirming a test fails. Behaviour that changed is listed under "Changed".

### Fixed
- **`resume()` lifted the halt before recording it.** A failed chain write left the terminal running with no record. It now records first and stays halted if it cannot.
- **`halt()` killed the running program but a multi-stage line (`a && b`, `a ; b`) went on to start the next stage.** The halted flag is now checked between stages and just after a program starts.
