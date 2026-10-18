# vega-terminal-sdk

![vega-terminal-sdk](assets/tile.svg)

Governed terminal: every command line is classified, gated by who typed it, run inside a job object with a clean environment, its output scrubbed, and a hash-only transcript kept on a custody chain.

> **Licensing.** Source-available, not open source. Free for personal use; free for registered small businesses (under US$1M revenue and valuation); everyone else needs a commercial license (see LICENSE; for a commercial license write to jasonblasiak.ai.mail@gmail.com). Patent pending. Draft licence text, not yet reviewed by an attorney.

Package: `vega_terminal` (src layout). Depends on: vega-custody-sdk, vega-governance-jacket-sdk.

## Modules

| Module | What it does |
|---|---|
| `lex` | Splits a line into stages without a shell; expansion syntax, background jobs and unsupported redirects are refused as opaque. |
| `policy` | Classifies each stage (READ, WRITE, NETWORK, EXEC, UNKNOWN, DESTRUCTIVE, OUTSIDE, SENSITIVE, HUMAN_ONLY) and maps publish, pay and key changes to canonical HUMAN_ONLY actions. |
| `pathrules` | Workspace containment after symlinks; refuses network paths, device names, alternate data streams and secret-looking files. |
| `builtins` | Read commands run in Python with no subprocess (ls, cat, head, tail, wc, grep, pwd, echo, cd). |
| `redact` | Terminal escape sequences removed from output; credential-shaped lines (and pairs of neighbouring lines) replaced. |
| `session` | run_human / run_agent: intent recorded before anything runs, human-signed single-use commitment for anything an agent runs beyond reading, job object, time and output caps, halt and signed resume. |

## What it does NOT do (read this)

- It cannot tell who is typing: the app must feed keystrokes to run_human and agent output to run_agent, and an agent that can inject keystrokes into the person's terminal defeats it.
- Output scrubbing is pattern matching, not a seal: a secret split over three lines or encoded is not caught.
- Job-object containment is not an operating-system sandbox; a program can still use the user's real profile through system calls.
- git hardening covers the settings known to run programs; it is not a proof that every git read command is safe.

## Status

See STATUS.md. Tests: 67 tests in 3 files, all passing.  See SECURITY.md for the threat model.

## Run the tests

Put `src` of this repo and of the repos it depends on on PYTHONPATH, then run each file in `tests/`.
