# vega-terminal-sdk — Capabilities

Capability inventory: every capability this repo publishes, why a policy-or-prompt-level approach structurally cannot provide it, where it is enforced in code, which test demonstrates it, and the honest limit. Everything below traces to `src/vega_terminal/` and `tests/`; test counts come from STATUS.md (72 tests in 4 files). Nothing here is a claim about operating-system sandboxing, expert review or legal compliance.

*Correction, 2026-10-20: an earlier version of this file was the superproof kit's capabilities text, committed here by mistake. This is the terminal kit's own.*

## 1. Who typed it, and what it is allowed to do

| # | Capability | Why a prompt-policy approach structurally cannot offer it | Where enforced in code | Test | Honest limit |
|---|---|---|---|---|---|
| T1 | **The channel decides the origin.** `run_human` and `run_agent` are separate entry points; nothing inside a line can claim to be human | A prompt can only ask the agent to say who it is; here the caller's entry point is the identity | `Session.run_human`, `Session.run_agent`, `Session.plan(origin)` | `test_agent_reads_without_signature_and_is_recorded`, `test_human_runs_ordinary_lines_but_human_only_needs_a_signature` | The kit cannot tell who is at the keyboard: keystroke injection into `run_human` defeats it |
| T2 | **An agent auto-runs READ only; a person auto-runs everything except HUMAN_ONLY** | "Ask before doing anything risky" is a hope; here the class of the worst stage decides | `Session._run_locked`, `policy.classify_stage` | `test_sensitive_and_outside_reads_are_denied_for_agent`, `test_human_runs_ordinary_lines_but_human_only_needs_a_signature` | Classification is rule-based and conservative, not understanding |
| T3 | **Publishing, paying and key changes are HUMAN_ONLY for everyone**, agent or person: they need a human-signed commitment | A policy can be talked around; the jacket's list is code and the commitment is a signature | `Session._run_locked` with the jacket's `ExitGate` | `test_publishing_paying_and_keys_are_human_only_for_everyone` | Only as strong as the human-key custody the jacket assumes |
| T4 | **A signature authorises one exact line in one folder, once**, within its lease | "Approved" flags get reused for other commands | `Session.params_for`, exit gate burn | `test_a_signature_is_single_use`, `test_a_signature_for_one_line_does_not_run_another`, `test_an_expired_lease_is_refused` | The lease cap and single use come from the jacket kit |

## 2. What is refused before anything runs

| # | Capability | Why a prompt-policy approach structurally cannot offer it | Where enforced in code | Test | Honest limit |
|---|---|---|---|---|---|
| T5 | **No shell is used, so shell expansion never runs**: `$`, backticks, `^`, `%VAR%`, braces and parentheses make a line OPAQUE and it is refused | A model told not to emit shell tricks can still emit them; here there is no shell to expand them | `lex.split` | `test_expansion_is_opaque`, `test_expansion_and_shell_syntax_never_pass_as_read` | Redirects are limited to `>` and `>>` on the last stage |
| T6 | **Background `&`, input `<` and numbered `2>` are refused; script launchers (`.bat`, `.ps1` ...) and look-alike or invisible program names are refused** | A deny-list in a prompt is easy to evade with a look-alike character | `lex.split`, `policy.program_name` | `test_unsupported_syntax_is_refused`, `test_script_launchers_are_refused_outright`, `test_invisible_and_look_alike_characters_are_refused` | A new launcher type nobody listed is classified UNKNOWN, not allowed |
| T7 | **The workspace is a wall, checked after symlinks and junctions**; secret-looking paths need a signature | "Stay in the project folder" cannot be enforced by asking | `pathrules.check` | `test_every_way_out_of_the_workspace_is_outside`, `test_a_junction_pointing_outside_is_outside`, `test_sensitive_names_need_a_signature` | Path rules cover the paths a line names, not what a program opens by itself |

## 3. What is recorded, and when

| # | Capability | Why a prompt-policy approach structurally cannot offer it | Where enforced in code | Test | Honest limit |
|---|---|---|---|---|---|
| T8 | **Intent is recorded before anything runs; if it cannot be recorded, nothing runs** | A log written after the fact can be skipped; here the record is a precondition | `Session._run_locked` (`TERMINAL_INTENT`) | `test_if_the_intent_cannot_be_recorded_nothing_runs`, `test_every_decision_leaves_a_record` | The chain is hash-linked, not signed: someone who can rewrite every replica can forge it |
| T9 | **The result is recorded before the output is returned; if it cannot be recorded, the output is withheld** | Output returned first and logged later can be lost | `Session._run_locked` (`TERMINAL_RESULT`) | `test_if_the_result_cannot_be_recorded_the_output_is_withheld` | Records hold hashes and counts, never the output text |
| T10 | **A tampered chain stops every run; credentials in a command line are never recorded; the record holds hashes, not output** | Plain logs can be edited and often hold the secret that was typed | `Session._run_locked`, `Session._line_for_record` | `test_a_tampered_chain_stops_every_run`, `test_credentials_in_the_command_line_are_not_recorded`, `test_the_record_holds_hashes_and_counts_not_output` | Credential detection is pattern matching |

## 4. How it runs

| # | Capability | Why a prompt-policy approach structurally cannot offer it | Where enforced in code | Test | Honest limit |
|---|---|---|---|---|---|
| T11 | **Programs run with a clean environment**, a trusted PATH that never includes the workspace, a time limit, an output cap and a survivor check that kills detached descendants | Whatever the agent's shell inherits, the program inherits | `Session._env`, `Session._execute`, `ProcessJob` | `test_the_program_sees_a_clean_environment`, `test_the_trusted_path_never_includes_the_workspace_or_relative_folders`, `test_timeout_kills_the_job`, `test_a_detached_grandchild_is_found_and_killed`, `test_an_output_flood_is_capped` | The Windows job object is a process group, not an operating-system sandbox; Linux and macOS fall back to a basic subprocess |
| T12 | **Terminal escape sequences are removed and credential-shaped lines are replaced** in output, including a credential split across lines | Output goes to a screen and a model; scrubbing it is a code path, not a request | `redact.strip_controls`, `redact.scrub` | `test_escape_sequences_removed`, `test_credential_lines_replaced`, `test_a_credential_split_by_carriage_returns_is_still_caught` | Best-effort pattern matching: encoded or oddly split secrets can evade it |
| T13 | **Git is run with its risky features off** (no hooks path, no external diff, no text conversion, no pager) | An agent allowed to run `git log` can be handed a repository that runs code | `GIT_SAFE` flags in `Session._stage` | `tests/redteam_2_session.py` (git cases) | Only known dangerous flags and configs are blocked |

## 5. Stopping

| # | Capability | Why a prompt-policy approach structurally cannot offer it | Where enforced in code | Test | Honest limit |
|---|---|---|---|---|---|
| T14 | **`halt()` kills the running program, refuses every later line, and stops the remaining stages of the line in progress; only a human-signed restore resumes**, and the resume is recorded before the terminal runs again | "Stop when asked" depends on the agent noticing; here the flag is checked between stages and after each program starts | `Session.halt`, `Session.resume`, `Session._execute` | `test_halt_refuses_until_a_signed_restore`, `test_halt_stops_a_running_command_and_blocks_the_next`, `tests/test_findings_20261020.py` | A halt cannot reach a program that has detached beyond the job object |
| T15 | **Lines run one at a time**, so concurrent callers cannot corrupt the chain | Two interleaved sessions write interleaved records | `Session._run` (lock) | `test_concurrent_lines_do_not_corrupt_the_chain` | One session object per process |

## What this does not claim

No independent security review, no expert cryptography review, no production hardening, no legal advice (the licence is a draft not reviewed by an attorney). See SPEC.md section "Non-guarantees" and the README's "What it cannot do".
