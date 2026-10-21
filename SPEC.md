# vega-terminal-sdk — Specification

**Spec v1.0 — 2026-10-19** — describes the published reference implementation as tested; where this document and the source disagree, the source wins.

## At a glance

| Property | Value |
|---|---|
| Package | `vega_terminal` (src layout) |
| Version | 0.1.0 |
| Python | ≥3.10 |
| Layer | 9 (interface) |
| Status | BUILT: lex, policy, pathrules, builtins, redact, session |
| Tests | 72 tests in 4 files, all passing |
| Declared deps | `vega-custody-sdk`, `vega-governance-jacket-sdk` |

## Table of contents

- [Purpose and scope](#purpose-and-scope)
- [Vocabulary](#vocabulary)
- [Components](#components)
  - [lex — shell-free line splitting](#lex--shell-free-line-splitting)
  - [policy — stage classification](#policy--stage-classification)
  - [pathrules — workspace containment](#pathrules--workspace-containment)
  - [builtins — in-process read commands](#builtins--in-process-read-commands)
  - [redact — output scrubbing](#redact--output-scrubbing)
  - [session — governed terminal session](#session--governed-terminal-session)
- [Guarantees and non-guarantees](#guarantees-and-non-guarantees)
- [Failure modes](#failure-modes)
- [Dependencies and layer rules](#dependencies-and-layer-rules)
- [Conformance](#conformance)

---

## Purpose and scope

This specification defines the behavior of the `vega_terminal` package: a governed terminal that classifies every command line, gates execution by origin (human vs agent) and risk class, runs commands in a contained environment, scrubs output, and records a hash-only transcript on an append-only custody chain. The specification covers the six modules in `src/vega_terminal/` and the `Session` class that orchestrates them.

**Out of scope:** the Electron terminal tab integration (designed, not built); any GUI or rendering layer; the custody DAG/ledger implementation (provided by `vega-custody-sdk`); the commitment signing and gate logic (provided by `vega-governance-jacket-sdk`); cryptographic primitives.

---

## Vocabulary

| Term | Definition |
|---|---|
| **stage** | One command in a pipeline or sequence (e.g., `cat a.txt`, `head -n 1`), split by `;`, `&&`, `||`, `|`, or newline. |
| **OPAQUE** | A line containing shell expansion syntax (`$`, `` ` ``, `^`, `%VAR%`, braces, parentheses) — refused because no shell expands it. |
| **class** | Risk classification of a stage: READ, WRITE, NETWORK, EXEC, UNKNOWN, DESTRUCTIVE, OUTSIDE, SENSITIVE, HUMAN_ONLY (mildest to worst). |
| **action** | Canonical name for a HUMAN_ONLY operation: `release_public`, `spend_funds`, `change_key_registry`, `restore_after_hard_stop`, or `terminal_exec` (default for non-HUMAN_ONLY signed lines). |
| **commitment** | A human-signed, single-use, time-limited note authorizing exactly one action with specific parameters; verified and burned by the exit gate. |
| **origin** | The channel a line arrived on: `human` (keystrokes from the person) or `agent` (output from a model/script/agent). |
| **intent record** | A `TERMINAL_INTENT` entry written to the custody DAG before execution, capturing origin, line hash, class, action, stages, commitment leaf. |
| **result record** | A `TERMINAL_RESULT` entry written after execution, capturing status, exit codes, output SHA-256, output length, redacted line count, truncated flag, survivor count, timed_out flag. |
| **fail-closed** | A design property: if any verification step fails (lexing, classification, signature, recording), the line is refused and nothing executes. |
| **workspace** | The root folder passed to `Session.__init__`; all paths are resolved relative to it and must stay inside after symlink resolution. |
| **scrub** | Best-effort replacement of credential-shaped lines (single lines and neighboring line pairs) with a marker; not a seal. |
| **job object** | Windows kernel object that groups processes; used to enforce clean environment, timeout, and survivor kill. |
| **survivor check** | After a command finishes, `ProcessJob.survivors()` counts detached descendant processes; if >0, they are killed and the run is marked failed. |

---

## Components

### lex — shell-free line splitting

**Role.** Split a command line into stages without invoking a shell; refuse any syntax a shell would expand.

**Public interface.**

- `lex.split(text: str) -> tuple[list[dict], bool]` — returns `(stages, opaque)`. Each stage: `{"words": list[str], "sep_after": ";"|"&&"|"||"|"|"|"|None, "redirect": (">"|">>", target)|None}`. `opaque=True` if expansion syntax detected.
- `lex.clean_line(text: str) -> str` — validates length, NUL, control/invisible characters; normalizes line endings.
- `lex.Refused` — exception raised on any refusal.

**Behavior.** On success: returns parsed stages and opaque flag. On failure: raises `Refused` with a descriptive message (NUL, over 8192 chars, control chars, unsupported separators `&` `<` `2>`, unterminated quotes, empty command, >16 stages, redirected stage feeding a pipe). The opaque flag means the line contained expansion syntax; callers must refuse opaque lines.

**Invariants.** No shell is ever invoked. A line with expansion syntax is never partially parsed — it is marked opaque whole. Background `&` and input redirection `<` are never supported. Numbered redirection `2>` is never supported.

---

### policy — stage classification

**Role.** Classify one stage (program + arguments) into a risk class and, where applicable, a canonical HUMAN_ONLY action name.

**Public interface.**

- `policy.classify_stage(words: list[str], root: str, cwd: str, piped: bool=False) -> dict` — returns `{"cls": str, "reasons": list[str], "action": str|None, "prog": str, "paths": list[str]}`.
- `policy.worst(classes: list[str]) -> str` — returns the worst class per `ORDER`.
- `policy.program_name(word: str) -> str` — normalizes a program name (ASCII only, no path, no launcher extensions, casefolded, `.exe` stripped); raises `Refused` on violation.
- Constants: `ORDER`, `BUILTIN_READ`, `BUILTIN_PATH_ARGS`, `GIT_READ`, `GIT_LIST_ONLY`, `GIT_BAD_FLAGS`, `GIT_BAD_PREFIX`, `GIT_HUMAN_ONLY`, `GIT_NETWORK`, `GIT_WRITE`, `GIT_DESTRUCTIVE`, `NETWORK_PROGS`, `EXEC_PROGS`, `DESTRUCTIVE_PROGS`, `WRITE_PROGS`, `HUMAN_PROGS`, `HUMAN_SUB`, `LAUNCHER_EXT`.

**Behavior.** On success: returns classification dict. Classification rules:

- Bare built-in read commands (ls, cat, head, tail, wc, grep, pwd, echo, cd) with workspace paths → READ.
- Git subcommands: read subcommands with safe flags → READ; list-only subcommands with only list flags → READ; write subcommands → WRITE; network subcommands → NETWORK; destructive subcommands → DESTRUCTIVE; bad flags (`--output`, `-c`, `-C`, etc.) → EXEC; `push` → HUMAN_ONLY (`release_public`).
- Programs in `HUMAN_PROGS` or `HUMAN_SUB` → HUMAN_ONLY with canonical action.
- Programs in `DESTRUCTIVE_PROGS` → DESTRUCTIVE.
- Programs in `EXEC_PROGS` → EXEC.
- Programs in `NETWORK_PROGS` → NETWORK.
- Programs in `WRITE_PROGS` → WRITE.
- Unknown programs → UNKNOWN (treated as EXEC).
- Any argument matching `-enc`, `-c`, `-exec`, `-delete`, etc. raises class to EXEC.
- Path arguments checked via `pathrules.check()`; `outside`/`device` flags raise to OUTSIDE; `sensitive` flags raise to SENSITIVE.
- Redirect targets checked same as path arguments; `>` on existing file → DESTRUCTIVE; `>` on new file → WRITE; `>>` → WRITE.

On failure: `program_name()` raises `Refused` for empty, non-ASCII, control chars, path forms, launcher extensions (`.bat`, `.cmd`, `.ps1`, `.vbs`, etc.).

**Invariants.** Classification is deterministic and depends only on the stage words, root, cwd, and piped flag. A program given by path (not bare name) is never READ. Launcher extensions are never executed. Git subcommand casefold prevents `PUSH` bypass. A line carrying two different HUMAN_ONLY actions is refused at the session level.

---

### pathrules — workspace containment

**Role.** Resolve a path argument against the workspace; detect outside, device, and sensitive paths.

**Public interface.**

- `pathrules.check(root: str, cwd: str, arg: str) -> tuple[str|None, set[str]]` — returns `(absolute_path or None, flags)` where flags ⊆ `{"outside", "sensitive", "device"}`.

**Behavior.** On success: returns resolved absolute path and flags. Resolution: replaces `/` with `\`; rejects UNC (`\\server\share`), device namespace, alternate data streams (`:`), drive-relative paths; rejects glob/tilde (`~`, `*`, `?`); resolves symlinks via `os.path.realpath`; checks `os.path.commonpath([root_real, target]) == root_real`; scans path components for sensitive names (`.env`, `*.pem`, `id_rsa`, `secret*`, `token*`, `.ssh`, `.aws`, `.gnupg`, etc.) and device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).

On failure: returns `(None, {"outside"})` for NUL, empty, UNC, device namespace, alternate data streams, drive-relative, glob/tilde.

**Invariants.** A path is allowed only if it stays inside the workspace after symlink resolution, is not a network/device/ADS path, and does not match sensitive patterns. No globbing or home expansion — refused rather than guessed.

---

### builtins — in-process read commands

**Role.** Run read commands in Python with no subprocess; each re-checks paths against the workspace.

**Public interface.**

- Functions: `pwd`, `echo`, `cd`, `ls` (aliased as `dir`), `cat` (aliased as `type`), `head`, `tail`, `wc`, `grep`.
- Each takes `(args: list[str], stdin: bytes, session: Session) -> tuple[bytes, int]`.
- `builtins.TABLE: dict[str, callable]` — maps command name to function.
- `builtins.BuiltinError` — exception raised on argument/path errors.

**Behavior.** On success: returns `(stdout_bytes, 0)`. All paths validated via `pathrules.check()`; `FILE_CAP` (1 MiB) limits file reads; `LIST_CAP` (1000) limits directory listings. `cd` updates `session.cwd`. `grep` supports `-i`, `-n`, `-l`, `-c`, `-v`, `-w`, `--ignore-case`, `--line-number`, `--count`; whole-word via `-w`; pattern is literal (not regex) for safety.

On failure: raises `BuiltinError` with descriptive message; caller converts to exit code 2.

**Invariants.** No subprocess is ever started. Every path is re-checked against the workspace (second look after policy). Standard input is used when no file arguments given (piped stages).

---

### redact — output scrubbing

**Role.** Remove terminal escape sequences and replace credential-shaped lines.

**Public interface.**

- `redact.strip_controls(text: str) -> str` — removes ESC sequences (OSC, CSI, DCS, PM, APC, etc.) and control characters except tab/newline; loops until no change (nested sequences).
- `redact.scrub(text: str) -> tuple[str, int]` — calls `strip_controls`, then `vega_custody.dag.dag.contains_credential` on each line and each pair of neighboring lines (joined with `\n` and with `""`); replaces flagged lines with `[REDACTED: credential-shaped line]`; returns `(scrubbed_text, replaced_count)`.

**Behavior.** On success: returns scrubbed text and count. Single lines and neighboring pairs are checked; a secret split over three or more lines, or encoded, is not caught.

**Invariants.** This is a seatbelt, not a seal. The record stores only the output SHA-256 and redacted line count, never the raw or scrubbed output text.

---

### session — governed terminal session

**Role.** Orchestrate lex → classify → gate → record intent → execute → scrub → record result; provide hard stop/resume.

**Public interface.**

- `Session.__init__(root: str, dag, exit_gate=None, timeout=30.0, session_id=None)` — `root` must exist; `dag` is a `vega_custody.dag.dag.Dag`; `exit_gate` is a `vega_jacket.gate.exit_gate.ExitGate` or `None`.
- `Session.run_human(line: str, signed: dict|None=None) -> dict`
- `Session.run_agent(line: str, signed: dict|None=None) -> dict`
- `Session.plan(line: str, origin: str) -> dict` — dry run; `origin` ∈ `{"human", "agent"}`.
- `Session.halt() -> bool` — kills running job, sets `halted=True`, records `TERMINAL_HALT`.
- `Session.resume(signed: dict)` — requires `restore_after_hard_stop` commitment; clears `halted`; records `TERMINAL_RESUME`.
- `Session.close()` — cleans up scratch directory.
- `Session.params_for(line: str) -> dict` — returns `{"line_sha256": str, "cwd": str}` for gate.
- `Session.TerminalRefused` — exception for invalid usage.

**Behavior.** `_run(line, origin, signed)` flow (every step fail-closed):

1. If `halted` → return `status="halted"`.
2. `plan(line, origin)` → if `refused`: record `TERMINAL_REFUSED` (best effort), return `status="refused"`.
3. If `need_signature`: require `exit_gate` and valid `signed` dict; call `gate.release(action, params, signed, route="human")`; on any exception → record `TERMINAL_DENIED`, return `status="denied"`; on success, capture commitment `leaf`.
4. Record `TERMINAL_INTENT` with `commitment_leaf`; on `DagError` → return `status="not_recorded"`.
5. `_execute(plan, line)`: iterate stages; built-ins via `builtins.TABLE`; external programs via `ProcessJob.start()` with clean env, timeout, output cap, survivor check; handle pipes (`|`), sequences (`;`, `&&`, `||`), redirects (`>`, `>>`).
6. `redact.scrub()` output; truncate to `OUT_CAP` (64 KiB).
7. Record `TERMINAL_RESULT`; on `DagError` → return `status="not_recorded"`, `output=""`, `recorded=False`.
8. Return result dict with `ok`, `status`, `output`, `exit_codes`, `redacted_lines`, `truncated`, `left_processes`, `timed_out`, `recorded`, `commitment_leaf`.

**Fail-closed points (with module+function):**

1. `lex.split()` → `lex.Refused` (line refused, nothing runs)
2. `policy.program_name()` → `lex.Refused` (bad program name refused)
3. `pathrules.check()` → flags raise classification to OUTSIDE/SENSITIVE/DESTRUCTIVE (agent needs signature, human may need signature)
4. `session.Session._run_locked()` line 121-122: `if self.halted` → immediate refuse
5. `session.Session._run_locked()` line 127-132: `plan["refused"]` → record `TERMINAL_REFUSED` (best effort), refuse
6. `session.Session._run_locked()` line 136-143: `need_signature` without valid gate/signature → record `TERMINAL_DENIED`, refuse
7. `session.Session._run_locked()` line 144-147: `TERMINAL_INTENT` record fails → refuse, nothing runs
8. `session.Session._execute()` line 319-326: timeout → kill job, `timed_out=True`; survivors → kill, `left_processes>0`, `ok=False`
9. `session.Session._run_locked()` line 156-158: `TERMINAL_RESULT` record fails → withhold output, `recorded=False`
10. `session.Session.resume()` line 182-187: no gate or invalid `restore_after_hard_stop` → raise `TerminalRefused`

**Invariants.** Origin is the channel, never inferred from text. Intent recorded before execution. Result recorded before output returned. Output withheld if result cannot be recorded. Halt persists until valid signed resume. Single-use commitments enforced by gate (replay denied). Two different HUMAN_ONLY actions in one line → refused.

---

## Guarantees and non-guarantees

### Guarantees

| Guarantee | Module | Test demonstrating |
|---|---|---|
| Shell expansion syntax never executes | `lex.split()` | `test_expansion_is_opaque`, `test_expansion_and_shell_syntax_never_pass_as_read` |
| Background `&`, input `<`, numbered `2>` refused | `lex.split()` | `test_unsupported_syntax_is_refused`, `test_background_redirection_and_numbered_forms_are_refused` |
| Launcher extensions (`.bat`, `.ps1`, etc.) refused | `policy.program_name()` | `test_script_launchers_are_refused_outright` |
| Non-ASCII/control-char program names refused | `policy.program_name()` | `test_invisible_and_look_alike_characters_are_refused` |
| Workspace containment after symlinks | `pathrules.check()` | `test_every_way_out_of_the_workspace_is_outside`, `test_a_junction_pointing_outside_is_outside` |
| Sensitive paths require signature | `pathrules.check()` | `test_sensitive_names_need_a_signature` |
| Agent auto-runs READ only | `session.Session._run_locked()` | `test_agent_reads_without_signature_and_is_recorded`, `test_sensitive_and_outside_reads_are_denied_for_agent` |
| Human auto-runs non-HUMAN_ONLY | `session.Session._run_locked()` | `test_human_runs_ordinary_lines_but_human_only_needs_a_signature` |
| HUMAN_ONLY needs signed commitment (both origins) | `session.Session._run_locked()` | `test_publishing_paying_and_keys_are_human_only_for_everyone` |
| Signature is single-use and line-specific | `session.Session._run_locked()` + gate | `test_a_signature_is_single_use`, `test_a_signature_for_one_line_does_not_run_another`, `test_a_signature_for_another_folder_is_refused` |
| Expired lease refused | gate + session | `test_an_expired_lease_is_refused` |
| Intent recorded before execution | `session.Session._run_locked()` | `test_if_the_intent_cannot_be_recorded_nothing_runs` |
| Result recorded before output returned | `session.Session._run_locked()` | `test_if_the_result_cannot_be_recorded_the_output_is_withheld` |
| Output withheld if result not recorded | `session.Session._run_locked()` | `test_if_the_result_cannot_be_recorded_the_output_is_withheld` |
| Tampered chain stops runs | `session.Session._run_locked()` + DAG | `test_a_tampered_chain_stops_every_run` |
| Credentials in command line not recorded | `session.Session._line_for_record()` | `test_credentials_in_the_command_line_are_not_recorded` |
| Record holds hashes/counts, not output | `session.Session._run_locked()` | `test_the_record_holds_hashes_and_counts_not_output` |
| Every decision leaves a record | `session.Session._run_locked()` | `test_every_decision_leaves_a_record` |
| Programs run in clean environment | `session.Session._env()` | `test_the_program_sees_a_clean_environment`, `test_the_trusted_path_never_includes_the_workspace_or_relative_folders`, `test_a_program_in_the_workspace_is_not_found_by_bare_name` |
| Timeout kills job | `session.Session._execute()` | `test_timeout_kills_the_job`, `test_a_runaway_program_is_stopped_at_the_time_limit` |
| Survivor check kills detached descendants | `session.Session._execute()` | `test_a_detached_grandchild_is_found_and_killed` |
| Output cap enforced | `session.Session._execute()` | `test_an_output_flood_is_capped` |
| Escape sequences removed from output | `redact.strip_controls()` | `test_escape_sequences_removed`, `test_terminal_escape_sequences_from_a_program_are_removed` |
| Credential lines replaced in output | `redact.scrub()` | `test_credential_lines_replaced`, `test_credential_lines_from_a_program_are_replaced`, `test_a_credential_split_by_carriage_returns_is_still_caught` |
| Halt refuses until signed resume | `session.Session.halt()`, `resume()` | `test_halt_refuses_until_a_signed_restore`, `test_halt_stops_a_running_command_and_blocks_the_next`, `test_resume_needs_the_right_signed_action` |
| Concurrent lines don't corrupt chain | `session.Session` + DAG | `test_concurrent_lines_do_not_corrupt_the_chain` |

### Non-guarantees

| Non-guarantee | Reason |
|---|---|
| Cannot identify the human at the keyboard | Origin is the channel; keystroke injection defeats it. |
| Credential scrubbing catches all secrets | Pattern matching only; multi-line splits, encoding evade it. |
| Job object is an OS sandbox | It is a Windows process group; system calls can reach user profile. |
| Git hardening covers all read commands | Only known dangerous flags/configs are blocked. |
| Cross-platform containment parity | Job object is Windows-only; Linux/macOS fall back to basic subprocess. |
| Production hardening | Reference implementation with tests; not stress-tested or audited. |
| Independent security review | None performed. |
| Expert cryptography review | None performed. |
| Legal advice | Licence is a draft not reviewed by an attorney. |

---

## Failure modes

| Failure mode | What happens | Test citing |
|---|---|---|
| Tampered custody chain | `dag.verify()` fails; subsequent `dag.record()` raises `DagError`; `_run_locked` returns `status="not_recorded"` or `refused`; nothing executes | `test_a_tampered_chain_stops_every_run` (redteam_2_session.py) |
| Missing commitment (agent, non-READ) | `need_signature=True`, no `signed` or no gate → `_deny()` records `TERMINAL_DENIED`, returns `status="denied"` | `test_agent_write_needs_a_signature_for_exactly_this_line` (test_terminal.py) |
| Expired commitment | Gate `release()` raises `CommitRefused` → `_deny()` records `TERMINAL_DENIED`, returns `status="denied"` | `test_an_expired_lease_is_refused` (redteam_2_session.py) |
| Replayed commitment | Gate burns commitment on first use; second use raises `CommitRefused` → `status="denied"` | `test_a_signature_is_single_use` (test_terminal.py) |
| Corrupt/malformed record write | `dag.record()` raises `DagError` at intent → `status="not_recorded"`, nothing runs; at result → `status="not_recorded"`, output withheld | `test_if_the_intent_cannot_be_recorded_nothing_runs`, `test_if_the_result_cannot_be_recorded_the_output_is_withheld` (redteam_2_session.py) |
| Lexer refusal (expansion, syntax, length) | `lex.Refused` raised → `TERMINAL_REFUSED` recorded (best effort), `status="refused"` | `test_unsupported_syntax_is_refused`, `test_unterminated_and_oversized_lines_are_refused` (redteam_1_classification.py) |
| Policy refusal (launcher, bad program name) | `lex.Refused` from `program_name()` → `status="refused"` | `test_script_launchers_are_refused_outright`, `test_invisible_and_look_alike_characters_are_refused` (redteam_1_classification.py) |
| Path outside workspace | `pathrules.check()` returns `outside` flag → classification raised to OUTSIDE → agent needs signature | `test_every_way_out_of_the_workspace_is_outside` (redteam_1_classification.py) |
| Sensitive path | `pathrules.check()` returns `sensitive` flag → classification raised to SENSITIVE → agent needs signature | `test_sensitive_names_need_a_signature` (redteam_1_classification.py) |
| Timeout | `job.proc.wait(timeout)` raises → `job.kill()`, `timed_out=True`, `left_processes≥1`, `ok=False` | `test_timeout_kills_the_job`, `test_a_runaway_program_is_stopped_at_the_time_limit` |
| Detached survivor | `job.survivors() > 0` → `job.kill()`, `left_processes≥1`, `ok=False` | `test_a_detached_grandchild_is_found_and_killed` (redteam_2_session.py) |
| Output flood | Accumulated bytes > `OUT_CAP * 2` → `truncated=True`, output truncated to `OUT_CAP` | `test_an_output_flood_is_capped` (redteam_2_session.py) |
| Halt active | `self.halted=True` → immediate `status="halted"` for any line | `test_halt_refuses_until_a_signed_restore`, `test_halt_stops_a_running_command_and_blocks_the_next` |
| Invalid resume | No gate or wrong action/session → `TerminalRefused` raised | `test_resume_needs_the_right_signed_action` (redteam_2_session.py) |

---

## Dependencies and layer rules

**Registry entry (verbatim from `vega_umbrella.registry.REGISTRY`):**

```python
"vega-terminal-sdk": {
    "layer": 9,
    "concern": "gated command execution for people and agents",
    "requires": ["vega-custody-sdk", "vega-governance-jacket-sdk"],
    "provides": ["session", "lex", "policy", "pathrules", "builtins", "redact"],
}
```

**Dependencies point down layers only, never up or sideways:**

- Layer 0: `vega-custody-sdk` — DAG, ledger, safepaths, proc (ProcessJob)
- Layer 1: `vega-governance-jacket-sdk` — humanauth, commit, gate (ExitGate, Verifier, Commit)
- This kit (layer 9) imports ONLY from layers 0 and 1.
- No imports from layers 2-8 (seal, adapt, contain, memory, conduct, knowledge, learn) or layers 10-15 (observe, reason, verify, watch, deliberate, assemble).

---

## Conformance

A third party can verify conformance by:

1. Installing the package and its two dependencies: `pip install -e .` (requires `vega-custody-sdk`, `vega-governance-jacket-sdk` on PYTHONPATH or installed).
2. Running the test suite: `python -m unittest discover -s tests` (all 72 tests in 4 files must pass).
3. Running the mutation check: `python tests/mutation_check.py` (all 11 mutations must be killed — i.e., each removal of a fix causes at least one test to fail).

**What passing means:** The reference implementation behaves as specified: lexing refuses expansion/syntax, classification matches the policy tables, paths are contained, signatures are single-use and line-specific, intent/result recording is fail-closed, containment (job object, clean env, timeout, survivor check) functions on Windows, output scrubbing replaces credential-shaped lines, halt/resume requires signed commitment.

**What passing does NOT mean:** Production readiness; security audit completion; cryptographic expert review; cross-platform containment parity (job object is Windows-only); legal compliance; that the licence is final; that any deployment is safe without further hardening.
