# vega-terminal-sdk — Architecture

**Layer 9 (interface) — gated command execution for people and agents.** This document shows where this kit sits in the 16-layer organism, its internal module wiring, the authority and data flows, trust boundaries, and every fail-closed constraint point with module+function citations.

## At a glance

| Property | Value |
|---|---|
| Layer | 9 (interface) |
| Concern | Gated command execution for people and agents |
| Down deps | Layer 0 (custody), Layer 1 (jacket) |
| Up dependents | Layer 15 (umbrella) |
| Modules | lex, policy, pathrules, builtins, redact, session |

## Table of contents

- [The organism (family picture)](#the-organism-family-picture)
- [Internal drawing: modules and flows](#internal-drawing-modules-and-flows)
- [Authority flow](#authority-flow)
- [Data/knowledge flow](#dataknowledge-flow)
- [Mermaid diagram](#mermaid-diagram)
- [Sequence: main scenario end to end](#sequence-main-scenario-end-to-end)
- [Trust boundaries](#trust-boundaries)
- [Fail-closed workflow diagram](#fail-closed-workflow-diagram)
- [Custom constraint extension points](#custom-constraint-extension-points)

---

## The organism (family picture)

```
                 ┌──────────────────────────┐
                 │   THE HUMAN (the owner)  │  holds the only signing key;
                 │  authority starts here   │  spends it one action at a time
                 └────────────┬─────────────┘
                              v single-use signed commitments
 15 assemble   vega-umbrella-sdk        the family as one organism: one keyed
                                        ledger, one approval check, one anchor,
                                        registry + pre-deploy audit
 14 deliberate vega-council-sdk         multi-brain deliberation, design-first builder
               vega-galaxy-sdk          the galaxy view of the knowledge lattice:
                                        levels, convergence, futures above the present
 13 watch      vega-governance-feed-sdk  live view of every chain + tamper alarms
 12 verify     vega-metacog-sdk          evidence rungs and the completion gate
 11 reason     vega-reasoning-sdk        fidelity, forecasting, routing: the lattice
                                        that predicts steps ahead
 10 observe    vega-trace-sdk            telemetry of reasoning: layer traces, entropy,
                                        harmonic echo, reference signature
  9 interface >>> vega-terminal-sdk <<<  gated command execution for people and agents
  8 learn      vega-train-sdk            governed training + freeze cards: records
                                        exactly what a model learned from
  7 knowledge  vega-dkg-lattice-sdk      the knowledge graph: every fact with origin
                                        and licence; repo-library processing
  6 conduct    vega-harness-sdk          deterministic workflow conduct, pre-registered
                                        predicted paths, library use gate
  5 memory     vega-librarian-sdk        lessons and memory of past incidents
  4 contain    vega-two-gate-sdk         containment between two gates + the hard stop
  3 adapt      vega-pareah-sdk            adapters, cards, quarantine of inbound code:
                                        the dead-end room for the unannounced
  2 seal       vega-superproof-sdk       layered sealing and proof tiers
  1 authority  vega-governance-jacket-sdk human-only actions, single-use signed
                                        commitments, entry and exit gates
  0 record     vega-custody-sdk          capsules, DAG, hash-chained ledger, safe paths,
                                        bounded processes — the foundation everything
                                        writes to
```

**What the layers below provide (downward dependencies):**

- **Layer 0 (custody):** Append-only hash-chained DAG (`TERMINAL_INTENT`, `TERMINAL_RESULT`, `TERMINAL_REFUSED`, `TERMINAL_DENIED`, `TERMINAL_HALT`, `TERMINAL_RESUME`); `safepaths` for capped atomic reads/writes; `ProcessJob` for Windows job object containment.
- **Layer 1 (jacket):** Human-only action registry (`release_public`, `spend_funds`, `change_key_registry`, `restore_after_hard_stop`); `Verifier` for device/surface binding; `Commit` for signing; `ExitGate` for single-use commitment check-and-burn.

**Who above consumes it (upward dependents, per registry):**

- **Layer 15 (umbrella):** Registers this kit as the interface layer; wires it into the unified organism.
- No layer 10–14 SDK imports this kit (dependencies point down only).

> **One family, one organism:** Every SDK owns exactly one concern and uses the owner of every other concern instead of growing its own copy.

---

## Internal drawing: modules and flows

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            vega_terminal.Session                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  run_human   │  │  run_agent   │  │    plan      │  │   halt/      │    │
│  │  (origin=    │  │  (origin=    │  │  (dry-run    │  │   resume     │    │
│  │   human)     │  │   agent)     │  │   only)      │  │              │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                 │                 │                 │            │
│         └─────────────────┼─────────────────┼─────────────────┘            │
│                           ▼                 ▼                              │
│                    ┌─────────────────────────────────┐                     │
│                    │       _run_locked(line)         │                     │
│                    │  (every step fails closed)      │                     │
│                    └──────────────┬──────────────────┘                     │
│                                   │                                        │
│         ┌─────────────────────────┼─────────────────────────┐              │
│         ▼                         ▼                         ▼              │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐          │
│  │  lex.split  │         │policy.class │         │ pathrules.  │          │
│  │  (stages,   │         │  ify_stage  │         │  check()    │          │
│  │   opaque)   │         │  (cls, act) │         │  (flags)    │          │
│  └──────┬──────┘         └──────┬──────┘         └──────┬──────┘          │
│         │                       │                       │                 │
│         ▼                       ▼                       ▼                 │
│  ┌─────────────────────────────────────────────────────────────┐          │
│  │  need_signature?  ──YES──▶ gate.release(action, params)    │          │
│  │       │                      │   on fail: TERMINAL_DENIED   │          │
│  │       NO                     ▼                              │          │
│  │       │            ┌─────────────────┐                      │          │
│  │       └───────────▶│ dag.record(     │                      │          │
│  │                    │  TERMINAL_INTENT│                      │          │
│  │                    │  ) on fail:     │                      │          │
│  │                    │  not_recorded   │                      │          │
│  │                    └────────┬────────┘                      │          │
│  │                             │                               │          │
│  │                             ▼                               │          │
│  │                    ┌─────────────────┐                      │          │
│  │                    │ _execute(plan)  │                      │          │
│  │                    │  • builtins     │                      │          │
│  │                    │  • ProcessJob   │                      │          │
│  │                    │  • pipes, seq,  │                      │          │
│  │                    │    redirect     │                      │          │
│  │                    └────────┬────────┘                      │          │
│  │                             │                               │          │
│  │                             ▼                               │          │
│  │                    ┌─────────────────┐                      │          │
│  │                    │ redact.scrub()  │                      │          │
│  │                    │  (strip ESC,    │                      │          │
│  │                    │   replace cred) │                      │          │
│  │                    └────────┬────────┘                      │          │
│  │                             │                               │          │
│  │                             ▼                               │          │
│  │                    ┌─────────────────┐                      │          │
│  │                    │ dag.record(     │                      │          │
│  │                    │  TERMINAL_RESULT│                      │          │
│  │                    │  ) on fail:     │                      │          │
│  │                    │  withhold output│                      │          │
│  │                    └─────────────────┘                      │          │
│  └─────────────────────────────────────────────────────────────┘          │
│                                   │                                        │
│                                   ▼                                        │
│                          return result dict                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Authority flow

Authority flows **down from the human**, never from the model:

```
Human signs commitment
       │
       ▼
ExitGate.release(action, params, signed) ──burns commitment──▶
       │
       ▼
Session._run_locked: records TERMINAL_INTENT (with commitment_leaf)
       │
       ▼
Execute (builtins or ProcessJob)
       │
       ▼
Session._run_locked: records TERMINAL_RESULT
```

---

## Data/knowledge flow

Data/knowledge flows **up from the record**:

```
TERMINAL_INTENT / TERMINAL_RESULT / TERMINAL_DENIED / TERMINAL_REFUSED / TERMINAL_HALT / TERMINAL_RESUME
       │
       ▼
vega-custody DAG (append-only, hash-chained)
       │
       ▼
vega-librarian-sdk → lessons → vega-dkg-lattice-sdk → knowledge graph
       │
       ▼
vega-reasoning-sdk / vega-galaxy-sdk → foresight → human decides again
```

---

## Mermaid diagram

```mermaid
graph TD
    A[run_human / run_agent] --> B[_run_locked]
    B --> C{halted?}
    C -- yes --> D[status=halted]
    C -- no --> E[plan(line, origin)]
    E --> F{refused?}
    F -- yes --> G[record TERMINAL_REFUSED]
    G --> H[status=refused]
    F -- no --> I{need_signature?}
    I -- yes --> J[gate.release]
    J --> K{ok?}
    K -- no --> L[record TERMINAL_DENIED]
    L --> M[status=denied]
    K -- yes --> N[commitment_leaf]
    I -- no --> N
    N --> O[record TERMINAL_INTENT]
    O --> P{fail?}
    P -- yes --> Q[status=not_recorded]
    P -- no --> R[_execute]
    R --> S[redact.scrub]
    S --> T[record TERMINAL_RESULT]
    T --> U{fail?}
    U -- yes --> V[status=not_recorded, output withheld]
    U -- no --> W[return result]
```

---

## Sequence: main scenario end to end

```
┌─────────┐     ┌──────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  Agent  │     │ Session  │     │  Gate   │     │   DAG   │     │ Process │
│ /Human  │     │_run_locked│    │(ExitGate)│    │ (custody)│    │ (Job)   │
└────┬────┘     └────┬─────┘     └────┬────┘     └────┬────┘     └────┬────┘
     │               │                │                │               │
     │ run_agent(l)  │                │                │               │
     │──────────────>│                │                │               │
     │               │ plan(l,agent)  │                │               │
     │               │───────────────>│                │               │
     │               │<──── cls,need  │                │               │
     │               │ need_signature │                │               │
     │               │ gate.release() │                │               │
     │               │───────────────>│                │               │
     │               │<──── leaf (OK) │                │               │
     │               │                │                │               │
     │               │ record INTENT  │                │               │
     │               │───────────────>│                │               │
     │               │<──── OK        │                │               │
     │               │                │                │               │
     │               │ _execute()     │                │               │
     │               │───────────────>│                │               │
     │               │    (job)       │                │               │
     │               │<──── output    │                │               │
     │               │                │                │               │
     │               │ redact.scrub() │                │               │
     │               │                │                │               │
     │               │ record RESULT  │                │               │
     │               │───────────────>│                │               │
     │               │<──── OK        │                │               │
     │               │                │                │               │
     │<─── result    │                │                │               │
```

---

## Trust boundaries

| Boundary | From | To | Enforcement |
|---|---|---|---|
| Human → Session | Person at keyboard | `run_human()` | Application must route keystrokes; origin is the channel, not inferred. |
| Agent → Session | Model/script/agent | `run_agent()` | Application must route agent output; origin is the channel. |
| Session → Gate | `Session._run_locked` | `ExitGate.release()` | Gate burns commitment; verifies signature, expiry, action match, device/surface binding. |
| Gate → Custody | `ExitGate` | `vega_custody.dag.Dag` | Commitment receipt (leaf) recorded in `TERMINAL_INTENT`; single-use enforced by ledger. |
| Session → ProcessJob | `Session._execute` | `vega_custody.proc.ProcessJob` | Job object (Windows) or subprocess (fallback); clean env, timeout, survivor check. |
| ProcessJob → OS | Child process | Windows/Linux/macOS | Job object limits (Windows only); PATH filtering, env sanitization, scratch dirs on all platforms. |
| Session → Custody | `Session._run_locked` | `vega_custody.dag.Dag` | Every decision recorded; hash chain verified by `dag.verify()`; tamper stops all runs. |
| Custody → Upstream | DAG records | Librarian/DKG/Reasoning | Append-only; upstream reads but never writes to this kit's records. |

---

## Fail-closed workflow diagram

```
INPUT LINE (human or agent channel)
       │
       ▼
┌────────────────────────────────────────────────────────────────┐
│ 1. lex.split(line)                                             │
│    module: vega_terminal.lex  function: split()                │
│    FAIL-CLOSED: NUL, >8192 chars, control chars, expansion    │
│    syntax ($ ` ^ %VAR% () {}), &, <, 2>, pipe with nothing     │
│    after |, unterminated quotes, empty cmd, >16 stages,       │
│    redirected stage feeding pipe → raises Refused              │
└────────────────────────────────────────────────────────────────┘
       │
       ▼ (opaque flag → refuse)
┌────────────────────────────────────────────────────────────────┐
│ 2. policy.classify_stage() per stage                           │
│    module: vega_terminal.policy  function: classify_stage()    │
│    FAIL-CLOSED: program_name() refuses non-ASCII, control,    │
│    path form, launcher extensions (.bat .ps1 .vbs .js .lnk     │
│    .com .scr .pif .hta .msi .reg .url) → raises Refused       │
│    Git subcommand casefold prevents PUSH bypass               │
└────────────────────────────────────────────────────────────────┘
       │
       ▼ (flags from pathrules.check)
┌────────────────────────────────────────────────────────────────┐
│ 3. pathrules.check(root, cwd, arg) per path arg                │
│    module: vega_terminal.pathrules  function: check()          │
│    FAIL-CLOSED: NUL, UNC, device ns, ADS, drive-relative,     │
│    glob/tilde → returns outside flag → class raised to        │
│    OUTSIDE; symlink resolution outside workspace → outside;    │
│    sensitive name/dir → sensitive flag → class raised to       │
│    SENSITIVE; device name (CON PRN AUX NUL COM1-9 LPT1-9)     │
│    → device flag → class raised                                │
└────────────────────────────────────────────────────────────────┘
       │
       ▼
┌────────────────────────────────────────────────────────────────┐
│ 4. session.Session._run_locked()                               │
│    module: vega_terminal.session  function: _run_locked()      │
│    FAIL-CLOSED points:                                         │
│    a) line 121-122: if self.halted → immediate status=halted  │
│    b) line 127-132: plan.refused → record TERMINAL_REFUSED    │
│       (best effort), return status=refused                    │
│    c) line 136-143: plan.need_signature and (no gate or       │
│       invalid signed) → record TERMINAL_DENIED, return        │
│       status=denied                                            │
│    d) line 144-147: dag.record(TERMINAL_INTENT) raises        │
│       DagError → return status=not_recorded (nothing runs)    │
└────────────────────────────────────────────────────────────────┘
       │
       ▼
┌────────────────────────────────────────────────────────────────┐
│ 5. session.Session._execute(plan, line)                        │
│    module: vega_terminal.session  function: _execute()         │
│    FAIL-CLOSED points:                                         │
│    a) line 319-326: timeout → job.kill(), timed_out=True,     │
│       left_processes≥1, ok=False                               │
│    b) line 323-326: job.survivors()>0 → job.kill(),           │
│       left_processes≥1, ok=False                               │
│    c) line 299-302: output bytes > OUT_CAP*2 → truncated=True,│
│       output truncated to OUT_CAP (64 KiB)                     │
│    d) line 253-255: redirect write fails → exit code 1,       │
│       error appended to output                                 │
└────────────────────────────────────────────────────────────────┘
       │
       ▼
┌────────────────────────────────────────────────────────────────┐
│ 6. redact.scrub(raw_output)                                    │
│    module: vega_terminal.redact  function: scrub()             │
│    BEST-EFFORT: strip_controls() removes ESC sequences;       │
│    contains_credential() on single lines + neighboring pairs  │
│    (joined with 
 and "") → replaced with marker.             │
│    NOT fail-closed: secrets split >2 lines or encoded pass.   │
└────────────────────────────────────────────────────────────────┘
       │
       ▼
┌────────────────────────────────────────────────────────────────┐
│ 7. dag.record(TERMINAL_RESULT)                                 │
│    module: vega_terminal.session  function: _run_locked()      │
│    FAIL-CLOSED: line 156-158: DagError → return               │
│    status=not_recorded, output="", recorded=False              │
└────────────────────────────────────────────────────────────────┘
       │
       ▼
RESULT DICT (ok, status, output, exit_codes, redacted_lines,
             truncated, left_processes, timed_out, recorded,
             commitment_leaf, bytes_kept)
```

---

## Custom constraint extension points

This version publishes no user-defined constraint hooks; constraints are fixed by the module and the jurisdiction floor.

> **User-defined constraints may be STRICTER than the legal minimum for the applicable jurisdiction, never looser. Jurisdictional legal minimums are defined by the jurisdiction registry (vega-jurisdiction-sdk); a custom constraint that would drop below a registered minimum is rejected at the gate.**

---

**This kit details one branch of a broader filed architecture. The remaining branches are the subject of filed disclosures and are outside the scope of this repository.**
