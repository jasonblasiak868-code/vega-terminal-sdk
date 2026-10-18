"""session.py - the governed terminal session.

One entry point per source, so who typed a line is decided by the channel it arrived on and never by anything inside the line:
  run_human(line, signed=None)   keystrokes from the person at the terminal
  run_agent(line, signed=None)   anything an agent, a script or a model sent
For each line, in this order (every step fails closed):
  1. the line is split without a shell; expansion syntax, background jobs and unsupported redirects are refused
  2. every stage is classified (policy.py); the line's class is its worst stage
  3. an agent may auto-run READ only; a person may auto-run everything except HUMAN_ONLY; anything else needs a human-signed commitment for exactly this line and folder, checked
     and burned by the exit gate (a HUMAN_ONLY line is checked as that HUMAN_ONLY action)
  4. the intent is recorded on the custody chain BEFORE anything runs; if it cannot be recorded, nothing runs
  5. stages run: built-ins in Python, programs inside a Windows job object with a clean environment, a time limit, an output cap and a survivor check
  6. output has terminal escape sequences removed and credential-shaped lines replaced, then the result (hashes and counts, never the output text) is recorded
  7. if the result cannot be recorded, the output is withheld
halt() kills the running job and refuses every line until resume() is given a human-signed restore."""
import hashlib
import os
import shutil
import subprocess
import tempfile
import threading
import time

from vega_custody import safepaths as sp
from vega_custody.dag.dag import DagError, contains_credential
from vega_custody.proc import ProcessJob
from vega_terminal import builtins as bi
from vega_terminal import lex, pathrules, policy, redact

OUT_CAP = 64 * 1024
GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-c", "core.pager=cat", "-c", "protocol.ext.allow=never", "-c", "diff.external=", "--no-pager"]
ENV_KEEP = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "LANG", "TZ")


class TerminalRefused(ValueError):
    pass


def h(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


class Session:
    def __init__(self, root, dag, exit_gate=None, timeout=30.0, session_id=None):
        self.root = os.path.realpath(root)
        if not os.path.isdir(self.root):
            raise TerminalRefused("the workspace folder does not exist")
        self.cwd = self.root
        self.dag, self.gate = dag, exit_gate
        self.timeout = float(timeout)
        self.id = session_id or h(self.root + str(time.time()))[:16]
        self.halted = False
        self._job = None
        self._lock = threading.Lock()
        self._scratch = tempfile.mkdtemp(prefix="vega_term_")

    # ---------------------------------------------------------------- planning
    def plan(self, line, origin):
        """Classify a line without running it. Returns dict(cls, stages, action, need_signature, refused)."""
        if origin not in ("human", "agent"):
            raise TerminalRefused("origin must be 'human' or 'agent'")
        try:
            stages, opaque = lex.split(line)
            if opaque:
                raise lex.Refused("expansion syntax ($ ` ^ %VAR% braces parentheses) is not supported: no shell is used, so it would not expand")
            infos = []
            for k, s in enumerate(stages):
                info = policy.classify_stage(s["words"], self.root, self.cwd, piped=bool(k and stages[k - 1]["sep_after"] == "|"))
                if s["redirect"]:
                    op, tgt = s["redirect"]
                    p, fl = pathrules.check(self.root, self.cwd, tgt)
                    if p is None or fl & {"outside", "device"}:
                        info["cls"] = policy._raise(info["cls"], "OUTSIDE")
                        info["reasons"] = info["reasons"] + ["redirect target %r is outside the workspace or not a plain path" % tgt]
                    elif "sensitive" in fl:
                        info["cls"] = policy._raise(info["cls"], "SENSITIVE")
                        info["reasons"] = info["reasons"] + ["redirect target %r looks like a secret file" % tgt]
                    else:
                        info["cls"] = policy._raise(info["cls"], "DESTRUCTIVE" if op == ">" and os.path.exists(p) else "WRITE")
                infos.append(info)
        except lex.Refused as exc:
            return dict(refused=str(exc), cls="REFUSED", stages=[], action=None, need_signature=False, stage_words=[])
        cls = policy.worst([i["cls"] for i in infos])
        actions = sorted({i["action"] for i in infos if i["action"]})
        if len(actions) > 1:
            return dict(refused="one line carries two different HUMAN_ONLY actions (%s): split it" % ", ".join(actions), cls="REFUSED", stages=infos, action=None, need_signature=False, stage_words=[])
        action = actions[0] if actions else "terminal_exec"
        need = (cls == "HUMAN_ONLY") if origin == "human" else (cls != "READ")
        return dict(refused=None, cls=cls, stages=infos, action=action, need_signature=need, parsed=stages)

    def params_for(self, line):
        return {"line_sha256": h(line), "cwd": self.cwd}

    # ---------------------------------------------------------------- recording
    def _record(self, kind, payload):
        payload = dict(payload)
        payload["session"] = self.id
        return self.dag.record(kind, payload)

    @staticmethod
    def _line_for_record(line):
        return "[REDACTED: credential-shaped command]" if contains_credential(line) else line[:2000]

    # ---------------------------------------------------------------- the entry points
    def run_human(self, line, signed=None):
        return self._run(line, "human", signed)

    def run_agent(self, line, signed=None):
        return self._run(line, "agent", signed)

    def _result(self, ok, status, **kw):
        out = dict(ok=ok, status=status, output="", exit_codes=[], recorded=True, timed_out=False, left_processes=0)
        out.update(kw)
        return out

    def _run(self, line, origin, signed):
        with self._lock:
            return self._run_locked(line, origin, signed)

    def _run_locked(self, line, origin, signed):
        if self.halted:
            return self._result(False, "halted", reason="the terminal is halted: resume() needs a human-signed restore")
        if not isinstance(line, str):
            return self._result(False, "refused", reason="a command line is text")
        plan = self.plan(line, origin)
        base = {"origin": origin, "line": self._line_for_record(line), "line_sha256": h(line), "cwd": self.cwd}
        if plan["refused"]:
            try:
                self._record("TERMINAL_REFUSED", dict(base, reason=plan["refused"]))
            except DagError:
                pass  # reviewed: the line is refused whether or not the refusal could be recorded (fail closed)
            return self._result(False, "refused", reason=plan["refused"])
        base["cls"] = plan["cls"]
        base["action"] = plan["action"]
        leaf = None
        if plan["need_signature"]:
            if self.gate is None or not isinstance(signed, dict):
                return self._deny(base, "this line needs a human-signed commitment (%s, class %s)" % (plan["action"], plan["cls"]), plan)
            try:
                got = self.gate.release(plan["action"], self.params_for(line), signed, route="human")
            except Exception as exc:                                         # Denied, CommitRefused, HumanAuthError: all mean no
                return self._deny(base, "commitment refused: %s" % exc, plan)
            leaf = got["receipt"]["leaf"]
        try:
            self._record("TERMINAL_INTENT", dict(base, commitment_leaf=leaf, stages=[{"cls": i["cls"], "prog": i["prog"]} for i in plan["stages"]]))
        except DagError as exc:
            return self._result(False, "not_recorded", reason="intent could not be recorded, so nothing was run: %s" % exc)
        run = self._execute(plan, line)
        text, hits = redact.scrub(run["raw"].decode("utf-8", "replace"))
        truncated = len(text.encode("utf-8")) > OUT_CAP or run["truncated"]
        if truncated:
            text = text.encode("utf-8")[:OUT_CAP].decode("utf-8", "ignore") + "\n[output truncated]"
        result = dict(base, status="ran", exit_codes=run["codes"], output_sha256=h(text), output_len=len(text), redacted_lines=hits, truncated=truncated, left_processes=run["left"], timed_out=run["timed_out"],
                      bytes_kept=len(run["raw"]), commitment_leaf=leaf)
        try:
            self._record("TERMINAL_RESULT", result)
        except DagError:
            return self._result(False, "not_recorded", reason="the result could not be recorded, so the output is withheld", exit_codes=run["codes"], recorded=False)
        return self._result(run["codes"][-1:] == [0] and not run["left"] and not run["timed_out"], "ran", output=text, exit_codes=run["codes"], redacted_lines=hits, truncated=truncated,
                            left_processes=run["left"], timed_out=run["timed_out"], bytes_kept=len(run["raw"]))

    def _deny(self, base, reason, plan):
        try:
            self._record("TERMINAL_DENIED", dict(base, reason=reason))
        except DagError:
            pass  # reviewed: denied either way
        return self._result(False, "denied", reason=reason, cls=plan["cls"], action=plan["action"], need_signature=True)

    # ---------------------------------------------------------------- halting
    def halt(self):
        job = self._job
        self.halted = True
        ok = True
        if job is not None:
            ok = job.kill()
        try:
            self._record("TERMINAL_HALT", {"kill_confirmed": bool(ok)})
        except DagError:
            pass  # reviewed: halted either way
        return ok

    def resume(self, signed):
        if self.gate is None or not isinstance(signed, dict):
            raise TerminalRefused("resume needs a human-signed restore_after_hard_stop")
        self.gate.release("restore_after_hard_stop", {"session": self.id}, signed, route="human")
        self.halted = False
        self._record("TERMINAL_RESUME", {})

    def close(self):
        shutil.rmtree(self._scratch, ignore_errors=True)

    # ---------------------------------------------------------------- running
    def _env(self):
        env = {k: v for k, v in os.environ.items() if k.upper() in ENV_KEEP}
        dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d and os.path.isabs(d) and not self._inside_root(d)]
        env["PATH"] = os.pathsep.join(dirs)
        for k in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"):
            env[k] = self._scratch
        env["TEMP"] = env["TMP"] = self._scratch
        env.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return env

    def _inside_root(self, d):
        r = os.path.realpath(d)
        try:
            return os.path.commonpath([self.root, r]) == self.root
        except ValueError:
            return False

    def _resolve(self, word, env):
        """Absolute path of the program, found only in absolute PATH folders outside the workspace (a planted program in the workspace or the current folder is never picked)."""
        if os.path.basename(word) != word:
            p = os.path.realpath(word if os.path.isabs(word) else os.path.join(self.cwd, word))
            return p if os.path.isfile(p) else None
        exts = [""] + [e for e in env.get("PATHEXT", ".EXE").lower().split(";") if e in (".exe", ".com")] if os.name == "nt" else [""]
        for d in env["PATH"].split(os.pathsep):
            for e in exts:
                c = os.path.join(d, word + e)
                if os.path.isfile(c):
                    return c
        return None

    def _execute(self, plan, line):
        out, codes, left, timed_out, truncated = [], [], 0, False, False
        stages = plan["parsed"]
        prev_code, i = 0, 0
        pipe_in = b""
        while i < len(stages):
            s = stages[i]
            info = plan["stages"][i]
            sep_before = stages[i - 1]["sep_after"] if i else None
            if sep_before == "&&" and prev_code != 0 or sep_before == "||" and prev_code == 0:
                i += 1
                continue
            stdin = pipe_in if sep_before == "|" else b""
            data, code, extra = self._stage(s, info, stdin)
            left += extra["left"]
            timed_out = timed_out or extra["timed_out"]
            truncated = truncated or extra["truncated"]
            prev_code = code
            if s["sep_after"] == "|":
                pipe_in = data
            else:
                pipe_in = b""
                codes.append(code)
                if s["redirect"]:
                    op, tgt = s["redirect"]
                    try:
                        p = pathrules.check(self.root, self.cwd, tgt)[0]
                        if op == ">>" and os.path.exists(p):
                            data = sp.read_capped(p, 8 << 20) + data
                        sp.atomic_write(p, redact.strip_controls(data.decode("utf-8", "replace")))
                    except (OSError, sp.PathRefused) as exc:
                        out.append(("redirect failed: %s\n" % exc).encode())
                        codes[-1] = 1
                else:
                    out.append(data)
            if timed_out or left:
                break
            i += 1
        return dict(raw=b"".join(out), codes=codes or [1], left=left, timed_out=timed_out, truncated=truncated)

    def _stage(self, stage, info, stdin):
        words = stage["words"]
        prog = info["prog"]
        extra = dict(left=0, timed_out=False, truncated=False)
        if prog in bi.TABLE and os.path.basename(words[0]) == words[0]:
            try:
                data, code = bi.TABLE[prog](words[1:], stdin, self)
                return data, code, extra
            except (bi.BuiltinError, OSError) as exc:
                return (str(exc) + "\n").encode(), 2, extra
        env = self._env()
        exe = self._resolve(words[0], env)
        if exe is None:
            return ("%s: program not found in the trusted PATH\n" % words[0]).encode(), 127, extra
        argv = [exe] + words[1:]
        if prog == "git":
            sub = words[1] if len(words) > 1 else ""
            argv = [exe] + GIT_SAFE + words[1:]
            if sub in ("diff", "show", "log", "blame"):
                argv.insert(len(GIT_SAFE) + 2, "--no-textconv")
                if sub != "blame":
                    argv.insert(len(GIT_SAFE) + 2, "--no-ext-diff")
        try:
            job = ProcessJob.start(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.cwd, env=env)
        except (OSError, ValueError) as exc:
            return ("could not start: %s\n" % exc).encode(), 126, extra
        self._job = job
        buf, over = [], [False]

        def reader():
            total = 0
            while True:
                chunk = job.proc.stdout.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total <= OUT_CAP * 2:
                    buf.append(chunk)
                else:
                    over[0] = True
        t = threading.Thread(target=reader, daemon=True)
        t.start()

        def writer():
            try:
                job.proc.stdin.write(stdin)
            except (OSError, ValueError):
                pass  # reviewed: the program may exit without reading its input
            finally:
                try:
                    job.proc.stdin.close()
                except OSError:
                    pass  # reviewed: already closed
        w = threading.Thread(target=writer, daemon=True)
        w.start()
        try:
            job.proc.wait(timeout=self.timeout)
        except Exception:
            extra["timed_out"] = True
        t.join(2.0)
        survivors = job.survivors()
        if extra["timed_out"] or survivors != 0:
            ok = job.kill()
            extra["left"] = 0 if (extra["timed_out"] and survivors == 0 and ok) else max(1, survivors) if survivors else (0 if ok else 1)
        for stream in (job.proc.stdout, job.proc.stdin):
            try:
                stream.close()
            except (OSError, ValueError):
                pass  # reviewed: already closed
        job.close()
        self._job = None
        extra["truncated"] = over[0]
        code = job.proc.returncode if job.proc.returncode is not None else 1
        return b"".join(buf), code, extra

