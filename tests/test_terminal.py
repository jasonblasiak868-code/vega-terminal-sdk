"""Functional tests for the governed terminal."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import fixture_terminal as fx  # noqa: E402
from vega_terminal import lex, redact  # noqa: E402


class Lexing(unittest.TestCase):
    def test_stages_and_separators(self):
        st, op = lex.split('echo "a b" && ls ; cat x | head -n 2')
        self.assertFalse(op)
        self.assertEqual([s["words"] for s in st], [["echo", "a b"], ["ls"], ["cat", "x"], ["head", "-n", "2"]])
        self.assertEqual([s["sep_after"] for s in st], ["&&", ";", "|", None])

    def test_expansion_is_opaque(self):
        for line in ("echo $(whoami)", "echo `id`", "echo %PATH%", "echo ${X}", "echo ^x", "echo (a)"):
            self.assertTrue(lex.split(line)[1], line)

    def test_unsupported_syntax_is_refused(self):
        for line in ("sleep 1 &", "cat < f", "ls 2> e", "ls |", "| ls", "echo 'x", "a\x00b", "ls > "):
            with self.assertRaises(lex.Refused, msg=repr(line)):
                lex.split(line)


class Redaction(unittest.TestCase):
    def test_escape_sequences_removed(self):
        self.assertEqual(redact.strip_controls("a\x1b]0;title\x07b\x1b[31mred\x1b[0m"), "abred")
        self.assertEqual(redact.strip_controls("\x1b\x1b[2Jx"), "x")

    def test_credential_lines_replaced(self):
        out, n = redact.scrub("ok\napi_key = abcdefghijklmnopqrstuvwxyz0123\nfine")
        self.assertEqual(n, 1)
        self.assertNotIn("abcdefghijkl", out)


class Classify(unittest.TestCase):
    def setUp(self):
        self.f = fx.build()

    def cls(self, line):
        return self.f.sess.plan(line, "agent")["cls"]

    def test_classes(self):
        for line, want in (("ls", "READ"), ("cat a.txt", "READ"), ("git status", "READ"), ("git log -n 3", "READ"), ("mkdir x", "WRITE"), ("curl http://x", "NETWORK"), ("python -c 1", "EXEC"),
                           ("foo", "UNKNOWN"), ("rm a", "DESTRUCTIVE"), ("cat ..\\x", "OUTSIDE"), ("cat .env", "SENSITIVE"), ("git push", "HUMAN_ONLY"), ("npm publish", "HUMAN_ONLY"),
                           ("echo hi > o.txt", "WRITE"), ("git diff --output=x", "EXEC"), ("git -c core.pager=x log", "EXEC"), ("cat \\\\srv\\share\\f", "OUTSIDE")):
            self.assertEqual(self.cls(line), want, line)

    def test_human_only_actions_are_canonical_names(self):
        from vega_jacket.humanauth import HUMAN_ONLY
        for line in ("git push", "npm publish", "stripe charges create", "cmdkey /add:x"):
            self.assertIn(self.f.sess.plan(line, "agent")["action"], HUMAN_ONLY)


class Running(unittest.TestCase):
    def setUp(self):
        self.f = fx.build()
        (self.f.work / "a.txt").write_text("alpha\nbeta\ngamma\n")

    def test_agent_reads_without_signature_and_is_recorded(self):
        r = self.f.sess.run_agent("cat a.txt")
        self.assertTrue(r["ok"], r)
        self.assertIn("beta", r["output"])
        self.assertEqual(fx.kinds(self.f)[-2:], ["TERMINAL_INTENT", "TERMINAL_RESULT"])
        self.assertTrue(self.f.dag.verify())

    def test_agent_write_needs_a_signature_for_exactly_this_line(self):
        r = self.f.sess.run_agent("mkdir sub")
        self.assertEqual(r["status"], "denied")
        self.assertFalse((self.f.work / "sub").exists())
        sig = self.f.sign_line("mkdir sub")
        self.assertEqual(self.f.sess.run_agent("mkdir other", sig)["status"], "denied")           # signature is for a different line
        r = self.f.sess.run_agent("echo made > made.txt", self.f.sign_line("echo made > made.txt"))
        self.assertEqual(r["status"], "ran", r)
        self.assertTrue((self.f.work / "made.txt").exists())

    def test_a_signature_is_single_use(self):
        sig = self.f.sign_line("echo hi > o.txt")
        self.assertEqual(self.f.sess.run_agent("echo hi > o.txt", sig)["status"], "ran")
        self.assertEqual(self.f.sess.run_agent("echo hi > o.txt", sig)["status"], "denied")

    def test_human_runs_ordinary_lines_but_human_only_needs_a_signature(self):
        self.assertEqual(self.f.sess.run_human("echo ok")["output"].strip(), "ok")
        r = self.f.sess.run_human("git push")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["action"], "release_public")

    def test_pipes_and_sequence(self):
        r = self.f.sess.run_agent("cat a.txt | head -n 1 ; echo done")
        self.assertEqual(r["output"].split(), ["alpha", "done"])
        r = self.f.sess.run_agent("cat nope && echo skipped || echo fallback")
        self.assertIn("fallback", r["output"])
        self.assertNotIn("skipped", r["output"])

    def test_cd_stays_in_workspace(self):
        (self.f.work / "d").mkdir()
        self.f.sess.run_agent("cd d")
        self.assertTrue(self.f.sess.cwd.endswith("d"))
        self.assertEqual(self.f.sess.run_agent("cd ..\\..")["status"], "denied")

    def test_credentials_in_files_are_redacted_in_output_and_record(self):
        (self.f.work / "n.txt").write_text("hello\npassword = hunter2hunter2hunter2hunter2\n")
        r = self.f.sess.run_agent("cat n.txt")
        self.assertNotIn("hunter2", r["output"])
        self.assertEqual(r["redacted_lines"], 1)
        with open(self.f.t / "c.jsonl", encoding="utf-8") as fh:
            self.assertNotIn("hunter2", fh.read())

    def test_sensitive_and_outside_reads_are_denied_for_agent(self):
        (self.f.work / ".env").write_text("X=1\n")
        self.assertEqual(self.f.sess.run_agent("cat .env")["status"], "denied")
        self.assertEqual(self.f.sess.run_agent("cat C:\\Windows\\win.ini")["status"], "denied")

    def test_program_runs_in_a_job_with_a_clean_environment(self):
        os.environ["VEGA_TEST_SECRET_ENV"] = "leak-me"
        try:
            (self.f.work / "env.py").write_text("import os; print(os.environ.get('VEGA_TEST_SECRET_ENV'))")
            r = self.f.sess.run_human('"%s" env.py' % sys.executable)
            self.assertEqual(r["status"], "ran", r)
            self.assertNotIn("leak-me", r["output"])
            self.assertIn("None", r["output"])
        finally:
            del os.environ["VEGA_TEST_SECRET_ENV"]

    def test_timeout_kills_the_job(self):
        f = fx.build(timeout=1.0)
        (f.work / "slow.py").write_text("import time; time.sleep(30)")
        r = f.sess.run_human('"%s" slow.py' % sys.executable)
        self.assertTrue(r["timed_out"])
        self.assertFalse(r["ok"])

    def test_halt_refuses_until_a_signed_restore(self):
        self.f.sess.halt()
        self.assertEqual(self.f.sess.run_agent("ls")["status"], "halted")
        self.f.sess.resume(self.f.sign("restore_after_hard_stop", {"session": self.f.sess.id}))
        self.assertEqual(self.f.sess.run_agent("ls")["status"], "ran")


if __name__ == "__main__":
    unittest.main()
