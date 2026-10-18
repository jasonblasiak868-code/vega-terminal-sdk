"""RED TEAM 2 - the governed terminal: signatures, recording, containment, output and halting.

Run:  . SDK_FAMILY/env_family.sh ; python -m unittest discover -s SDK_FAMILY/vega-terminal-sdk/tests -p "redteam_2_*.py"
"""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import fixture_terminal as fx  # noqa: E402
from vega_custody.dag.dag import DagError  # noqa: E402

PY = sys.executable


class Base(unittest.TestCase):
    def setUp(self):
        self.f = fx.build(timeout=15.0)
        self.s = self.f.sess

    def script(self, name, body):
        (self.f.work / name).write_text(body, encoding="utf-8")
        return '"%s" %s' % (PY, name)

    def chain_text(self):
        with open(self.f.t / "c.jsonl", encoding="utf-8") as fh:
            return fh.read()


class A_Signatures(Base):
    def test_a_signature_for_one_line_does_not_run_another(self):
        sig = self.f.sign_line("echo a > one.txt")
        self.assertEqual(self.s.run_agent("echo b > one.txt", sig)["status"], "denied")
        self.assertFalse((self.f.work / "one.txt").exists())

    def test_a_signature_for_another_folder_is_refused(self):
        (self.f.work / "d").mkdir()
        sig = self.f.sign_line("echo a > one.txt")                    # signed while in the workspace root
        self.s.run_agent("cd d")
        self.assertEqual(self.s.run_agent("echo a > one.txt", sig)["status"], "denied")

    def test_an_expired_lease_is_refused(self):
        sig = self.f.sign("terminal_exec", self.s.params_for("echo a > one.txt"), 1)
        time.sleep(2.3)
        self.assertEqual(self.s.run_agent("echo a > one.txt", sig)["status"], "denied")

    def test_an_ordinary_signature_never_authorises_a_human_only_line(self):
        sig = self.f.sign_line("git push")                           # signed as terminal_exec
        self.assertEqual(self.s.run_human("git push", sig)["status"], "denied")
        self.assertEqual(self.s.run_agent("git push", sig)["status"], "denied")

    def test_a_human_only_signature_authorises_exactly_that_line_once(self):
        line = "stripe charges list"
        sig = self.f.sign_line(line, "spend_funds")
        r = self.s.run_agent(line, sig)
        self.assertEqual(r["status"], "ran", r)                        # the gate passed; the program is not installed here
        self.assertEqual(self.s.run_agent(line, sig)["status"], "denied")

    def test_a_human_only_signature_does_not_cover_an_ordinary_line(self):
        sig = self.f.sign_line("echo a > one.txt", "release_public")
        self.assertEqual(self.s.run_agent("echo a > one.txt", sig)["status"], "denied")

    def test_garbage_signatures_are_refused(self):
        for sig in (None, {}, {"nonce": "x"}, {"signature": "00" * 64, "nonce": "n", "expiry": 9999999999}, "sig", 5, [], {"signature": 5}):
            self.assertEqual(self.s.run_agent("echo a > one.txt", sig)["status"], "denied", repr(sig))

    def test_no_gate_means_nothing_signed_can_run(self):
        from vega_terminal.session import Session
        s = Session(str(self.f.work), self.f.dag, None)
        self.assertEqual(s.run_agent("echo a > one.txt", self.f.sign_line("echo a > one.txt"))["status"], "denied")

    def test_origin_is_the_channel_not_the_text(self):
        r = self.s.run_agent("echo '# human' > x.txt")
        self.assertEqual(r["status"], "denied")
        with self.assertRaises(Exception):
            self.s.plan("ls", "HUMAN")
        with self.assertRaises(Exception):
            self.s.plan("ls", None)


class B_Recording(Base):
    def test_if_the_intent_cannot_be_recorded_nothing_runs(self):
        real = self.f.dag.record

        def boom(kind, payload, parents=None):
            if kind == "TERMINAL_INTENT":
                raise DagError("disk full")
            return real(kind, payload, parents)
        self.f.dag.record = boom
        r = self.s.run_human("echo a > one.txt")
        self.assertEqual(r["status"], "not_recorded")
        self.assertFalse((self.f.work / "one.txt").exists())

    def test_if_the_result_cannot_be_recorded_the_output_is_withheld(self):
        real = self.f.dag.record

        def boom(kind, payload, parents=None):
            if kind == "TERMINAL_RESULT":
                raise DagError("disk full")
            return real(kind, payload, parents)
        self.f.dag.record = boom
        r = self.s.run_human("echo secret-looking-but-fine")
        self.assertEqual(r["status"], "not_recorded")
        self.assertEqual(r["output"], "")
        self.assertFalse(r["recorded"])

    def test_a_tampered_chain_stops_every_run(self):
        with open(self.f.t / "c.jsonl", "a", encoding="utf-8") as fh:
            fh.write('{"garbage": true}\n')
        r = self.s.run_human("echo a > one.txt")
        self.assertIn(r["status"], ("not_recorded", "refused", "denied"))
        self.assertFalse((self.f.work / "one.txt").exists())

    def test_credentials_in_the_command_line_are_not_recorded(self):
        key = "nvapi-" + "A1b2C3d4E5" * 3
        r = self.s.run_human("echo " + key)
        self.assertEqual(r["status"], "ran")
        self.assertNotIn(key, r["output"])
        self.assertNotIn(key, self.chain_text())

    def test_the_record_holds_hashes_and_counts_not_output(self):
        (self.f.work / "n.txt").write_text("plain visible words\n")
        self.s.run_agent("cat n.txt")
        self.assertNotIn("plain visible words", self.chain_text())
        self.assertIn("output_sha256", self.chain_text())

    def test_every_decision_leaves_a_record(self):
        self.s.run_agent("ls")
        self.s.run_agent("rm x")
        self.s.run_agent("ls &")
        self.assertEqual(fx.kinds(self.f), ["TERMINAL_INTENT", "TERMINAL_RESULT", "TERMINAL_DENIED", "TERMINAL_REFUSED"])
        self.assertTrue(self.f.dag.verify())


class C_Containment(Base):
    def test_a_detached_grandchild_is_found_and_killed(self):
        body = ("import subprocess,sys\n"
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'], creationflags=0x00000008|0x00000200, close_fds=True)\n")
        r = self.s.run_human(self.script("spawn.py", body))
        self.assertEqual(r["status"], "ran")
        self.assertGreaterEqual(r["left_processes"], 1)
        self.assertFalse(r["ok"])

    def test_a_runaway_program_is_stopped_at_the_time_limit(self):
        f = fx.build(timeout=1.0)
        (f.work / "slow.py").write_text("import time; time.sleep(60)", encoding="utf-8")
        t0 = time.time()
        r = f.sess.run_human('"%s" slow.py' % PY)
        self.assertTrue(r["timed_out"])
        self.assertLess(time.time() - t0, 10)

    def test_an_output_flood_is_capped(self):
        body = "import sys,time\nt=time.time()\nwhile time.time()-t<2:\n    sys.stdout.write('A'*100000)\n"
        r = self.s.run_human(self.script("flood.py", body))
        self.assertTrue(r["truncated"])
        self.assertLess(len(r["output"]), 70000)
        self.assertLess(r["bytes_kept"], 2 * 65536 + 100000)                     # what was held in memory, not just what was shown

    def test_the_program_sees_a_clean_environment(self):
        os.environ["VEGA_RT2_SECRET"] = "leak"
        os.environ["NVIDIA_API_KEY"] = "leak"
        try:
            body = "import os\nprint(sorted(k for k in os.environ if 'VEGA' in k or 'KEY' in k.upper() or 'TOKEN' in k.upper()))\nprint(os.environ.get('USERPROFILE'), os.environ.get('HOME'))\n"
            r = self.s.run_human(self.script("env.py", body))
            self.assertIn("[]", r["output"])
            self.assertNotIn("leak", r["output"])
            self.assertIn(self.s._scratch, r["output"])
        finally:
            del os.environ["VEGA_RT2_SECRET"]
            del os.environ["NVIDIA_API_KEY"]

    def test_the_trusted_path_never_includes_the_workspace_or_relative_folders(self):
        old = os.environ["PATH"]
        os.environ["PATH"] = os.pathsep.join([str(self.f.work), ".", "bin", old])
        try:
            dirs = self.s._env()["PATH"].split(os.pathsep)
        finally:
            os.environ["PATH"] = old
        self.assertNotIn(str(self.f.work), dirs)
        self.assertNotIn(".", dirs)
        self.assertNotIn("bin", dirs)

    def test_a_program_in_the_workspace_is_not_found_by_bare_name(self):
        import shutil
        shutil.copy(PY, self.f.work / "vegatool.exe")
        r = self.s.run_human("vegatool --version")
        self.assertIn(r["exit_codes"][-1], (127,))


class D_Output(Base):
    def test_terminal_escape_sequences_from_a_program_are_removed(self):
        body = "import sys\nsys.stdout.buffer.write(b'ok\\x1b]52;c;ZXZpbA==\\x07\\x1b]0;pwned\\x07\\x1b[2J\\xc2\\x9b31m end')\n"
        r = self.s.run_human(self.script("esc.py", body))
        self.assertEqual(r["output"].strip(), "ok end")

    def test_credential_lines_from_a_program_are_replaced(self):
        body = "print('fine')\nprint('api_key = ' + 'Zx9' * 10)\nprint('ghp_' + 'a' * 36)\n"
        r = self.s.run_human(self.script("cred.py", body))
        self.assertEqual(r["redacted_lines"], 2)
        self.assertNotIn("ghp_", r["output"])

    def test_a_credential_split_by_carriage_returns_is_still_caught(self):
        (self.f.work / "x.txt").write_bytes(b"password\r= abcdefghijklmnopqrstuvwxyz0123\n")
        r = self.s.run_agent("cat x.txt")
        self.assertNotIn("abcdefghij", r["output"])

    def test_a_huge_file_is_refused_not_loaded(self):
        with open(self.f.work / "big.bin", "wb") as fh:
            fh.truncate(5 * 1024 * 1024)
        r = self.s.run_agent("cat big.bin")
        self.assertNotEqual(r["exit_codes"][-1], 0)
        self.assertLess(len(r["output"]), 500)


class E_Halting(Base):
    def test_halt_stops_a_running_command_and_blocks_the_next(self):
        (self.f.work / "slow.py").write_text("import time; time.sleep(60)", encoding="utf-8")
        got = {}

        def go():
            got["r"] = self.s.run_human('"%s" slow.py' % PY)
        t = threading.Thread(target=go)
        t.start()
        time.sleep(1.5)
        self.assertTrue(self.s.halt())
        t.join(15)
        self.assertFalse(t.is_alive())
        self.assertEqual(self.s.run_agent("ls")["status"], "halted")
        self.assertEqual(self.s.run_human("echo hi")["status"], "halted")

    def test_resume_needs_the_right_signed_action(self):
        self.s.halt()
        for sig in (None, self.f.sign("terminal_exec", {"session": self.s.id}), self.f.sign("restore_after_hard_stop", {"session": "other"})):
            with self.assertRaises(Exception):
                self.s.resume(sig)
        self.assertTrue(self.s.halted)
        self.s.resume(self.f.sign("restore_after_hard_stop", {"session": self.s.id}))
        self.assertEqual(self.s.run_agent("ls")["status"], "ran")

    def test_concurrent_lines_do_not_corrupt_the_chain(self):
        def go():
            for _ in range(5):
                self.s.run_agent("ls")
        ts = [threading.Thread(target=go) for _ in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertTrue(self.f.dag.verify())
        self.assertEqual(len(self.f.dag.content.entries()), 40)


if __name__ == "__main__":
    unittest.main()
