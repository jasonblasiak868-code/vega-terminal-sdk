"""Regression tests (2026-10-20): halt() killed the running program but a multi-stage line (a && b, a ; b) went on to start the next stage, because the halted flag was only
checked when a line began."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixture_terminal as fx  # noqa: E402
from vega_terminal import builtins as bi  # noqa: E402


class HaltStopsTheWholeLine(unittest.TestCase):
    def setUp(self):
        self.f = fx.build()
        self.s = self.f.sess
        self.real = bi.TABLE["echo"]
        self.calls = []

        def echo(args, stdin, sess):
            self.calls.append(list(args))
            out = self.real(args, stdin, sess)
            if args == ["first"]:
                sess.halt()                                   # a halt arrives while the line is running
            return out
        bi.TABLE["echo"] = echo
        self.addCleanup(bi.TABLE.__setitem__, "echo", self.real)

    def test_a_halt_during_a_line_stops_the_stages_after_it(self):
        r = self.s.run_human("echo first && echo second")
        self.assertEqual(self.calls, [["first"]], "a stage started after the halt")
        self.assertNotIn("second", r["output"])

    def test_a_halt_during_a_line_stops_semicolon_chains_too(self):
        self.s.run_human("echo first ; echo second ; echo third")
        self.assertEqual(self.calls, [["first"]])

    def test_after_the_halt_new_lines_are_refused(self):
        self.s.run_human("echo first")
        r = self.s.run_human("echo again")
        self.assertEqual(r["status"], "halted")

    def test_an_unhalted_chain_still_runs_every_stage(self):
        r = self.s.run_human("echo other && echo second")
        self.assertEqual(self.calls, [["other"], ["second"]])
        self.assertIn("second", r["output"])


class ResumeRecordsFirst(unittest.TestCase):
    def test_a_resume_that_cannot_be_recorded_leaves_the_terminal_halted(self):
        from vega_custody.dag.dag import RecordRefused
        f = fx.build()
        s = f.sess
        s.halt()
        signed = f.sign("restore_after_hard_stop", {"session": s.id})

        class Broken:
            def record(self, kind, payload, parents=None):
                raise RecordRefused("disk full")

            def __getattr__(self, k):
                return getattr(f.dag, k)
        s.dag = Broken()
        with self.assertRaises(Exception):
            s.resume(signed)
        self.assertTrue(s.halted)


if __name__ == "__main__":
    unittest.main()
