"""RED TEAM 1 - the governed terminal: try to get a dangerous line classified as safe, or to sneak a second command through the parser.

Run:  . SDK_FAMILY/env_family.sh ; python -m unittest discover -s SDK_FAMILY/vega-terminal-sdk/tests -p "redteam_1_*.py"
"""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import fixture_terminal as fx  # noqa: E402
from vega_terminal import lex  # noqa: E402

READ_OK = {"READ"}


class Base(unittest.TestCase):
    def setUp(self):
        self.f = fx.build()
        (self.f.work / "a.txt").write_text("alpha\n")
        (self.f.work / "sub").mkdir()

    def plan(self, line, origin="agent"):
        return self.f.sess.plan(line, origin)

    def not_auto(self, line):
        p = self.plan(line)
        self.assertTrue(p["refused"] or p["need_signature"], "%r would run unsigned as %s" % (line, p["cls"]))


class A_SecondCommandInsideALine(Base):
    def test_separators_without_spaces_are_still_separators(self):
        for line in ("ls;rm a.txt", "ls&&rm a.txt", "ls||rm a.txt", "ls|rm a.txt", "cat a.txt>b.txt", "ls\nrm a.txt", "ls\r\nrm a.txt", "ls\rrm a.txt"):
            self.not_auto(line)

    def test_expansion_and_shell_syntax_never_pass_as_read(self):
        for line in ("echo $(rm a.txt)", "echo `rm a.txt`", "echo %COMSPEC%", "ls ${HOME}", "echo ^| rm", "cat a.txt $env:USERPROFILE", "echo $x", "ls (rm a.txt)", "ls {a,b}", "echo '$(x)'"):
            self.not_auto(line)

    def test_background_redirection_and_numbered_forms_are_refused(self):
        for line in ("ls &", "ls & rm a.txt", "cat < a.txt", "ls 2>&1", "ls 2> e", "ls 1>x"):
            self.assertTrue(self.plan(line)["refused"], line)

    def test_invisible_and_look_alike_characters_are_refused(self):
        for line in ("ls\u202e", "l\u200bs", "ｒｍ a.txt", "ls\u2028rm a.txt", "r\u00adm a.txt", "ls\u0085rm", "ls \x1b[2J"):
            self.assertTrue(self.plan(line)["refused"], repr(line))
        self.assertTrue(self.plan("\u0440m a.txt")["refused"])                      # Cyrillic r look-alike

    def test_quotes_do_not_hide_a_second_stage(self):
        for line in ("ls \"x\";rm a.txt", "ls 'x' ; rm a.txt"):
            self.assertEqual(self.plan(line)["cls"], "DESTRUCTIVE", line)

    def test_unterminated_and_oversized_lines_are_refused(self):
        self.assertTrue(self.plan("echo \"x")["refused"])
        self.assertTrue(self.plan("echo " + "a" * 9000)["refused"])
        self.assertTrue(self.plan(";".join(["ls"] * 40))["refused"])


class B_ProgramNames(Base):
    def test_case_extension_and_path_forms_of_dangerous_programs(self):
        exact = {"RM a.txt": "DESTRUCTIVE", "Rm.EXE a.txt": "DESTRUCTIVE", "DEL a.txt": "DESTRUCTIVE", "Remove-Item a.txt": "DESTRUCTIVE", ".\\rm.exe a.txt": "DESTRUCTIVE",                 "PowerShell -Enc AAAA": "EXEC", "pwsh -c 1": "EXEC", "python -c 1": "EXEC", "node -e 1": "EXEC", "GIT PUSH": "HUMAN_ONLY", "GIT push": "HUMAN_ONLY", "Git.exe push": "HUMAN_ONLY",
                 "NPM Publish": "HUMAN_ONLY"}
        for line, want in exact.items():
            self.assertEqual(self.plan(line)["cls"], want, line)
        for line in ("CMD /c dir", "rd /s /q sub", "C:\\Windows\\System32\\cmd.exe /c dir"):
            self.not_auto(line)

    def test_script_launchers_are_refused_outright(self):
        for name in ("x.bat", "X.CMD", "run.ps1", "a.vbs", "a.js", "a.lnk", "a.hta", "a.msi", "a.reg", "a.com", ".\\x.bat", "sub\\y.PS1"):
            self.assertTrue(self.plan(name)["refused"], name)

    def test_unknown_programs_need_a_signature(self):
        for line in ("frobnicate", "explorer .", "mshta x", "regsvr32 x", "cscript x", "wmic os", "schtasks /create", "msiexec /i x", "certutil -urlcache x", "bitsadmin /transfer"):
            self.not_auto(line)

    def test_a_planted_program_in_the_workspace_is_never_resolved(self):
        s = self.f.sess
        (self.f.work / "git.exe").write_bytes(b"MZ")
        env = s._env()
        self.assertTrue(s._resolve("git", env) is None or not s._inside_root(os.path.dirname(s._resolve("git", env))))
        self.assertFalse(any(s._inside_root(d) for d in env["PATH"].split(os.pathsep) if d))


class C_Git(Base):
    def test_git_read_commands_with_dangerous_flags_are_not_read(self):
        for line in ("git diff --output=x", "git log --output x", "git diff -O x", "git show --textconv x", "git log --ext-diff", "git -c core.pager=x log", "git -C .. status", "git --git-dir=x status",
                     "git --exec-path=x status", "git status -c x", "git log --exec=x", "git ls-remote origin", "git archive --output=x HEAD", "git config core.fsmonitor x", "git submodule update",
                     "git branch -D x", "git branch -m a b", "git branch newname", "git tag -d x", "git tag v1", "git remote add o u", "git remote set-url o u", "git push", "git push --force", "git reset --hard",
                     "git clean -fdx", "git checkout .", "git credential fill", "git help status", "git difftool", "git mergetool", "git gui", "git instaweb", "git daemon"):
            self.not_auto(line)

    def test_ordinary_git_reads_pass(self):
        for line in ("git status", "git log", "git log -n 3", "git diff", "git show", "git branch", "git branch -a", "git tag", "git tag -l", "git remote -v", "git rev-parse HEAD", "git ls-files"):
            self.assertEqual(self.plan(line)["cls"], "READ", line)


class D_Paths(Base):
    def test_every_way_out_of_the_workspace_is_outside(self):
        for line in ("cat ..", "cat ..\\x", "cat sub\\..\\..\\x", "cat .\\..\\x", "cat C:/Windows/win.ini", "cat C:\\Windows\\win.ini", "cat //server/share/f", "cat \\\\server\\share\\f", "cat \\\\?\\C:\\x",
                     "cat C:x", "cat a.txt:stream", "cat a.txt::$DATA", "cat ~\\x", "cat ~", "cat PROGRA~1", "cat *", "cat a?.txt", "ls ..", "ls /", "ls \\", "cd ..", "cd \\", "head -n 1 ..\\x", "wc -l ..\\x", "grep a ..\\x",
                     "cat con", "cat nul.txt", "cat COM1", "cat a.txt.", "cat \"a.txt \"", "dir /s"):
            self.not_auto(line)

    def test_sensitive_names_need_a_signature(self):
        for name in (".env", ".ENV", ".env.local", "key.pem", "KEY.PEM", "id_rsa", "id_ed25519", "secrets", "my_secret.txt", "token.json", "credentials", "password.txt", ".npmrc", ".pypirc", ".netrc", "x.pfx",
                     "api_key.txt", "vega_keys.json", "x.kdbx", ".git\\config", ".ssh\\known_hosts", ".aws\\credentials"):
            self.not_auto("cat " + name)
            self.not_auto("type " + name)
            self.not_auto("head " + name)

    def test_a_junction_pointing_outside_is_outside(self):
        outside = self.f.t / "outside"
        outside.mkdir()
        (outside / "s.txt").write_text("x")
        link = self.f.work / "j"
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
        if r.returncode != 0:
            self.skipTest("could not create a junction")
        for line in ("cat j\\s.txt", "ls j", "cd j", "grep x j\\s.txt"):
            self.not_auto(line)

    def test_redirect_targets_are_checked_like_any_path(self):
        for line in ("echo x > ..\\out", "echo x > .env", "echo x > con", "echo x > C:\\x", "echo x >> ..\\o", "echo x > \\\\s\\p", "echo x > a.txt:s"):
            self.not_auto(line)
        self.assertEqual(self.plan("echo x > a.txt")["cls"], "DESTRUCTIVE")
        self.assertEqual(self.plan("echo x > new.txt")["cls"], "WRITE")
        self.assertEqual(self.plan("echo x >> a.txt")["cls"], "WRITE")

    def test_write_and_exec_programs_with_outside_paths_are_outside(self):
        for line in ("copy a.txt ..\\b", "mkdir ..\\x", "mv a.txt \\\\s\\p", "python ..\\x.py", "curl -o ..\\x http://u", "curl --output=..\\x http://u"):
            self.not_auto(line)
        self.assertEqual(self.plan("curl http://u/x")["cls"], "NETWORK")


class E_HumanOnly(Base):
    def test_publishing_paying_and_keys_are_human_only_for_everyone(self):
        from vega_jacket.humanauth import HUMAN_ONLY
        for line in ("git push", "npm publish", "pnpm publish", "cargo publish", "gh release create v1", "docker push x", "twine upload dist/*", "vsce publish", "vercel --prod", "stripe charges create", "solana transfer x 1",
                     "cmdkey /add:x /user:u /pass:p", "ssh-keygen", "gpg --export-secret-keys", "keyring set a b"):
            p = self.plan(line, "human")
            self.assertEqual(p["cls"], "HUMAN_ONLY", line)
            self.assertTrue(p["need_signature"], line)
            self.assertIn(p["action"], HUMAN_ONLY, line)

    def test_two_different_human_only_actions_in_one_line_are_refused(self):
        self.assertTrue(self.plan("git push ; stripe charges create")["refused"])

    def test_a_human_only_line_cannot_hide_behind_a_harmless_stage(self):
        for line in ("ls ; git push", "git push ; ls", "ls && npm publish", "echo hi | git push"):
            self.assertEqual(self.plan(line)["cls"], "HUMAN_ONLY", line)


class F_Pipes(Base):
    def test_stdin_commands_are_read_only_when_piped_from_a_reader(self):
        self.assertEqual(self.plan("cat a.txt | head -n 1")["cls"], "READ")
        self.assertNotEqual(self.plan("head -n 1")["cls"], "READ")
        self.assertNotEqual(self.plan("cat")["cls"], "READ")
        self.assertNotEqual(self.plan("cat a.txt | python x")["cls"], "READ")


if __name__ == "__main__":
    unittest.main()
