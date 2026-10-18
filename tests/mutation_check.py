"""mutation_check.py - remove each fix in a COPY of the package and confirm a test fails. A fix whose removal no test notices is not protected.
Not a unit test: run it by hand.   python tests/mutation_check.py"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent / "src" / "vega_terminal"

MUTATIONS = [
    ("opaque expansion refused", "session.py", "            if opaque:\n", "            if False:\n"),
    ("signature required", "session.py", '        if plan["need_signature"]:', "        if False:"),
    ("trusted PATH excludes workspace", "session.py", "and not self._inside_root(d)]", "]"),
    ("survivor check", "session.py", 'if extra["timed_out"] or survivors != 0:', 'if extra["timed_out"]:'),
    ("pair scrub", "redact.py", "for i in range(len(lines) - 1):", "for i in range(0):"),
    ("escape strip", "redact.py", "        text = _ESC.sub(\"\", text)", "        pass"),
    ("git subcommand casefold", "policy.py", "args[0].casefold()", "args[0]"),
    ("sensitive names", "pathrules.py", '        flags.add("sensitive")', "        pass"),
    ("outside paths", "pathrules.py", '        flags.add("outside")\n    rel =', '        pass\n    rel ='),
    ("launcher refusal", "policy.py", "    if base.endswith(LAUNCHER_EXT):", "    if False:"),
    ("non-ascii program names", "policy.py", "or not word.isascii()", "or False"),
    ("clean environment", "session.py", "env = {k: v for k, v in os.environ.items() if k.upper() in ENV_KEEP}", "env = dict(os.environ)"),
    ("output cap", "session.py", "if total <= OUT_CAP * 2:", "if True:"),
]


def run(tests_dir, srcroot):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(srcroot) + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", str(tests_dir), "-p", "*.py"], capture_output=True, text=True, env=env, timeout=600)
    return r.returncode, (r.stderr or "")[-300:]


def main():
    survivors = []
    for name, fname, old, new in MUTATIONS:
        tmp = pathlib.Path(tempfile.mkdtemp())
        shutil.copytree(SRC, tmp / "vega_terminal")
        f = tmp / "vega_terminal" / fname
        text = f.read_text(encoding="utf-8")
        if old not in text:
            print("CANNOT APPLY", name)
            survivors.append(name + " (could not apply)")
            continue
        f.write_text(text.replace(old, new, 1), encoding="utf-8")
        code, tail = run(HERE, tmp)
        print(("killed   " if code != 0 else "SURVIVED ") + name)
        if code == 0:
            survivors.append(name)
        shutil.rmtree(tmp, ignore_errors=True)
    print("survivors:", survivors or "none")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
