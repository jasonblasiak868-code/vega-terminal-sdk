"""policy.py - classify one stage (a program and its arguments) into a risk class and, where it applies, the HUMAN_ONLY action it would be.

Classes, mildest first:
  READ            a built-in read command on paths inside the workspace (ls, cat, head, tail, wc, grep, pwd, echo, cd) or a git read command run with hardening
  WRITE           changes files inside the workspace (redirect, mkdir, copy, move)
  NETWORK         reaches the network (curl, git fetch, pip install ...)
  EXEC            runs other code (an interpreter, a build tool)
  UNKNOWN         a program this table has not heard of: treated as EXEC
  DESTRUCTIVE     deletes or overwrites (rm, del, rmdir, format, kill, shutdown)
  OUTSIDE         touches a path outside the workspace, a network path or a device
  SENSITIVE       touches a file that usually holds a secret
  HUMAN_ONLY      publishes, pays, or changes keys (git push, npm publish, cmdkey ...): maps to a canonical HUMAN_ONLY action name
Anything that is not READ needs a signed commitment when an agent asked for it; a person at the keyboard needs one only for HUMAN_ONLY."""
import os
import re
import unicodedata

from vega_terminal import pathrules
from vega_terminal.lex import Refused

ORDER = ["READ", "WRITE", "NETWORK", "EXEC", "UNKNOWN", "DESTRUCTIVE", "OUTSIDE", "SENSITIVE", "HUMAN_ONLY"]

BUILTIN_READ = {"pwd", "echo", "cd", "ls", "dir", "cat", "type", "head", "tail", "wc", "grep"}
BUILTIN_PATH_ARGS = {"cd", "ls", "dir", "cat", "type", "head", "tail", "wc", "grep"}
GIT_READ = {"status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "describe", "shortlog", "ls-tree", "rev-list"}
GIT_LIST_ONLY = {"branch": {"-a", "-r", "-v", "-vv", "--list", "--show-current"}, "tag": {"-l", "--list"}, "remote": {"-v"}}
GIT_BAD_FLAGS = {"--output", "-o", "--open-files-in-pager", "-O", "--ext-diff", "--textconv", "--exec", "--upload-pack", "--receive-pack", "--exec-path", "--git-dir", "--work-tree", "--config-env", "-c", "-C"}
GIT_BAD_PREFIX = ("--output", "--exec", "--upload-pack", "--receive-pack", "--open-files-in-pager", "--git-dir", "--work-tree", "--config-env", "--ext-diff", "--textconv")
GIT_HUMAN_ONLY = {"push": "release_public"}
GIT_NETWORK = {"fetch", "pull", "clone", "ls-remote", "submodule"}
GIT_WRITE = {"add", "commit", "checkout", "switch", "restore", "merge", "rebase", "stash", "tag", "branch", "init", "cherry-pick", "mv", "revert", "apply", "am", "worktree", "config", "remote"}
GIT_DESTRUCTIVE = {"reset", "clean", "rm", "gc", "prune", "filter-branch", "update-ref"}

NETWORK_PROGS = {"curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "ssh", "scp", "sftp", "ftp", "nc", "ncat", "telnet", "ping", "nslookup", "tracert", "pip", "pip3", "npm", "pnpm",
                 "yarn", "winget", "choco", "conda", "bitsadmin", "certutil", "gh", "docker", "ollama"}
EXEC_PROGS = {"python", "python3", "py", "node", "deno", "bun", "powershell", "pwsh", "cmd", "bash", "sh", "zsh", "wsl", "cscript", "wscript", "mshta", "rundll32", "regsvr32", "msiexec", "cargo", "go",
              "java", "javac", "make", "cmake", "dotnet", "msbuild", "npx", "uv", "uvx", "start", "invoke-expression", "iex", "eval", "xargs", "env", "sudo", "runas", "schtasks", "sc", "at", "wmic", "reg",
              "setx", "set", "export", "alias", "source"}
DESTRUCTIVE_PROGS = {"rm", "del", "erase", "rmdir", "rd", "remove-item", "ri", "format", "shutdown", "taskkill", "kill", "pkill", "diskpart", "cipher", "dd", "truncate", "shred", "mkfs", "fsutil",
                     "icacls", "takeown", "attrib", "chmod", "chown"}
WRITE_PROGS = {"mkdir", "md", "touch", "cp", "copy", "mv", "move", "ren", "rename", "new-item", "ni", "set-content", "add-content", "tee", "xcopy", "robocopy"}
HUMAN_PROGS = {"cmdkey": "change_key_registry", "vaultcmd": "change_key_registry", "keyring": "change_key_registry", "ssh-keygen": "change_key_registry", "ssh-add": "change_key_registry",
               "gpg": "change_key_registry", "twine": "release_public", "vsce": "release_public", "vercel": "release_public", "netlify": "release_public", "firebase": "release_public",
               "stripe": "spend_funds", "solana": "spend_funds", "cast": "spend_funds", "paypal": "spend_funds"}
HUMAN_SUB = {("npm", "publish"): "release_public", ("pnpm", "publish"): "release_public", ("yarn", "publish"): "release_public", ("cargo", "publish"): "release_public",
             ("gh", "release"): "release_public", ("docker", "push"): "release_public", ("gh", "repo"): "release_public", ("gh", "pr"): "release_public"}
LAUNCHER_EXT = (".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".lnk", ".com", ".scr", ".pif", ".hta", ".msi", ".reg", ".url")
_RUNS_CODE = re.compile(r"(?i)^(-+(enc|encodedcommand|ec|command|exec|execdir|delete|ok|pre|hostname-bin)|-c|-e|/c|/k)$")
_PATHISH = re.compile(r"[\\/]|^\.\.?$|^[A-Za-z]:|~")
_URL = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://")
_GREP_FLAGS = re.compile(r"-[inlcvw]+|--ignore-case|--line-number|--count")
_PLAIN_FLAGS = re.compile(r"-[0-9]+|-n[0-9]*|-[a-zA-Z]{1,4}|--lines=[0-9]+")


def program_name(word):
    """The comparison name of a program: ASCII only, no invisible characters, no path, no extension; anything odd is refused."""
    if not isinstance(word, str) or not word:
        raise Refused("empty program name")
    if unicodedata.normalize("NFKC", word) != word or not word.isascii() or any(not c.isprintable() for c in word):
        raise Refused("program name %r is not plain ASCII" % word)
    base = re.split(r"[\\/]", word)[-1].casefold()
    if base.endswith(LAUNCHER_EXT):
        raise Refused("script launchers (%s) are not run by the governed terminal" % os.path.splitext(base)[1])
    return base[:-4] if base.endswith(".exe") else base


def _raise(cls, new):
    return max(cls, new, key=ORDER.index)


def _scan_paths(args, root, cwd, cls, reasons, paths, skip_flags=True):
    for a in args:
        if a.startswith("-") and "=" not in a and skip_flags:
            continue
        val = a.split("=", 1)[1] if a.startswith("-") and "=" in a else a
        if _PATHISH.search(val) and not _URL.match(val):
            p, fl = pathrules.check(root, cwd, val)
            if p:
                paths.append(p)
            if "outside" in fl or "device" in fl:
                cls = _raise(cls, "OUTSIDE")
                reasons.append("path %r is outside the workspace or not a plain path" % val)
            elif "sensitive" in fl:
                cls = _raise(cls, "SENSITIVE")
                reasons.append("path %r looks like it holds a secret" % val)
    return cls


def classify_stage(words, root, cwd, piped=False):
    """-> dict(cls, reasons, action, prog, paths). action is a canonical HUMAN_ONLY name or None."""
    prog = program_name(words[0])
    args = words[1:]
    reasons, paths = [], []
    bare = re.split(r"[\\/]", words[0])[-1] == words[0]
    if prog in BUILTIN_READ and bare:
        cls = "READ"
        if prog in BUILTIN_PATH_ARGS:
            if prog == "grep":
                pos = [a for a in args if not a.startswith("-")]
                cands = pos[1:]                                                         # the first positional is the pattern
                if any(a.startswith("-") and not _GREP_FLAGS.fullmatch(a) for a in args):
                    cls, reasons = "UNKNOWN", reasons + ["unsupported grep flag"]
                if not pos:
                    cls, reasons = "UNKNOWN", reasons + ["grep needs a pattern"]
            else:
                cands = [a for i, a in enumerate(args) if not a.startswith("-") and not (i and args[i - 1] == "-n" and a.isdigit())]
                if any(a.startswith("-") and not _PLAIN_FLAGS.fullmatch(a) for a in args):
                    cls, reasons = "UNKNOWN", reasons + ["unsupported flag"]
            if not cands and prog in ("cat", "type", "head", "tail", "wc", "grep") and not (piped and prog in ("head", "tail", "wc", "grep")):
                cls, reasons = "UNKNOWN", reasons + ["reading standard input or a whole tree is not supported"]
            for a in cands:
                p, fl = pathrules.check(root, cwd, a)
                if p:
                    paths.append(p)
                if "outside" in fl or "device" in fl:
                    cls, reasons = _raise(cls, "OUTSIDE"), reasons + ["path %r is outside the workspace or not a plain path" % a]
                elif "sensitive" in fl:
                    cls, reasons = _raise(cls, "SENSITIVE"), reasons + ["path %r looks like it holds a secret" % a]
        return dict(cls=cls, reasons=reasons, action=None, prog=prog, paths=paths)
    if prog == "git":
        return _git(args, root, cwd)
    if not bare:
        reasons.append("program given by path")
    if prog in HUMAN_PROGS:
        return dict(cls="HUMAN_ONLY", reasons=["%s changes keys, publishes or spends" % prog], action=HUMAN_PROGS[prog], prog=prog, paths=[])
    sub = next((a.casefold() for a in args if not a.startswith("-")), None)
    if (prog, sub) in HUMAN_SUB:
        return dict(cls="HUMAN_ONLY", reasons=["%s %s publishes" % (prog, sub)], action=HUMAN_SUB[(prog, sub)], prog=prog, paths=[])
    cls = ("DESTRUCTIVE" if prog in DESTRUCTIVE_PROGS else "EXEC" if prog in EXEC_PROGS else "NETWORK" if prog in NETWORK_PROGS else "WRITE" if prog in WRITE_PROGS else "UNKNOWN")
    if any(_RUNS_CODE.match(a) for a in args):
        cls = _raise(cls, "EXEC")
        reasons.append("an argument runs code or deletes (-enc / -c / -exec / -delete)")
    cls = _scan_paths(args, root, cwd, cls, reasons, paths)
    return dict(cls=cls, reasons=reasons, action=None, prog=prog, paths=paths)


def _git(args, root, cwd):
    r = dict(cls="UNKNOWN", reasons=[], action=None, prog="git", paths=[])
    if not args:
        return r
    if args[0].startswith("-"):
        r["cls"] = "EXEC" if args[0] in GIT_BAD_FLAGS or args[0].startswith(("-c", "-C") + GIT_BAD_PREFIX) else "UNKNOWN"
        r["reasons"] = ["git option before the subcommand changes configuration or location"]
        return r
    sub, rest = args[0].casefold(), args[1:]                      # git treats the name as case-sensitive on most systems; a case-insensitive file system or alias must not turn 'PUSH' into a free pass
    if sub in GIT_HUMAN_ONLY:
        r.update(cls="HUMAN_ONLY", action=GIT_HUMAN_ONLY[sub], reasons=["git %s publishes" % sub])
    elif sub in GIT_DESTRUCTIVE:
        r["cls"] = "DESTRUCTIVE"
    elif sub in GIT_NETWORK:
        r["cls"] = "NETWORK"
    elif sub in GIT_LIST_ONLY:
        r["cls"] = "READ" if all(a in GIT_LIST_ONLY[sub] for a in rest) else "WRITE"
    elif sub in GIT_READ:
        bad = [a for a in rest if a in GIT_BAD_FLAGS or a.startswith(GIT_BAD_PREFIX)]
        if bad:
            r.update(cls="EXEC", reasons=["git %s with %s can write files or run a program" % (sub, bad[0])])
        else:
            r["cls"] = _scan_paths(rest, root, cwd, "READ", r["reasons"], r["paths"])
    elif sub in GIT_WRITE:
        r["cls"] = "WRITE"
    return r


def worst(classes):
    return max(classes, key=ORDER.index)
