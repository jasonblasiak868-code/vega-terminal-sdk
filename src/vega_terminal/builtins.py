"""builtins.py - the read commands the terminal runs itself, in Python, with no subprocess at all.

An agent's everyday reading (look at a folder, read a file, search it) never starts a program, so there is nothing to hijack: no PATH lookup, no shell, no plug-in. Every path is re-checked
here against the workspace (the policy already classified it; this is the second look). Each command takes (args, stdin_bytes, session) and returns (stdout_bytes, exit_code)."""
import os
import re

from vega_custody import safepaths as sp
from vega_terminal import pathrules

FILE_CAP = 1 << 20
LIST_CAP = 1000


class BuiltinError(Exception):
    pass


def _path(sess, arg):
    p, fl = pathrules.check(sess.root, sess.cwd, arg)
    if p is None or fl & {"outside", "device"}:
        raise BuiltinError("%s: outside the workspace or not a plain path" % arg)
    return p


def _read(sess, arg):
    p = _path(sess, arg)
    if not os.path.isfile(p):
        raise BuiltinError("%s: not a file" % arg)
    try:
        return sp.read_capped(p, FILE_CAP)
    except sp.PathRefused as exc:
        raise BuiltinError(str(exc))


def _texts(sess, paths, stdin):
    """The text of each named file, or of standard input when no file is named (a piped stage)."""
    if not paths:
        return [stdin[:FILE_CAP].decode("utf-8", "replace")]
    return [_read(sess, a).decode("utf-8", "replace") for a in paths]


def _lines_count(args):
    n, paths, i = 10, [], 0
    while i < len(args):
        a = args[i]
        if a == "-n" and i + 1 < len(args) and args[i + 1].isdigit():
            n, i = int(args[i + 1]), i + 2
            continue
        m = re.fullmatch(r"-n?([0-9]+)|--lines=([0-9]+)", a)
        if m:
            n = int(m.group(1) or m.group(2))
        elif a.startswith("-"):
            raise BuiltinError("unsupported flag %s" % a)
        else:
            paths.append(a)
        i += 1
    return min(n, 10000), paths


def pwd(args, stdin, sess):
    return (sess.cwd + "\n").encode(), 0


def echo(args, stdin, sess):
    return (" ".join(args) + "\n").encode(), 0


def cd(args, stdin, sess):
    if len(args) != 1:
        raise BuiltinError("cd takes one folder")
    p = _path(sess, args[0])
    if not os.path.isdir(p):
        raise BuiltinError("%s: not a folder" % args[0])
    sess.cwd = p
    return b"", 0


def ls(args, stdin, sess):
    if any(a.startswith("-") for a in args):
        args = [a for a in args if not a.startswith("-")]
    out = []
    for a in (args or ["."]):
        p = _path(sess, a)
        if os.path.isfile(p):
            out.append(os.path.basename(p))
            continue
        if not os.path.isdir(p):
            raise BuiltinError("%s: not found" % a)
        names = sorted(os.listdir(p))
        for nm in names[:LIST_CAP]:
            out.append(nm + ("/" if os.path.isdir(os.path.join(p, nm)) else ""))
        if len(names) > LIST_CAP:
            out.append("... %d more" % (len(names) - LIST_CAP))
    return ("\n".join(out) + "\n").encode(), 0


def cat(args, stdin, sess):
    return b"".join(_read(sess, a) for a in args if not a.startswith("-")), 0


def head(args, stdin, sess):
    n, paths = _lines_count(args)
    out = []
    for text in _texts(sess, paths, stdin):
        out.extend(text.split("\n")[:n])
    return ("\n".join(out) + "\n").encode(), 0


def tail(args, stdin, sess):
    n, paths = _lines_count(args)
    out = []
    for text in _texts(sess, paths, stdin):
        out.extend(text.rstrip("\n").split("\n")[-n:])
    return ("\n".join(out) + "\n").encode(), 0


def wc(args, stdin, sess):
    flags = [a for a in args if a.startswith("-")]
    names = [a for a in args if not a.startswith("-")]
    out = []
    items = [(a, _read(sess, a)) for a in names] if names else [("", stdin[:FILE_CAP])]
    for name, data in items:
        text = data.decode("utf-8", "replace")
        cols = {"-l": text.count("\n"), "-w": len(text.split()), "-c": len(data)}
        picked = [cols[f] for f in flags if f in cols] or [cols["-l"], cols["-w"], cols["-c"]]
        out.append(" ".join(str(x) for x in picked) + (" " + name if name else ""))
    return ("\n".join(out) + "\n").encode(), 0


def grep(args, stdin, sess):
    flags = "".join(a[1:] for a in args if re.fullmatch(r"-[inlcvw]+", a))
    for a in args:
        if a.startswith("-") and not re.fullmatch(r"-[inlcvw]+|--ignore-case|--line-number|--count", a):
            raise BuiltinError("unsupported grep flag %s" % a)
    if "--ignore-case" in args:
        flags += "i"
    if "--line-number" in args:
        flags += "n"
    if "--count" in args:
        flags += "c"
    pos = [a for a in args if not a.startswith("-")]
    pat, files = pos[0], pos[1:]
    needle = pat.casefold() if "i" in flags else pat
    out, matched = [], False
    sources = list(zip(files, _texts(sess, files, b""))) if files else [("", stdin[:FILE_CAP].decode("utf-8", "replace"))]
    for f, text in sources:
        lines = text.split("\n")
        hits = []
        for i, line in enumerate(lines, 1):
            hay = line.casefold() if "i" in flags else line
            ok = (re.search(r"(?<!\w)" + re.escape(needle) + r"(?!\w)", hay) is not None) if "w" in flags else (needle in hay)
            if ok != ("v" in flags):
                hits.append((i, line))
        matched = matched or bool(hits)
        if "c" in flags:
            out.append("%s:%d" % (f, len(hits)) if len(files) > 1 else str(len(hits)))
        elif "l" in flags:
            if hits:
                out.append(f)
        else:
            for i, line in hits[:LIST_CAP]:
                out.append(("%s:" % f if len(files) > 1 else "") + ("%d:" % i if "n" in flags else "") + line)
    return ("\n".join(out) + ("\n" if out else "")).encode(), 0 if matched else 1


TABLE = {"pwd": pwd, "echo": echo, "cd": cd, "ls": ls, "dir": ls, "cat": cat, "type": cat, "head": head, "tail": tail, "wc": wc, "grep": grep}
