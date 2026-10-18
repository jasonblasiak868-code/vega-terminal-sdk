"""lex.py - a command line is split into stages WITHOUT a shell, and anything a shell would expand is refused as opaque.

No shell ever sees the text, so the only way a second command can hide inside a line is syntax this file does not understand: it is marked OPAQUE (or the whole line is refused),
never guessed at. Quotes group words; there are no backslash escapes (Windows paths); `$`, a backtick, `^`, `%name%` and braces/parentheses anywhere make the line opaque."""
import re
import unicodedata

MAX_LINE = 8192
MAX_STAGES = 16


class Refused(ValueError):
    pass


_OPAQUE = re.compile(r"[$`^]|%[^%\s]+%|[(){}]")
_SEP = {";", "&&", "||", "\n"}


def clean_line(text):
    if not isinstance(text, str):
        raise Refused("a command line is text")
    if "\x00" in text:
        raise Refused("NUL in a command line")
    if len(text) > MAX_LINE:
        raise Refused("command line over %d characters" % MAX_LINE)
    for c in text:
        cat = unicodedata.category(c)
        if (cat in ("Cf", "Cc") and c not in "\t\n\r") or cat in ("Zl", "Zp") or (ord(c) > 127 and not c.isalnum() and not c.isprintable()):
            raise Refused("invisible or control character %r in a command line" % c)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def split(text):
    """-> (stages, opaque). stages: list of {"words": [...], "sep_after": ';'|'&&'|'||'|'|'|None, "redirect": (">"|">>", target)|None}."""
    text = clean_line(text)
    opaque = bool(_OPAQUE.search(text))
    toks, cur, i, n = [], [], 0, len(text)
    have_word = False

    def flush():
        nonlocal cur, have_word
        if have_word:
            toks.append(("w", "".join(cur)))
        cur, have_word = [], False
    while i < n:
        c = text[i]
        if c in "'\"":
            j = text.find(c, i + 1)
            if j < 0:
                raise Refused("unterminated quote")
            cur.append(text[i + 1:j])
            have_word = True
            i = j + 1
            continue
        if c in " \t":
            flush()
            i += 1
            continue
        if c == "\n":
            flush()
            toks.append(("o", "\n"))
            i += 1
            continue
        two = text[i:i + 2]
        if two in ("&&", "||", ">>"):
            flush()
            toks.append(("o", two))
            i += 2
            continue
        if c in ";|>&<":
            if c in "&<":
                raise Refused("background '&' and input redirection '<' are not supported")
            flush()
            toks.append(("o", c))
            i += 1
            continue
        if c.isdigit() and i + 1 < n and text[i + 1] == ">" and not cur:
            raise Refused("numbered redirection (2> ...) is not supported")
        cur.append(c)
        have_word = True
        i += 1
    flush()
    stages, words, sep, redir = [], [], None, None
    k = 0
    while k < len(toks):
        kind, v = toks[k]
        if kind == "w":
            words.append(v)
        elif v in (">", ">>"):
            if k + 1 >= len(toks) or toks[k + 1][0] != "w":
                raise Refused("redirection without a target")
            if redir:
                raise Refused("one redirection per stage")
            redir = (v, toks[k + 1][1])
            k += 1
        else:
            if not words:
                if v == "\n":
                    k += 1
                    continue
                raise Refused("empty command before %r" % v)
            stages.append({"words": words, "sep_after": ";" if v == "\n" else v, "redirect": redir})
            words, redir = [], None
        k += 1
    if words:
        stages.append({"words": words, "sep_after": None, "redirect": redir})
    elif toks and toks[-1] == ("o", "|"):
        raise Refused("pipe with nothing after it")
    if not stages:
        raise Refused("empty command")
    if len(stages) > MAX_STAGES:
        raise Refused("more than %d stages" % MAX_STAGES)
    for idx, s in enumerate(stages):
        if s["sep_after"] == "|" and s["redirect"]:
            raise Refused("a redirected stage cannot feed a pipe")
    return stages, opaque
