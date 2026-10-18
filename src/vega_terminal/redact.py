"""redact.py - what comes back from a command is scrubbed before anyone (a person, an agent, the record) sees it.

  strip_controls(text)   removes terminal escape sequences (title changes, clipboard writes, cursor tricks) and control characters; keeps tab and newline
  scrub(text)            replaces any line that looks like a credential with a marker; returns (text, number_of_lines_replaced)"""
import re

from vega_custody.dag.dag import contains_credential

_ESC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[P^_X][^\x1b]*(?:\x1b\\)?|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|\x9b[0-?]*[ -/]*[@-~]|\x9d[^\x07\x9c]*[\x07\x9c]?")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")


def strip_controls(text):
    prev = None
    while prev != text:                                    # nested or re-assembled sequences (ESC ESC [ ...) are peeled until none is left
        prev = text
        text = _ESC.sub("", text)
    return _CTRL.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))


def scrub(text):
    """Best-effort: pattern matching on single lines and on each pair of neighbouring lines (joined with a newline and joined with nothing), so 'password' on one line and its value on
    the next, or a key broken across two lines, are still caught. A program that splits a secret across three or more lines, or encodes it, is not caught: this is a seatbelt, not a seal."""
    lines = strip_controls(text).split("\n")
    bad = {i for i, line in enumerate(lines) if contains_credential(line)}
    for i in range(len(lines) - 1):
        if i not in bad and i + 1 not in bad and (contains_credential(lines[i] + "\n" + lines[i + 1]) or contains_credential(lines[i] + lines[i + 1])):
            bad.update((i, i + 1))
    out = ["[REDACTED: credential-shaped line]" if i in bad else line for i, line in enumerate(lines)]
    return "\n".join(out), len(bad)
