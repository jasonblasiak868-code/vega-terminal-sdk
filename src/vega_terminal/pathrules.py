"""pathrules.py - which paths a command may touch.

A path argument is allowed only if it stays inside the workspace after symlinks are resolved, is not a network or device path, and is not a file that usually holds a
secret (keys, .env, credential stores). Anything else is OUTSIDE or SENSITIVE and needs a signed commitment."""
import os
import re

_SENSITIVE_NAME = re.compile(r"(?i)(^\.env($|\.)|\.(pem|key|pfx|p12|ppk|kdbx|keystore|jks|asc|gpg)$|^id_(rsa|dsa|ecdsa|ed25519)|(^|[_.-])(secret|secrets|credential|credentials|passwd|password|token|tokens|apikey|api_key|vega_keys)([_.-]|$)|^\.(npmrc|pypirc|netrc|git-credentials|pgpass)$|^known_hosts$|^authorized_keys$|^kubeconfig$)")
_SENSITIVE_DIR = {".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker", ".config", "credentials", "secrets", "appdata", ".git"}
_DEVICE = re.compile(r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$")


def check(root, cwd, arg):
    """Resolve a path argument against cwd. Returns (absolute_path or None, flags) where flags is a set of 'outside' / 'sensitive' / 'device'."""
    flags = set()
    if not isinstance(arg, str) or not arg or "\x00" in arg:
        return None, {"outside"}
    a = arg.replace("/", "\\")
    drive = re.match(r"^[A-Za-z]:", a)
    if a.startswith("\\\\") or (drive and not a.startswith(drive.group(0) + "\\")) or ":" in a[2 if drive else 0:]:
        return None, {"outside"}                                      # UNC / device namespace / alternate data stream / drive-relative
    for p in (q for q in a.split("\\") if q):
        if p not in (".", "..") and (p.endswith((".", " ")) or _DEVICE.match(p)):
            flags.add("device")
    if any(c in arg for c in "~*?"):
        flags.add("outside")                                          # no globbing, no home expansion: refused rather than guessed at
    target = os.path.realpath(arg if os.path.isabs(arg) else os.path.join(cwd, arg))
    root_real = os.path.realpath(root)
    try:
        inside = os.path.commonpath([root_real, target]) == root_real
    except ValueError:
        inside = False
    if not inside:
        flags.add("outside")
    rel = os.path.relpath(target, root_real) if inside else ""
    comps = [c for c in re.split(r"[\\/]+", rel) if c and c != "."]
    if any(_SENSITIVE_NAME.search(c) for c in comps) or any(c.lower() in _SENSITIVE_DIR for c in comps):
        flags.add("sensitive")
    return target, flags
