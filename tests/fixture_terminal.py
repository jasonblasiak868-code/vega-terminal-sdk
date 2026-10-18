"""Shared fixture for the terminal tests (not a test file)."""
import pathlib
import tempfile
import types

from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_jacket import humanauth
from vega_jacket.commit.commit import Commit
from vega_jacket.gate.exit_gate import ExitGate
from vega_jacket.humanauth import human_signer, verify
from vega_terminal.session import Session

PW, DEV, SURF = "correct horse battery", "dev-term", "surf-term"


def build(timeout=20.0):
    blob, pub = human_signer.generate(PW)
    t = pathlib.Path(tempfile.mkdtemp())
    work = t / "work"
    work.mkdir()
    dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
    led = Ledger([LocalBackend(t / "led.jsonl")], commitment_check=verify.commitment_signature_checker(pub))
    ver = humanauth.Verifier(pub, DEV, SURF)
    gate = ExitGate(Commit(ver, led, dag), led, ver, dag)
    sess = Session(str(work), dag, gate, timeout=timeout)

    def sign(action, params, lease=300):
        return human_signer.sign(blob, PW, DEV, SURF, action, params, lease)

    def sign_line(line, action="terminal_exec"):
        return sign(action, sess.params_for(line))
    return types.SimpleNamespace(t=t, work=work, dag=dag, led=led, gate=gate, sess=sess, sign=sign, sign_line=sign_line)


def kinds(fx):
    return [e["kind"] for e in fx.dag.content.entries()]
