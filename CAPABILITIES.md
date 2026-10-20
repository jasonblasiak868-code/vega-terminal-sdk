# vega-superproof-sdk — Capabilities

Minute capability inventory: every capability this repo publishes, why a policy-or-prompt-level approach structurally cannot provide it, where it is enforced in code, which test demonstrates it, and the honest limit.

## Table of Contents
- [Tier architecture](#tier-architecture)
- [Zero-knowledge (zk.py) — privacy tier rationale](#zero-knowledge-zkpy--privacy-tier-rationale)
- [Fully homomorphic encryption (fhe.py) — fail-closed interface](#fully-homomorphic-encryption-fhepy--fail-closed-interface)
- [Updatable encryption (rotation.py)](#updatable-encryption-rotationpy)
- [Key re-wrap / scrambler (scrambler.py)](#key-re-wrap--scrambler-scramblerpy)
- [Capabilities](#capabilities)
- [Family predictive loop — this repo's part](#family-predictive-loop--this-repos-part)

## Tier architecture

The seal produces a proof at one of four tiers. Tier 0 is built-in and always available. Tiers 1–3 require a registered backend (via `builtin.enable_*()`); without one, the seal raises `TierUnavailable` **before any DAG write** — no silent downgrade, no partial output.

| Tier | Name | Status | What it proves | Backend registration |
|------|------|--------|----------------|---------------------|
| 0 | Integrity | **BUILT** (`proof_tier0.py`) | This exact ciphertext, configuration (preset), and lineage were produced. Binding = SHA-256(canonicalized {tier:0, statement}). Never faked. | None required (built-in) |
| 1 | Privacy (SNARK) | **DESIGNED interface / BUILT backend** (`proof_tier1.py` + `builtin.PrivacyBackend`) | Schnorr proof of knowledge: the sealer knows the discrete log of a public point, bound to the seal statement via Fiat-Shamir. Classical security (secp256k1). | `builtin.enable_privacy(secret)` registers `PrivacyBackend` which uses `zk.prove_knowledge()` |
| 2 | Quantum-proof (STARK) | **DESIGNED interface / BUILT backend** (`proof_tier2.py` + `builtin.QuantumBackend`) | Attestation that every primitive in the seal is quantum-resistant: layers ⊆ {aes-256-gcm, chacha20-poly1305}, hash = sha256, signature = hashsig-sha256-w16. Verifier re-checks against `QUANTUM_SAFE` allow-list. | `builtin.enable_quantum_proof()` registers `QuantumBackend` AND `hashsig.register()` |
| 3 | Locked compute | **DESIGNED interface / BUILT backend** (`proof_tier3.py` + `builtin.ComputeBackend`) | Tier 2 + binding to LWE parameter set ID, encryption epoch, and rotation log hash. Says *which generation* of the updating encryption the seal belongs to. | `builtin.enable_locked_compute(params_id, epoch, rotation_log_sha256)` registers `ComputeBackend` AND `hashsig.register()` |

**Fail-closed semantics (all tiers 1–3):** `proof_tierN.require_prover()` raises `TierUnavailable` if no backend registered. Registration is deliberate (`replace=True` required to change). The seal pipeline calls `require_prover()` **before any DAG write** (`superproof.seal()` lines 47–57).

**Design note:** "Quantum-proof" means the seal rests only on hashes and 256-bit symmetric keys — a large quantum computer weakens but does not break them (~128-bit security remains). The zero-knowledge tier (tier 1) relies on discrete log and is **NOT quantum-proof**. General-purpose SNARK/STARK provers are DESIGN ONLY — their interfaces fail closed.

## Zero-knowledge (zk.py) — privacy tier rationale

### What the built zk.py does
`seal/zk.py` implements zero-knowledge proofs on **secp256k1** (classical security, discrete log). It provides:

- **Pedersen commitments** (`commit`, `opens_to`): perfectly hiding, computationally binding (C = v*G + r*H).
- **Schnorr proof of knowledge** (`prove_knowledge`, `verify_knowledge`): proves knowledge of `x` for public `Y = x*G` bound to a message (signature of knowledge).
- **Bit-by-bit range proofs** (`prove_range`, `verify_range`): proves a committed value is in `[0, 2^bits)` without revealing it. Uses CDS OR-proofs per bit (each bit proven to be 0 or 1). Max 64 bits.
- **At-least proofs** (`prove_at_least`, `verify_at_least`): proves `v ≥ T` (and `< T + 2^bits`) via range proof on `C - T*G`. The 'income at least X' / 'balance at least X' building block.
- **Issuer attestation** (`attest`, `verify_attestation`): an issuer's Ed25519 signature over a commitment + label (e.g., "monthly_income_cents"), so a verifier knows WHO vouches for the hidden number.

Every proof is bound to a **CONTEXT** (bytes) through the Fiat-Shamir hash, so a proof made for one purpose does not verify for another.

**Honest limits:** Classical security only (a large quantum computer breaks the discrete log); the quantum-proof tier is hash-based (disclosure.py, hashsig.py). Plain Python, not constant-time, no independent cryptographic review: do not protect real secrets with it before one.

### Privacy-industry rationale (why this tier exists)
Tier 1 exists because **regulated industries cannot transfer sensitive data without proving the transfer happened without revealing the data itself**.

| Industry | What must stay private | What must be provable | How tier 1 addresses it |
|----------|------------------------|----------------------|-------------------------|
| **HIPAA / Medical** | Patient records, diagnoses, treatment codes, PHI | That a record was sealed, who authorized it, that the *same* record reaches the recipient | Schnorr proof of knowledge binds the sealer's secret to the seal statement — the verifier learns *that* the seal was produced by someone holding the authorizing key, without learning the record contents. Range proofs (`prove_range`) let a hospital prove "age ≥ 18" or "dosage ≤ max" without revealing the exact value. Issuer attestation lets a hospital sign a commitment to a diagnosis code. |
| **Banking / Finance** | Account numbers, transfer amounts, counterparties, balances | That a transfer was authorized, that amounts are within limits, that the same keys sealed both layers | At-least proofs (`prove_at_least`) let a bank prove "balance ≥ transfer amount" without revealing the balance. Range proofs prove "amount ≤ regulatory limit". The dual lineage binds the *content* (the transfer) to the *keys* (who authorized it) — a record cannot be re-attributed to different keys or different data. |
| **Government / Classified** | Classification levels, compartment markings, source identities | That a document was sealed at the correct classification, that the seal chain is unbroken, that rotation history is intact | The seal's dual lineage + tier 1 proof provides cryptographic evidence that the *same* keys produced both ciphertext layers and that the seal statement (including classification metadata) is bound to the proof. Rotation log hashes in tier 3 extend this to key rotation history. |

**What tier 1 does NOT do:** It does not make the data confidential (that is the two-layer encryption's job). It does not prove the *truth* of the committed values (that is the issuer's attestation). It does not provide quantum-proof privacy (tier 2/3 use hash-based primitives for that).

## Fully homomorphic encryption (fhe.py) — fail-closed interface

`seal/fhe.py` provides **only the interface and the refusal**. The SDK carries no homemade FHE scheme.

```python
class FHEUnavailable(Exception):
    """Locked compute was requested and no FHE backend is registered."""

_BACKEND = None

def register_backend(backend, replace: bool = False): ...
def available() -> bool: ...
def locked_compute(operation: str, ciphertexts: list):  # raises FHEUnavailable if _BACKEND is None
```

**Behavior:** If no backend is registered, any request for locked compute raises `FHEUnavailable` — **it never falls back to computing on plaintext**. A backend must expose `evaluate(operation: str, ciphertexts: list) -> object`.

**Design note:** FHE hides the data; it does not prove the computation ran correctly. Pair it with an execution proof (see `vega-harness-sdk` cards/server_card.py: `verify_execution_proof`).

**Status:** DESIGN ONLY per STATUS.md. The interface exists to define the contract; a vetted backend (e.g., a wrapped OpenFHE or TFHE-rs library) must be registered deliberately before `locked_compute` becomes available.

## Updatable encryption (rotation.py)

`seal/rotation.py` implements **updatable encryption** for sealed records: change the keys without losing the seal's history.

- **`KeyRatchet(root_secret)`** — epoch keys that only move forward: `advance()` derives the next epoch's pair of layer keys and drops the old one, so a key stolen later cannot open what was sealed under an earlier epoch (forward secrecy). Python cannot truly wipe memory; the old key is released, not scrubbed: for a hard guarantee keep the ratchet in a hardware module.
- **`reseal(...)`** — opens a seal with the old keys and seals the same capsule under new keys (and, if asked, another preset), writing a `SEAL_ROTATED` record that links the old top root to the new one. The old seal stays valid as history; only the new one should be kept online.

The homomorphic layer rotates its own key (`lwe.KeyHolder.rotate`), also epoch by epoch.

**Invariants:** Keys differ per epoch and layer. New keys ≠ old keys. `SEAL_ROTATED` links roots. Old seal remains verifiable.

## Key re-wrap / scrambler (scrambler.py)

**HONEST LABEL:** this is **KEY RE-WRAP (envelope encryption)**. The data key (DEK) is wrapped under a key-encryption key (KEK); rotation unwraps with the old KEK and wraps under the new one, **without touching the ciphertext**. It is not an updatable-encryption scheme over the ciphertext itself, and it is not homomorphic.

Two rules, both enforced here:
1. The card will not rotate without a **FRESH, minted, single-use commitment** (`require_commitment`).
2. Every rotation is committed to the chain and the **old key id is retired** (`commit_rotation`).

**Public interface:**
- `wrap(dek, kek, aad) -> bytes` — AES-GCM envelope encryption
- `unwrap(wrapped, kek, aad) -> bytes`
- `require_commitment(ledger, dag, commitment, action="rotate_keys") -> leaf` — checks: action matches, unexpired, minted in ledger, never used for rotation before (checks DAG for ROTATION entry with same commitment leaf)
- `commit_rotation(dag, old_kid, new_kid, commitment_leaf, parents) -> entry` — records rotation, retires old key id (ids only, never key material)
- `rotate(wrapped_dek, old_kek, new_kek, ledger, dag, commitment) -> dict` — sequences: require_commitment → unwrap → wrap → commit_rotation

## Capabilities

### 1. Two-layer authenticated encryption with algorithm tags

**Capability**: AES-256-GCM (key1) then ChaCha20-Poly1305 (key2), both authenticated; algorithm tags (`alg1`, `alg2`, `version`) embedded in every envelope so a future release can add or retire an algorithm without guessing.

**Why policy/prompt cannot**: A prompt says "use strong encryption" but cannot enforce that both layers actually ran, that the algorithms are what the caller requested, or that the envelope carries proof of which algorithms were used. The model can claim it used ChaCha20 while actually using XOR.

**Enforced in**: `seal/layers.py` — `seal_layers()` writes `alg1="aes-256-gcm"`, `alg2="chacha20-poly1305"`, `version=1`, nonces, AAD hash, and both ciphertext digests. `open_layers()` refuses unknown tags (`ValueError: "unknown algorithm tags: refusing to guess"`). `ciphertext_digest_ok()` re-hashes the actual ciphertext and compares to the envelope's claimed digest.

**Test**: `tests/test_seal.py` lines 48-58 (two layers open with both keys; wrong key rejected; tampered ciphertext rejected; identical keys refused; algorithm tags present).

**Honest limit**: Plain Python via `cryptography` library; not constant-time. No independent cryptographic review.

---

### 2. Dual lineage (content chain + key-event chain) bound into a single top root

**Capability**: Every sealed record carries two hash chains — one for *what* was sealed (content digests: capsule, c1, c2) and one for *which keys* sealed it (key events: "layer1:key_id", "layer2:key_id"). The top root = SHA-256(content_head || key_head) binds both. A record cannot be re-attributed to different keys or different data without breaking the root.

**Why policy/prompt cannot**: A prompt says "record which key was used" but the model controls the record. It can write any key identifier, or swap keys after the fact. The binding must be cryptographic and append-only, not a claim in a log the model writes.

**Enforced in**: `seal/lineage.py` — `Lineage.add_content(digest)` and `add_key_event(key_id, event)` build separate chains. `key_id()` uses domain-separated SHA-256 (not plain key hash). `root()` combines both heads. `superproof.seal()` calls `add_content` for each stage digest and `add_key_event` for each key before computing the top root.

**Test**: `tests/test_seal.py` lines 63-76 (every stage DAGed in order; lineage root recorded; audit records tier and preset hash). `tests/redteam_1_seal_verification.py` lines 49-53 (every top-level field bound — altering lineage_root, top_root, or preset_hash fails verification).

**Honest limit**: The key_id is a hash of the key; if the key is low-entropy (not from `generate_key()`), the id could be brute-forced. `layers.validate_keys()` checks for patterned keys but cannot enforce entropy source.

---

### 3. Tier 0: hash-binding integrity proof (always available, never faked)

**Capability**: Proof that this exact ciphertext, under this exact configuration card and lineage, was produced by the pipeline. Binding = SHA-256(canonicalized {tier:0, statement}). Always available — no backend registration needed. Never silently downgrades.

**Why policy/prompt cannot**: A prompt says "prove integrity" but the model can generate a fake proof string. There is no way to verify the proof without a deterministic, code-enforced binding that the model cannot spoof.

**Enforced in**: `seal/proof_tier0.py` — `prove()` returns `{"tier":0, "statement":..., "binding":sha256(canon({tier:0, statement}))}`. `verify()` recomputes the binding and checks it matches. No external dependency.

**Test**: `tests/test_seal.py` lines 61-71 (seal verifies independently; seal opens back to capsule; every stage DAGed in order including STAGE:proof-tier0).

**Honest limit**: Integrity and binding only — NOT zero-knowledge. Does not prove a computation was done correctly; tiers 1–3 exist for that.

---

### 4. Tier 1 (privacy): Schnorr proof of knowledge bound to the seal statement — fails closed without registered prover

**Capability**: A zero-knowledge proof (Schnorr signature of knowledge) that the sealer knows the discrete log of a public point, bound to the exact seal statement via Fiat-Shamir. The tier refuses to run if no prover is registered (`TierUnavailable` raised before any DAG write).

**Why policy/prompt cannot**: A prompt says "prove you know the secret without revealing it" — the model can output a convincing-looking proof string. Without a registered, code-enforced verifier that the model cannot swap, there is no guarantee the proof is real or bound to this seal.

**Enforced in**: `seal/proof_tier1.py` — `_BACKEND` global, `register()`, `require_prover()` raises `TierUnavailable`. `seal/superproof.py` calls `require_prover()` before any DAG write. `seal/builtin.py` `PrivacyBackend` implements Schnorr proof of knowledge via `zk.prove_knowledge()` bound to `statement_digest(statement)`. `enable_privacy(secret)` registers it deliberately.

**Test**: `tests/test_seal.py` lines 79-84 (tier 1 without prover refuses; refused seal wrote nothing). `tests/redteam_3_upper_tiers.py` lines 434-444 (privacy tier works once prover registered; proof bound to this seal; secret nowhere in record).

**Honest limit**: Classical security only (discrete log on secp256k1). Plain Python, not constant-time. No independent review. Requires deliberate `builtin.enable_privacy()` call at startup — tier is unavailable by default.

---

### 5. Tier 2 (quantum-proof): attestation that every primitive in the seal is quantum-resistant — fails closed without registration

**Capability**: A proof that the seal uses only quantum-resistant primitives: 256-bit symmetric ciphers (AES-256-GCM, ChaCha20-Poly1305), SHA-256, and the hash-based stateful signature (Winternitz w=16 under Merkle). The attestation is checked by the verifier against the `QUANTUM_SAFE` allow-list. Fails closed without `builtin.enable_quantum_proof()`.

**Why policy/prompt cannot**: A prompt says "use quantum-proof algorithms" but the model cannot prove which algorithms were actually used at seal time. The configuration could drift, or a weaker algorithm could be substituted. The attestation is a cryptographic binding of the *actual* primitives used, verified against a fixed allow-list.

**Enforced in**: `seal/proof_tier2.py` — same fail-closed interface as tier 1. `seal/builtin.py` `QuantumBackend._attest()` returns the allow-list and statement digest. `verify()` checks `layers ⊆ QUANTUM_SAFE["layers"]`, `hash ∈ QUANTUM_SAFE["hash"]`, `signature ∈ QUANTUM_SAFE["signature"]`. `enable_quantum_proof()` registers backend AND calls `hashsig.register()`.

**Test**: `tests/redteam_3_upper_tiers.py` lines 446-457 (quantum_proof tier uses only quantum-resistant parts; classical seal cannot pass as quantum-proof; attestation naming a weak part is refused).

**Honest limit**: "Quantum-proof" means the seal rests only on hashes and 256-bit symmetric keys — a large quantum computer weakens but does not break them (~128-bit security remains). Not a claim about every attack. Code has no independent review. The zero-knowledge tier (tier 1) relies on discrete log and is NOT quantum-proof.

---

### 6. Tier 3 (locked compute): tier 2 + binding to homomorphic parameters, epoch, and rotation log hash

**Capability**: Extends tier 2 with a binding to the LWE parameter set ID, the encryption epoch, and the rotation log hash. This says *which generation* of the updating encryption the seal belongs to. Fails closed without `builtin.enable_locked_compute(params_id, epoch, rotation_log_sha256)`.

**Why policy/prompt cannot**: A prompt says "bind to the encryption generation" but cannot enforce that the binding is cryptographic, that the epoch matches the actual ciphertexts, or that the rotation log is the one that was used. The model can claim any epoch.

**Enforced in**: `seal/proof_tier3.py` — fail-closed interface. `seal/builtin.py` `ComputeBackend` extends `QuantumBackend`; `_attest()` adds `he_params`, `epoch`, `rotation_log`. `enable_locked_compute()` registers tier 3 backend AND `hashsig.register()`.

**Test**: `tests/redteam_3_upper_tiers.py` lines 478-485 (locked_compute tier names the generation; attestation includes epoch, he_params, rotation_log).

**Honest limit**: LWE is additive only — not fully homomorphic. No ciphertext×ciphertext, no encrypted comparisons. Parameters (n=512, q=2^48) have no independent review. Small test params (n<256) marked `insecure`.

---

### 7. Hash-based stateful signature (Winternitz w=16 under Merkle, SHA-256 only)

**Capability**: A many-time signature scheme whose security rests on SHA-256 only. Winternitz one-time keys (w=16) under a Merkle tree. Stateful: each of 2^height one-time keys used ONCE; index written to disk BEFORE signature returned; refuses to go backwards; refuses when keys exhausted. State file must never be copied or restored.

**Why policy/prompt cannot**: A prompt says "sign this" but cannot enforce the state machine: that each key is used once, that the index is persisted before the signature exists, that a restored backup cannot reuse a key. These are code-enforced invariants, not claims.

**Enforced in**: `seal/hashsig.py` — `Signer` class with `_lock`, `_save()` (atomic write via tmp+fsync), `sign()` increments `_next` and saves BEFORE returning signature. `verify()` checks Merkle path to root. `HashSigBackend` plugs into `signature.register()`.

**Test**: `tests/redteam_3_upper_tiers.py` lines 180-264 (sign/verify/tamper; one-time keys used once then run out; index saved before signature and never goes back; damaged state file blocks signing; threads never share an index; checksum digits stop forger from only moving chains forward).

**Honest limit**: Stateful — state file and seed must stay on one machine, never copied. Signature size ~2.2 kB + 32 bytes per tree level. Height 1–10 (max 1024 signatures). Not interoperable with XMSS/RFC 8391. No independent review.

---

### 8. Selective disclosure via salted Merkle tree

**Capability**: Commit to a whole record (fields → salted leaves, padded to power of two, shuffled by secret permutation), later reveal chosen fields with Merkle paths. Root hides values, names, and exact field count (only size bucket). Only SHA-256 used — holds against quantum computer as the hash does.

**Why policy/prompt cannot**: A prompt says "only show the income field" but the model controls what it outputs. It can show a different value, or a different field, or leak hidden fields in its reasoning. The Merkle commitment binds the *actual* committed fields; the verifier checks the path against the root — the model cannot change the commitment after the fact.

**Enforced in**: `seal/disclosure.py` — `commit_record()` builds salted leaves, pads, shuffles by secret permutation, builds Merkle tree. `disclose()` produces proof with paths. `verify_disclosure()` recomputes root from revealed fields + paths; returns shown fields or `None` on any failure.

**Test**: `tests/redteam_3_upper_tiers.py` lines 267-299 (show some fields only those; root hides values/names/exact count; tampering and forgery fail; bad input refused).

**Honest limit**: Proves the revealed fields are the ones committed to; does NOT prove the committed numbers are true (that is the issuer's signature on the root). Does NOT prove things about hidden fields (use zk.py for that). Max 1024 fields.

---

### 9. Additively homomorphic LWE with key rotation (epochs, switch keys, noise budget)

**Capability**: Encrypt integers; anyone holding only ciphertexts can add, subtract, scale by plaintext, compute dot products (linear scores). Key rotation: holder produces a switch key that moves ciphertexts to new epoch without decrypting; old secret wiped. Every ciphertext carries a worst-case noise bound; operations that would exceed the decryption limit are refused.

**Why policy/prompt cannot**: A prompt says "compute on encrypted data" but the model sees plaintext if it does the computation. The evaluator must be able to operate on ciphertexts without the key — this requires code that enforces the algebraic structure, noise accounting, and epoch separation. A model cannot be trusted to not decrypt, not mix epochs, or not ignore noise limits.

**Enforced in**: `seal/lwe.py` — `Params`, `KeyHolder` (only object that can encrypt/decrypt), `Ciphertext` (carries params_id, epoch, noise), `SwitchKey` (public material for rotation), `add`, `sub`, `scale`, `total`, `dot`, `switch`. `_guard()` checks noise budget. `KeyHolder.rotate()` wipes old secret. `LweBackend` plugs into `fhe.register_backend()`.

**Test**: `tests/redteam_3_upper_tiers.py` lines 304-415 (add/sub/scale/dot on locked numbers; evaluator needs no key; updating encryption moves ciphertexts without decrypting; epochs and parameter sets never mix; noise budget refuses instead of answering wrong; ciphertexts survive JSON round-trip; default params marked secure, small ones insecure; backend plugs into FHE interface).

**Honest limit**: Additive only — NOT fully homomorphic. No ciphertext×ciphertext, no encrypted comparisons, no neural-net activations. Default params (n=512, q=2^48) in range people use for lattice schemes but these exact choices, this code, and its key-switching have had NO independent cryptographic review. Not constant-time. Treat as working research model.

---

### 10. Shamir secret splitting (2-of-3 roles: TPM, card, human) with checked reconstruction

**Capability**: Split a secret across roles using Shamir over GF(256) (any k of n rebuild, fewer than k reveal nothing). `split_roles()` gives one share per role (default 2-of-3). `combine_checked()` verifies reconstruction against a hash of the secret — detects too few shares, wrong share, or corrupt share.

**Why policy/prompt cannot**: A prompt says "split the key" but cannot enforce that the shares are mathematically correct, that reconstruction actually recovers the original secret, or that a corrupted share is detected. The model can output shares that look right but don't reconstruct, or claim reconstruction succeeded when it didn't.

**Enforced in**: `seal/keysplit.py` — GF(256) with AES polynomial 0x11b. `split()` builds random polynomial. `combine()` uses Lagrange interpolation. `split_checked()` adds SHA-256 check tag. `combine_checked()` verifies tag. `split_roles()` maps to ("tpm","card","human").

**Test**: `tests/redteam_2_keys_backends_rotation.py` lines 19-58 (too few/wrong/malformed shares never silently accepted; checked combine detects too few, wrong share, corrupt share; random secrets and subsets always rebuild; below-threshold subsets do not equal secret).

**Honest limit**: Check hash is SHA-256 of secret — safe for random keys, NOT for guessable secrets (would allow offline guessing). Plain Shamir cannot tell if it has enough shares or if one is corrupt — must use `combine_checked()`.

---

### 11. Key re-wrap (envelope encryption) gated by single-use human commitment

**Capability**: Wrap/unwrap a data encryption key under a key-encryption key. Rotation requires a fresh, minted, single-use human commitment for exactly "rotate_keys"; old key id retired on chain; cannot be used again.

**Why policy/prompt cannot**: A prompt says "rotate the key" but cannot enforce that a human actually approved *this specific rotation*, that the commitment is single-use, that the old key is retired, or that the re-wrap actually happened. The model can claim rotation happened while keeping the old key.

**Enforced in**: `seal/scrambler.py` — `wrap()`/`unwrap()` (AES-GCM envelope). `require_commitment()` checks: action="rotate_keys", unexpired, minted in ledger, never used for rotation before (checks DAG for ROTATION entry with same commitment leaf). `commit_rotation()` retires old key id. `rotate()` sequences: require_commitment → unwrap → wrap → commit_rotation.

**Test**: `tests/test_seal.py` lines 99-116 (rotation with unminted commitment refused; fresh commitment re-wraps same data key; old key no longer opens new wrap; rotation recorded, old key retired; same commitment cannot rotate twice; commitment for another action refused).

**Honest limit**: This is KEY RE-WRAP (envelope encryption), not updatable encryption over the ciphertext itself, not homomorphic. Honest label in module docstring.

---

### 12. Forward-secrecy key ratchet + reseal linking old and new top roots

**Capability**: `KeyRatchet` derives epoch keys via HMAC-SHA256; `advance()` moves forward only (old key released, not scrubbed — Python cannot truly wipe). `reseal()` opens old seal with old keys, seals same capsule under new keys (optionally new preset), writes SEAL_ROTATED record linking old top root to new. Old seal stays valid as history.

**Why policy/prompt cannot**: A prompt says "rotate keys and keep history" but cannot enforce that the old keys are actually dropped, that the new seal contains the same capsule, that the rotation is recorded, or that the old seal remains verifiable. These are code-enforced invariants with cryptographic linking.

**Enforced in**: `seal/rotation.py` — `KeyRatchet.current()` returns (key1, key2) for epoch; `advance()` derives next epoch keys via HMAC, increments epoch. `reseal()` calls `superproof.open_seal()` with old keys, then `superproof.seal()` with new keys, records SEAL_ROTATED with old/new top roots and key ids.

**Test**: `tests/redteam_3_upper_tiers.py` lines 493-529 (ratchet only moves forward, keys differ by epoch and layer; reseal moves record to new keys and links old root; old keys no longer open new seal; both old and new seals verify; SEAL_ROTATED records old and new top roots).

**Honest limit**: Python cannot truly wipe memory — old key is released, not scrubbed. For a hard guarantee, keep the ratchet in a hardware module.

---

### 13. Configuration cards (presets) whose hash is recorded in every audit commitment

**Capability**: Presets are data-only cards (tier, layers, signature algorithm, note). Their hash is recorded in the SEAL_AUDIT entry of every seal, so anyone can later tell exactly which configuration produced a given proof.

**Why policy/prompt cannot**: A prompt says "use high assurance mode" but the model can claim one preset while using another. The preset hash in the audit commitment is a cryptographic binding of the *actual* configuration used — not a claim.

**Enforced in**: `seal/presets.py` — `PRESETS` dict, `preset_card()`, `preset_hash()` (canonical JSON SHA-256). `superproof.seal()` computes `ph = presets.preset_hash(card)` and includes it in the statement, proof, top root, and audit commitment.

**Test**: `tests/test_seal.py` lines 134-137 (preset hash stable and distinct).

**Honest limit**: The preset name is a string; if the caller passes a custom string not in `PRESETS`, `preset_card()` raises `KeyError`. No mechanism prevents a caller from constructing a custom card dict directly — but its hash would differ from the named presets.

---

### 14. Fail-closed on unavailable tiers, unavailable signatures, weak keys — nothing written when refused

**Capability**: Any refusal (unknown tier, unregistered prover, unavailable signature algorithm, weak/identical keys, malformed preset) raises BEFORE any DAG or ledger write. The seal pipeline validates everything up front.

**Why policy/prompt cannot**: A prompt says "don't proceed if something's wrong" but the model controls the execution flow. It can skip checks, proceed partially, or write orphan records. The fail-closed property is enforced by code structure: validation happens first, and only on success does the pipeline enter the DAG-writing phase.

**Enforced in**: `seal/superproof.py` `seal()` — lines 47-57: `validate_keys()`, `presets.preset_card()`, tier check (`if tier not in _TIERS: raise TierUnavailable`), `require_prover()` for tier>0, signature algorithm check (`signature.supported()`). Only after all checks pass does the pipeline call `dag.record_stage()`.

**Test**: `tests/test_seal.py` lines 79-84 (tier 1 without prover refuses; tier 2 without prover refuses; refused seal wrote nothing; pq signature without signer refuses). `tests/redteam_1_seal_verification.py` lines 105-112 (weak or equal keys refused before anything recorded).

**Honest limit**: The fail-closed property holds for the published code paths. A caller who bypasses `superproof.seal()` and calls lower-level modules directly could write partial records — but the documented API is `seal()`.

---

## Family predictive loop — this repo's part

Per ORGANISM_MAP.md, the family predictive loop is:

```
records → lessons → knowledge graph → lattice foresight → human decision
```

**This repo's centerpiece: sealed evidence that survives the loop.**

- **Records**: Every seal writes an append-only DAG trace (capsule → layer1 → layer2 → lineage-root → proof-tierN) and a ledger commitment (signed top root). The SEAL_AUDIT entry records the proof tier and preset hash. SEAL_ROTATED entries link key rotations. This is the *ground truth* that feeds upward.
- **Lessons**: `vega-librarian-sdk` consumes these audit entries to distill lessons — e.g., "tier 2 seals with hashsig were used for these capsules at these epochs."
- **Knowledge graph**: `vega-dkg-lattice-sdk` builds the graph with origin and licence per fact. Superproof's audit entries become nodes: "this capsule was sealed at tier 2 with quantum-proof primitives on 2026-10-19."
- **Lattice foresight**: `vega-reasoning-sdk` and `vega-galaxy-sdk` forecast from the lattice — e.g., "if we rotate keys at epoch 5, the next seal will be at tier 2 with these parameters."
- **Human decision**: The human sees the full chain (feed/galaxy), verifies the seals independently (`verify_seal()`), and decides the next commitment.

**What makes this repo's evidence special**:
- The tier is *enforced*, not claimed — a tier 2 seal literally cannot be produced without `builtin.enable_quantum_proof()` and a registered hashsig signer.
- The preset hash in the audit commitment makes the configuration *auditable* — no configuration drift.
- The dual lineage binds *content* to *keys* — a record cannot be re-attributed.
- The top root is the *single value* signed and minted — minimal trust surface.
- Reseal links old and new — key rotation does not break the chain of custody.

**Honest limit**: The loop only works if every layer actually uses the layer below it. If a higher layer ignores superproof's audit entries and invents its own "proof tier" field, the chain breaks. The registry and umbrella audit exist to catch this, but they are only as good as their adoption.
