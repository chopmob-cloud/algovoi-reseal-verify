# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi.
"""algovoi_reseal_verify — inspect classical signatures and verify reseal attestations.

This is the OPEN (Apache-2.0) half of AlgoVoi Reseal: it triages the classical
RSA/ECDSA signatures on a document (`inspect`) and verifies post-quantum reseal
attestations offline (`verify`). It never mints attestations - the proprietary
`algovoi-reseal` package holds the signing/`seal` engine. Verification is open
by design: don't trust the sealer, check the bytes yourself.

Original problem, stated once: a document signed with RSA or ECDSA stays

The problem this solves, stated once: a document signed with RSA or ECDSA stays
provable only while those algorithms stay unforgeable. Records on decade-long
retention clocks (contracts, clinical records, deeds, qualified e-signatures)
outlive that window. Once a quantum adversary can forge the classical signature,
the original can no longer be told apart from a tamper, and no amount of
after-the-fact effort recovers it. The only time the evidence can be rescued is
NOW, while the classical signature still verifies.

A reseal attestation captures, in one JCS-canonical payload:
  - the exact content (sha256 content address),
  - what classical signature evidence was present and precisely which checks it
    passed today (stated honestly, checked vs not_checked),
  - the full signer certificate chain as bytes, so the verification is
    reproducible even after the issuing PKI is gone,
and then binds that payload under Falcon-1024 + ML-DSA-65 signatures with an
RFC 3161 timestamp over the attestation hash. The result verifies offline,
forever, with no AlgoVoi service in the trust path.

Envelope shape matches the estate convention:
``{"payload","alg":"Falcon-1024","kid","sig"[,"alg2","kid2","sig2"]}`` b64url
encoded, ``sha256:`` + SHA-256(JCS(payload)) as the content address.
"""
from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import time

import rfc8785

from . import classical as _classical

FORMAT = "algovoi-reseal/2"
ATTESTATION_TYPE = "reseal_attestation"
CANON_VERSION = "jcs-rfc8785-v1"

try:
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify
except ImportError as exc:  # pragma: no cover
    raise ImportError("algovoi-reseal-verify requires pqcrypto (Falcon-1024)") from exc

# Second-signature verifiers, keyed by the algorithm name the sealed payload
# declares. ML-DSA-65 (NIST L3) and ML-DSA-87 (NIST L5, matches Falcon-1024's
# level) are both accepted; verification dispatches on the AUTHENTICATED
# sealed_with declaration, never on the unauthenticated envelope label.
_MLDSA_VERIFIERS: dict = {}
try:
    from pqcrypto.sign.ml_dsa_65 import verify as _mldsa65_verify
    _MLDSA_VERIFIERS["ML-DSA-65"] = _mldsa65_verify
except ImportError:  # pragma: no cover - older pqcrypto builds
    pass
try:
    from pqcrypto.sign.ml_dsa_87 import verify as _mldsa87_verify
    _MLDSA_VERIFIERS["ML-DSA-87"] = _mldsa87_verify
except ImportError:  # pragma: no cover
    pass
_HAVE_MLDSA = bool(_MLDSA_VERIFIERS)


# ── primitives (estate conventions) ──────────────────────────────────────────

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def sha256_jcs(payload) -> str:
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _prefixed(payload: dict) -> str:
    return "sha256:" + sha256_jcs(payload)


def _kid(public_key: bytes) -> str:
    # FULL 256-bit digest, not truncated. The kid is the sole authenticity
    # anchor (--expect-kid), so a truncated kid would be second-preimage-able:
    # an attacker grinds their own keypair until _kid(their_pk) collides with a
    # pinned kid. At 64 bits that is ~2^64 classical and ~2^32 under Grover -
    # trivially broken by the very quantum adversary this tool exists to resist.
    return "sha256:" + hashlib.sha256(_b64u(public_key).encode()).hexdigest()


# ── attestation build (inspection: no signing) ───────────────────────────────

def build_attestation_payload(file_bytes: bytes, filename: str,
                              prev_entry_hash: str | None = None,
                              sealed_at_ms: int | None = None,
                              detached_sig_bytes: bytes | None = None,
                              trust_roots_der: list[bytes] | None = None,
                              crl_bytes: bytes | None = None) -> dict:
    """Inspect the file's classical signature evidence and build the payload.

    ``detached_sig_bytes`` is a sibling .p7s over the file; when given, the
    file is the subject and the detached CMS is the evidence. Supplying
    ``trust_roots_der`` / ``crl_bytes`` runs offline chain-to-root and CRL
    checks and records them in the sealed payload. ``sealed_at_ms`` is
    self-asserted issuer time; the RFC 3161 token added at seal time is what an
    auditor should trust for WHEN.
    """
    if detached_sig_bytes is not None:
        classical = _classical.inspect_detached(file_bytes, detached_sig_bytes,
                                                trust_roots_der, crl_bytes)
        classical["evidence_sha256"] = hashlib.sha256(detached_sig_bytes).hexdigest()
    else:
        classical = _classical.inspect_bytes(file_bytes, filename,
                                             trust_roots_der, crl_bytes)
    media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return {
        "type": ATTESTATION_TYPE,
        "v": 1,
        "canon": CANON_VERSION,
        "subject": {
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
            "size": len(file_bytes),
            "filename": os.path.basename(filename),
            "media_type": media_type,
        },
        "classical": classical,
        "sealed_at_ms": sealed_at_ms if sealed_at_ms is not None else int(time.time() * 1000),
        "prev_entry_hash": prev_entry_hash,
    }



# ── verification (library form; the free-verifier mirrors this standalone) ───

def verify_artifact(artifact: dict, file_bytes: bytes | None = None,
                    expected_kid: str | None = None,
                    tsa_roots_der: list[bytes] | None = None) -> dict:
    """Verify a reseal artifact. Offline, from the bytes alone.

    TRUST MODEL: the artifact carries its signing public key, so signature
    checks prove it is internally consistent and unaltered, NOT who sealed it.
    Anyone can mint keys and fabricate an internally-perfect artifact. Pass
    ``expected_kid`` (the sealer's published Falcon kid, pinned out-of-band)
    to anchor authenticity; without it ``anchored`` stays False and callers
    must surface "intact but self-asserted", never plain success.
    """
    report: dict = {"ok": False, "anchored": False, "checks": []}
    try:
        if artifact.get("format") != FORMAT:
            report["error"] = "unrecognised format"
            return report
        env = json.loads(_b64u_dec(artifact["attestation"]))
        payload = env["payload"]
        if not isinstance(payload, dict) or not isinstance(payload.get("subject"), dict):
            report["error"] = "malformed attestation payload"
            return report
        msg = rfc8785.dumps(payload)
    except Exception as exc:  # noqa: BLE001 - attacker-supplied artifact must fail clean
        report["error"] = f"malformed artifact: {exc}"
        return report

    try:
        falcon_pk = _b64u_dec(artifact["signer"]["falcon_pk"])
        falcon_ok = bool(_falcon_verify(falcon_pk, msg, _b64u_dec(env["sig"])))
    except Exception:  # noqa: BLE001
        falcon_ok = False
        falcon_pk = b""
    report["checks"].append({"check": "falcon_1024_signature", "ok": falcon_ok})
    if env.get("kid") != _kid(falcon_pk):
        report["checks"].append({"check": "falcon_kid_binding", "ok": False})
        return report
    if expected_kid is not None:
        anchored = _kid(falcon_pk) == expected_kid
        report["anchored"] = anchored
        report["checks"].append({"check": "kid_anchor", "ok": anchored,
                                 "expected": expected_kid})
        if not anchored:
            return report

    # The second signature's ALGORITHM comes from the authenticated sealed_with
    # (declared inside the Falcon-signed payload), never from env["alg2"] which
    # an attacker controls. We dispatch verification on the declared name, so a
    # downgrade to a weaker/absent verifier fails closed.
    _sw = payload.get("sealed_with") or {}
    _declared_algs = _sw.get("algs") if isinstance(_sw, dict) else None
    second_alg = (_declared_algs[1] if isinstance(_declared_algs, list)
                  and len(_declared_algs) > 1 else None)

    mldsa_ok = True
    second_kid = None
    mldsa_present = bool(env.get("sig2") and artifact["signer"].get("mldsa_pk"))
    if mldsa_present:
        verifier = _MLDSA_VERIFIERS.get(second_alg)
        if verifier is None:
            report["checks"].append({"check": "second_signature", "ok": False,
                                     "alg": second_alg,
                                     "note": "declared second algorithm unknown or unavailable "
                                             "in this build; cannot verify sig2"})
            mldsa_ok = False  # cannot verify a declared signature => fail closed
        else:
            mldsa_pk = _b64u_dec(artifact["signer"]["mldsa_pk"])
            second_kid = _kid(mldsa_pk)
            try:
                mldsa_ok = bool(verifier(mldsa_pk, msg, _b64u_dec(env["sig2"])))
            except Exception:  # noqa: BLE001
                mldsa_ok = False
            if env.get("kid2") != second_kid:
                mldsa_ok = False
            report["checks"].append({"check": "second_signature", "alg": second_alg,
                                     "ok": mldsa_ok})

    # Anti-strip binding: every algorithm the SIGNED payload declares must have
    # a present, valid signature under the matching kid. This is what makes the
    # dual signature real - you cannot drop ML-DSA to fall back to Falcon-only.
    sealed_with = payload.get("sealed_with")
    if not isinstance(sealed_with, dict) or not isinstance(sealed_with.get("algs"), list):
        report["checks"].append({"check": "sealed_with_binding", "ok": False,
                                 "note": "missing signing-algorithm binding"})
        return report
    declared = list(zip(sealed_with.get("algs", []), sealed_with.get("kids", [])))
    present_valid = {}
    if falcon_ok:
        present_valid["Falcon-1024"] = _kid(falcon_pk)
    if mldsa_present and mldsa_ok and second_alg is not None:
        present_valid[second_alg] = second_kid
    binding_ok = True
    for alg, kid in declared:
        if present_valid.get(alg) != kid:
            binding_ok = False
    # And no undeclared signature is smuggled in.
    if set(present_valid) != {a for a, _ in declared}:
        binding_ok = False
    report["checks"].append({"check": "sealed_with_binding", "ok": binding_ok,
                             "declared": [a for a, _ in declared]})

    hash_ok = artifact.get("attestation_hash") == _prefixed(payload)
    report["checks"].append({"check": "attestation_content_address", "ok": hash_ok})

    subject_ok = True
    if file_bytes is not None:
        subject_ok = hashlib.sha256(file_bytes).hexdigest() == payload["subject"].get("sha256")
        report["checks"].append({"check": "subject_sha256", "ok": subject_ok})

    ts_ok = True
    if artifact.get("rfc3161"):
        from . import tsa as _tsa
        try:
            ah = artifact.get("attestation_hash")
            if not isinstance(ah, str) or ":" not in ah:
                raise ValueError("attestation_hash missing or malformed")
            digest_hex = ah.split(":", 1)[1]
            ts = _tsa.verify_token(artifact["rfc3161"], bytes.fromhex(digest_hex),
                                   tsa_roots_der=tsa_roots_der)
            # The token's CMS signature must verify (structural integrity). Its
            # ISSUER is only trusted if anchored: without pinned TSA roots the
            # token proves a well-formed timestamp exists, NOT that an
            # independent authority issued it - an attacker can mint a TSA cert.
            ts_ok = ts["ok"]
            if tsa_roots_der and not ts.get("tsa_anchored"):
                ts_ok = False
            report["tsa_anchored"] = ts.get("tsa_anchored")
            report["checks"].append({"check": "rfc3161_token", **ts})
        except Exception as exc:  # noqa: BLE001
            ts_ok = False
            report["checks"].append({"check": "rfc3161_token", "ok": False, "error": str(exc)})

    report["ok"] = (falcon_ok and mldsa_ok and binding_ok and hash_ok
                    and subject_ok and ts_ok)
    report["payload"] = payload
    return report
