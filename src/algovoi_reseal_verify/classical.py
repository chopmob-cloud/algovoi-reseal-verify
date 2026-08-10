# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi.
"""algovoi_reseal.classical — capture and verify today's classical signature evidence.

Supports the two dominant carriers of long-lived signed documents:
  - PDF embedded signatures (PAdES / PKCS#7): /ByteRange + /Contents CMS blobs.
  - Detached CMS (.p7s) over any file.

Honesty contract: ``checks`` lists exactly what WAS verified and ``not_checked``
what was not (revocation, trust path to a root store, embedded timestamp
tokens). The attestation records evidence, it does not launder a broken PKI
into "valid". Full path validation stays out of v1 on purpose: the certs are
captured as bytes so any future verifier can re-run a stricter policy.

Every classical algorithm seen here (RSA, ECDSA) is quantum-vulnerable; the
``quantum_vulnerable`` flag is what the reseal exists to answer.
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone

from asn1crypto import cms as _cms
from cryptography.hazmat.primitives import hashes as _hashes, serialization as _serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec, padding as _padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import load_der_x509_certificate

_HASHES = {
    "sha1": _hashes.SHA1, "sha256": _hashes.SHA256,
    "sha384": _hashes.SHA384, "sha512": _hashes.SHA512,
}
_DIGESTS = {
    "sha1": hashlib.sha1, "sha256": hashlib.sha256,
    "sha384": hashlib.sha384, "sha512": hashlib.sha512,
}

# /ByteRange [ a b c d ] possibly split across whitespace/newlines. Digit runs
# are bounded (a PDF offset never needs >15 digits): an unbounded \d+ lets a
# hostile PDF carry a multi-million-digit run that trips Python's
# int_max_str_digits and raises out of the parser (DoS crash).
_BYTERANGE_RE = re.compile(rb"/ByteRange\s*\[\s*(\d{1,15})\s+(\d{1,15})\s+(\d{1,15})\s+(\d{1,15})\s*\]")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def inspect_bytes(file_bytes: bytes, filename: str,
                  trust_roots_der: list[bytes] | None = None,
                  crl_bytes: bytes | None = None) -> dict:
    """Return the ``classical`` block of an attestation payload."""
    name = filename.lower()
    if file_bytes[:5] == b"%PDF-":
        sigs = _pdf_signatures(file_bytes)
        if sigs:
            for s in sigs:
                _augment_trust(s, trust_roots_der, crl_bytes)
            return {"present": True, "carrier": "pdf_embedded", "signatures": sigs}
        return {"present": False, "carrier": "pdf", "note": "no embedded signature found"}
    if name.endswith((".p7s", ".p7m")):
        s = _verify_cms(file_bytes, covered=None)
        _augment_trust(s, trust_roots_der, crl_bytes)
        return {"present": True, "carrier": "cms_file", "signatures": [s]}
    return {"present": False, "carrier": "raw",
            "note": "no recognised signature carrier; attestation proves existence and integrity only"}


def inspect_detached(file_bytes: bytes, sig_bytes: bytes,
                     trust_roots_der: list[bytes] | None = None,
                     crl_bytes: bytes | None = None) -> dict:
    """Detached .p7s over ``file_bytes``."""
    s = _verify_cms(sig_bytes, covered=file_bytes)
    _augment_trust(s, trust_roots_der, crl_bytes)
    return {"present": True, "carrier": "cms_detached", "signatures": [s]}


def _augment_trust(entry: dict, trust_roots_der: list[bytes] | None,
                   crl_bytes: bytes | None) -> None:
    """Run opt-in chain-to-root and CRL checks, moving them out of not_checked."""
    from . import trust as _trust
    chain_b64 = entry.get("cert_chain_der_b64")
    if not chain_b64:
        return
    import base64 as _b
    chain = [_b.b64decode(c) for c in chain_b64]
    if trust_roots_der:
        tp = _trust.verify_chain(chain, trust_roots_der)
        entry["trust_path"] = {k: v for k, v in tp.items() if k != "not_checked"}
        if "trust_path_to_root" in entry.get("not_checked", []):
            entry["not_checked"].remove("trust_path_to_root")
        entry["checks"].append({"check": "trust_path_to_root", "ok": tp["ok"]})
        if not tp["ok"]:
            entry["verified"] = False
    if crl_bytes and chain:
        # The issuer is chain[1] when present, else a supplied trust root whose
        # subject matches the leaf's issuer (detached CMS often ships only the
        # leaf). Without an issuer cert we cannot verify the CRL, so we leave
        # revocation in not_checked rather than guess.
        issuer_der = _issuer_of(chain[0], chain[1:], trust_roots_der or [])
        if issuer_der is not None:
            rev = _trust.check_revocation(chain[0], issuer_der, crl_bytes)
            entry["revocation"] = rev
            if "revocation" in entry.get("not_checked", []):
                entry["not_checked"].remove("revocation")
            entry["checks"].append({"check": "not_revoked", "ok": rev.get("ok", False)})
            if not rev.get("ok"):
                entry["verified"] = False


def _issuer_of(leaf_der: bytes, chain_rest: list[bytes],
               roots: list[bytes]) -> bytes | None:
    """Return the cert that ACTUALLY signed the leaf (subject-name match plus a
    verified signature). Name match alone is attacker-steerable: the CMS chain
    is attacker-controlled, so a rogue cert can carry the real issuer's subject
    name. Requiring the signature to verify removes that ambiguity. Trust roots
    are preferred over chain-supplied certs."""
    from cryptography import x509
    from . import trust as _trust
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except Exception:  # noqa: BLE001
        return None
    want = leaf.issuer.public_bytes()
    for der in list(roots) + list(chain_rest):
        try:
            cand = x509.load_der_x509_certificate(der)
        except Exception:  # noqa: BLE001
            continue
        if cand.subject.public_bytes() == want and _trust._verify_signed_by(leaf, cand):
            return der
    return None


# ── PDF ──────────────────────────────────────────────────────────────────────

def _pdf_signatures(pdf: bytes) -> list[dict]:
    """Extract and verify every /ByteRange-covered CMS signature in the PDF."""
    out: list[dict] = []
    for m in _BYTERANGE_RE.finditer(pdf):
        a, b, c, d = (int(x) for x in m.groups())
        if a != 0 or b > len(pdf) or c + d > len(pdf) or c <= b:
            out.append({"format": "pdf_byterange", "verified": False,
                        "error": "implausible ByteRange"})
            continue
        covered = pdf[a:a + b] + pdf[c:c + d]
        # /Contents <hex...> sits in the gap [b, c); take the hex run between < >.
        gap = pdf[b:c]
        lt, gt = gap.find(b"<"), gap.rfind(b">")
        if lt < 0 or gt <= lt:
            out.append({"format": "pdf_byterange", "verified": False,
                        "error": "no /Contents hex blob in ByteRange gap"})
            continue
        hexs = re.sub(rb"\s", b"", gap[lt + 1:gt])
        try:
            der = bytes.fromhex(hexs.decode("ascii")).rstrip(b"\x00")
        except ValueError:
            out.append({"format": "pdf_byterange", "verified": False,
                        "error": "malformed /Contents hex"})
            continue
        entry = _verify_cms(der, covered=covered)
        entry["format"] = "pdf_byterange"
        entry["byte_range"] = [a, b, c, d]
        # Shadow-attack surface: a ByteRange that stops short of EOF means the
        # file carries revisions the signature never covered (PDF incremental
        # update). The signature can be genuine for an EARLIER revision while
        # the file renders something else. Never report that as plain
        # "verifies" - the flag must travel into the attestation.
        entry["covers_entire_file"] = (a == 0 and c + d == len(pdf))
        if not entry["covers_entire_file"]:
            entry["coverage_note"] = (
                "signature covers an earlier revision only; "
                f"{len(pdf) - (c + d)} bytes follow the signed range")
        out.append(entry)
    return out


# ── CMS ──────────────────────────────────────────────────────────────────────

def _verify_cms(der: bytes, covered: bytes | None) -> dict:
    """Verify one CMS SignedData blob. ``covered`` is the detached content;
    None means the content is encapsulated in the blob itself."""
    entry: dict = {"verified": False, "checks": [], "not_checked":
                   ["revocation", "trust_path_to_root", "embedded_timestamp_token"]}
    try:
        ci = _cms.ContentInfo.load(der)
        sd = ci["content"]
        signer = sd["signer_infos"][0]
    except Exception as exc:  # noqa: BLE001
        entry["error"] = f"CMS parse failed: {exc}"
        return entry

    if covered is None:
        encap = sd["encap_content_info"]["content"]
        covered = encap.native if encap is not None else None
        if covered is None:
            entry["error"] = ("detached CMS: the signed content is not in the blob; "
                              "supply the original file alongside it")
            return entry
        if isinstance(covered, str):
            covered = covered.encode()

    digest_alg = signer["digest_algorithm"]["algorithm"].native
    if digest_alg not in _DIGESTS:
        entry["error"] = f"unsupported digest {digest_alg}"
        return entry
    entry["digest_algorithm"] = digest_alg
    # SHA-1 collisions are practical (SHAttered, 2017): a "verifying" SHA-1
    # CMS is weak evidence and the attestation must say so.
    entry["weak_digest"] = digest_alg == "sha1"
    content_digest = _DIGESTS[digest_alg](covered).digest()

    signed_attrs = signer["signed_attrs"]
    if signed_attrs is not None and len(signed_attrs) > 0:
        md = None
        for attr in signed_attrs:
            if attr["type"].native == "message_digest":
                md = attr["values"][0].native
            elif attr["type"].native == "signing_time":
                st = attr["values"][0].native
                if isinstance(st, datetime):
                    entry["claimed_signing_time"] = st.astimezone(timezone.utc).isoformat()
        md_ok = md == content_digest
        entry["checks"].append({"check": "message_digest_attr", "ok": md_ok})
        if not md_ok:
            entry["error"] = "content digest does not match signed messageDigest attribute"
            return entry
        # Signature covers the signed attrs as explicit SET OF (0x31), not the
        # implicit [0] (0xA0) they are transmitted as. Single-byte tag swap.
        dump = signed_attrs.dump()
        to_verify = b"\x31" + dump[1:]
    else:
        to_verify = covered

    certs = [c.chosen.dump() for c in sd["certificates"]] if sd["certificates"] else []
    entry["cert_chain_der_b64"] = [_b64(c) for c in certs]

    # Bind the signer cert by issuer AND serial (RFC 5652 sid). Serial alone
    # is forgeable across issuers: an attacker controls every cert in the CMS
    # and can collide serial numbers, so a serial-only match can display the
    # wrong identity for the key that actually verified.
    sid = signer["sid"]
    cert = None
    if sid.name == "issuer_and_serial_number":
        want_serial = sid.chosen["serial_number"].native
        want_issuer = sid.chosen["issuer"].dump()
        for cder in certs:
            c = load_der_x509_certificate(cder)
            try:
                if (c.serial_number == want_serial
                        and c.issuer.public_bytes() == want_issuer):
                    cert = c
                    break
            except Exception:  # noqa: BLE001
                continue
    if cert is None and certs:
        cert = load_der_x509_certificate(certs[0])
        entry["cert_binding_note"] = "sid did not match any embedded cert; using first"
    if cert is None:
        entry["error"] = "no signer certificate in CMS"
        return entry

    entry["signer_subject"] = cert.subject.rfc4514_string()
    entry["signer_cert_sha256"] = hashlib.sha256(
        cert.public_bytes(_serialization.Encoding.DER)).hexdigest()
    now = datetime.now(timezone.utc)
    validity_ok = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    entry["checks"].append({"check": "cert_validity_window", "ok": validity_ok,
                            "not_after": cert.not_valid_after_utc.isoformat()})

    sig = signer["signature"].native
    pub = cert.public_key()
    hash_cls = _HASHES[digest_alg]
    try:
        if isinstance(pub, RSAPublicKey):
            pub.verify(sig, to_verify, _padding.PKCS1v15(), hash_cls())
            entry["signature_algorithm"] = f"rsa-{pub.key_size}"
        elif isinstance(pub, EllipticCurvePublicKey):
            pub.verify(sig, to_verify, _ec.ECDSA(hash_cls()))
            entry["signature_algorithm"] = f"ecdsa-{pub.curve.name}"
        else:
            entry["error"] = f"unsupported key type {type(pub).__name__}"
            return entry
        sig_ok = True
    except Exception:  # noqa: BLE001
        sig_ok = False
    entry["checks"].append({"check": "signature_cryptographic", "ok": sig_ok})
    entry["quantum_vulnerable"] = True  # RSA and ECDSA both fall to Shor
    entry["verified"] = sig_ok and all(
        c["ok"] for c in entry["checks"] if c["check"] != "cert_validity_window")
    return entry
