# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi.
"""algovoi_reseal.trust — offline chain-to-root and CRL revocation validation.

Both are OPT-IN and OFFLINE: the caller supplies trusted root certificates and,
optionally, CRLs. Nothing here reaches the network, so it stays air-gap capable
and cannot be turned into an oracle or an SSRF vector by a hostile document.

Honesty about scope, stated in the results and the README: this performs basic
RFC 5280 path building (issuer/subject linkage, per-link signature, validity
windows, anchor pinned by SHA-256, CA basicConstraints on non-leaf certs). It
does NOT enforce name constraints, policy OIDs, EKU, or path-length beyond the
chain presented. A `checked`/`not_checked` split is returned so the attestation
never overstates what was proven.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
from cryptography.hazmat.primitives.asymmetric import ec as _ec, padding as _padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def _fp(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(_ser.Encoding.DER)).hexdigest()


def _load(der_list: list[bytes]) -> list[x509.Certificate]:
    out = []
    for d in der_list:
        try:
            out.append(x509.load_der_x509_certificate(d))
        except Exception:  # noqa: BLE001 - skip unparseable, never crash
            continue
    return out


def _verify_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Does ``issuer``'s public key verify ``child``'s signature?"""
    pub = issuer.public_key()
    try:
        if isinstance(pub, RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       _padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       _ec.ECDSA(child.signature_hash_algorithm))
        else:
            return False
        return True
    except Exception:  # noqa: BLE001 - InvalidSignature and any parse error fail closed
        return False


def _is_ca(cert: x509.Certificate) -> bool:
    """A usable issuer needs basicConstraints CA:TRUE and, if a keyUsage
    extension is present, the keyCertSign bit. A CA:TRUE cert that lacks
    keyCertSign is not authorised to sign certificates."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca:
            return False
    except x509.ExtensionNotFound:
        return False
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_cert_sign:
            return False
    except x509.ExtensionNotFound:
        pass  # no keyUsage constraint present
    return True


def verify_chain(chain_der: list[bytes], trust_roots_der: list[bytes],
                 at_time: datetime | None = None) -> dict:
    """Build and validate a path from the leaf (chain_der[0]) to a trusted root.

    Returns {ok, checks[], not_checked[], anchor_fp?}. ``ok`` is True only when
    a full path to a pinned trusted root verifies.
    """
    now = at_time or datetime.now(timezone.utc)
    result: dict = {"ok": False, "checks": [],
                    "not_checked": ["name_constraints", "policy_oids",
                                    "extended_key_usage", "path_length"]}
    chain = _load(chain_der)
    roots = _load(trust_roots_der)
    if not chain:
        result["checks"].append({"check": "chain_present", "ok": False})
        return result
    if not roots:
        result["not_checked"].append("trust_path_to_root")
        result["checks"].append({"check": "trust_roots_supplied", "ok": False})
        return result

    root_fps = {_fp(r): r for r in roots}
    root_subjects = {}
    for r in roots:
        root_subjects.setdefault(r.subject.public_bytes(), r)

    # Index chain certs by subject for issuer linkage.
    by_subject: dict[bytes, x509.Certificate] = {}
    for c in chain:
        by_subject.setdefault(c.subject.public_bytes(), c)

    cur = chain[0]
    seen: set[str] = set()
    for _ in range(len(chain) + len(roots) + 1):  # bound: no infinite loop on a cycle
        fp = _fp(cur)
        if fp in seen:
            result["checks"].append({"check": "path_acyclic", "ok": False})
            return result
        seen.add(fp)

        val_ok = cur.not_valid_before_utc <= now <= cur.not_valid_after_utc
        result["checks"].append({"check": "validity_window",
                                 "subject": cur.subject.rfc4514_string(), "ok": val_ok,
                                 "not_after": cur.not_valid_after_utc.isoformat()})
        if not val_ok:
            return result

        issuer_name = cur.issuer.public_bytes()
        # Reached a trusted root directly?
        if fp in root_fps:
            result["ok"] = True
            result["anchor_fp"] = fp
            return result
        # Issuer is a trusted root?
        if issuer_name in root_subjects:
            root = root_subjects[issuer_name]
            if _verify_signed_by(cur, root):
                if cur is not chain[0] and not _is_ca(root):
                    result["checks"].append({"check": "issuer_is_ca", "ok": False})
                    return result
                result["checks"].append({"check": "link_signature",
                                         "issuer": root.subject.rfc4514_string(), "ok": True})
                result["ok"] = True
                result["anchor_fp"] = _fp(root)
                return result
            result["checks"].append({"check": "link_signature",
                                     "issuer": root.subject.rfc4514_string(), "ok": False})
            return result
        # Otherwise follow the issuer within the presented chain.
        issuer = by_subject.get(issuer_name)
        if issuer is None or issuer is cur:
            result["checks"].append({"check": "issuer_found", "ok": False,
                                     "note": "no path to a trusted root"})
            return result
        if not _is_ca(issuer):
            result["checks"].append({"check": "issuer_is_ca",
                                     "subject": issuer.subject.rfc4514_string(), "ok": False})
            return result
        if not _verify_signed_by(cur, issuer):
            result["checks"].append({"check": "link_signature",
                                     "issuer": issuer.subject.rfc4514_string(), "ok": False})
            return result
        result["checks"].append({"check": "link_signature",
                                 "issuer": issuer.subject.rfc4514_string(), "ok": True})
        cur = issuer
    result["checks"].append({"check": "path_bounded", "ok": False})
    return result


def check_revocation(cert_der: bytes, issuer_der: bytes, crl_bytes: bytes) -> dict:
    """Offline CRL check: is ``cert``'s serial revoked, per a CRL we can verify
    was signed by ``issuer``? PEM or DER CRL accepted."""
    result: dict = {"ok": False, "checks": []}
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        issuer = x509.load_der_x509_certificate(issuer_der)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"cert parse: {exc}"
        return result
    try:
        crl = x509.load_der_x509_crl(crl_bytes)
    except Exception:  # noqa: BLE001
        try:
            crl = x509.load_pem_x509_crl(crl_bytes)
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"CRL parse: {exc}"
            return result

    # The CRL must be signed by the cert's issuer, else it proves nothing.
    sig_ok = crl.is_signature_valid(issuer.public_key())
    result["checks"].append({"check": "crl_signed_by_issuer", "ok": bool(sig_ok)})
    if not sig_ok:
        return result
    issuer_match = crl.issuer.public_bytes() == cert.issuer.public_bytes()
    result["checks"].append({"check": "crl_issuer_matches_cert", "ok": issuer_match})
    if not issuer_match:
        return result

    # A stale CRL can miss a recent revocation, so "not revoked" from an
    # expired CRL is weak. Report freshness rather than silently trusting it.
    try:
        nxt = crl.next_update_utc
        if nxt is not None:
            fresh = nxt >= datetime.now(timezone.utc)
            result["crl_next_update"] = nxt.isoformat()
            result["crl_current"] = fresh
            if not fresh:
                result["checks"].append({"check": "crl_current", "ok": False,
                                         "note": "CRL is past its nextUpdate; revocation may be stale"})
    except Exception:  # noqa: BLE001
        pass

    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    result["revoked"] = revoked is not None
    if revoked is not None:
        result["revoked_at"] = revoked.revocation_date_utc.isoformat()
    result["checks"].append({"check": "not_revoked", "ok": revoked is None})
    result["ok"] = revoked is None
    return result
