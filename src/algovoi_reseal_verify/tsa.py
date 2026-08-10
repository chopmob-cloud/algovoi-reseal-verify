# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi.
"""algovoi_reseal.tsa — minimal RFC 3161 client + token check.

Self-asserted issuer time proves intent, not the moment; an RFC 3161 token is
an independent authority attesting the attestation hash existed by then. The
TSA sees ONLY the hash (messageImprint), never content.

Honesty contract: ``checks`` records what was verified (status, messageImprint,
nonce, token CMS signature against the TSA cert carried in the token) and
``not_checked`` what was not (TSA trust path to a root store, revocation). The
TSA cert is captured in the artifact so a stricter policy can re-run later.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.request

from asn1crypto import tsp as _tsp

from . import classical as _classical

_ACCEPTED = frozenset({"granted", "granted_with_mods"})
DEFAULT_TSA = "http://timestamp.digicert.com"


def timestamp_digest(digest: bytes, tsa_url: str = DEFAULT_TSA, timeout: int = 20) -> dict:
    """POST a TimeStampReq for ``digest`` (sha256) and return the token block."""
    nonce = int.from_bytes(secrets.token_bytes(8), "big")
    req = _tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": {
            "hash_algorithm": {"algorithm": "sha256"},
            "hashed_message": digest,
        },
        "cert_req": True,
        "nonce": nonce,
    })
    http = urllib.request.Request(
        tsa_url, data=req.dump(),
        headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(http, timeout=timeout) as resp:
        body = resp.read()
    parsed = _tsp.TimeStampResp.load(body)
    status = parsed["status"]["status"].native
    if status not in _ACCEPTED:
        raise ValueError(f"TSA refused: {status}")
    token = parsed["time_stamp_token"]
    info = token["content"]["encap_content_info"]["content"].parsed
    if info["message_imprint"]["hashed_message"].native != digest:
        raise ValueError("TSA token messageImprint does not match our digest")
    if info["nonce"].native != nonce:
        raise ValueError("TSA token nonce mismatch (replay?)")
    return {
        "tsa_url": tsa_url,
        "token_b64": base64.b64encode(token.dump()).decode(),
        "gen_time": info["gen_time"].native.isoformat(),
        "hash_algorithm": "sha256",
    }


def verify_token(block: dict, expected_digest: bytes,
                 tsa_roots_der: list[bytes] | None = None) -> dict:
    """Offline re-check of a stored token against the attestation digest.

    ``ok`` means the token is structurally sound: its messageImprint matches
    our digest and its CMS signature verifies against the TSA cert IT CARRIES.
    That alone does NOT prove an independent authority issued it - the cert is
    inside the token, so an attacker who mints their own TSA cert produces a
    structurally valid token with any genTime they like. Supply ``tsa_roots_der``
    (pinned TSA roots) to anchor the issuer: ``tsa_anchored`` is then True only
    when the TSA cert chains to a trusted root. Callers that need a trustworthy
    time MUST require ``tsa_anchored``."""
    report: dict = {"ok": False, "tsa_anchored": None, "checks": [],
                    "not_checked": ["tsa_revocation"]}
    token = _tsp.ContentInfo.load(base64.b64decode(block["token_b64"]))
    sd = token["content"]
    info_octets = sd["encap_content_info"]["content"]
    info = info_octets.parsed
    imprint_ok = info["message_imprint"]["hashed_message"].native == expected_digest
    report["checks"].append({"check": "message_imprint", "ok": imprint_ok})
    report["gen_time"] = info["gen_time"].native.isoformat()

    # The token is CMS SignedData over DER(TSTInfo); reuse the CMS verifier
    # with the encapsulated octets as the covered content.
    cms_entry = _classical._verify_cms(token.dump(), covered=info_octets.contents)
    sig_ok = bool(cms_entry.get("verified"))
    report["checks"].append({"check": "token_cms_signature", "ok": sig_ok,
                             "signer": cms_entry.get("signer_subject")})

    if tsa_roots_der:
        from . import trust as _trust
        chain = [base64.b64decode(c) for c in cms_entry.get("cert_chain_der_b64", [])]
        tp = _trust.verify_chain(chain, tsa_roots_der) if chain else {"ok": False}
        report["tsa_anchored"] = bool(tp.get("ok"))
        report["checks"].append({"check": "tsa_trust_path", "ok": bool(tp.get("ok"))})
    else:
        report["not_checked"].append("tsa_trust_path_to_root")

    report["ok"] = imprint_ok and sig_ok
    return report
