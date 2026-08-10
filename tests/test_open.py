# SPDX-License-Identifier: Apache-2.0
"""Standalone tests for the open verifier package — no proprietary sealer needed.

Artifacts are signed INLINE here with raw pqcrypto (signing in a test is not the
proprietary product; it just produces inputs to exercise the open verifier). This
proves algovoi-reseal-verify inspects and verifies on its own.
"""
from __future__ import annotations

import base64
import datetime
import json
import os
import sys

import pytest
import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from pqcrypto.sign import falcon_1024 as F, ml_dsa_65 as M

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from algovoi_reseal_verify import (  # noqa: E402
    build_attestation_payload, verify_artifact, _b64u, _kid, FORMAT,
)
from algovoi_reseal_verify import classical, trust  # noqa: E402
from algovoi_reseal_verify.cli import main as cli_main  # noqa: E402

CONTENT = b"an agreement that must outlive its RSA signature\n"


def _seal_inline(payload: dict) -> dict:
    """Minimal reference sealer, for tests only (mirrors the proprietary one)."""
    fpk, fsk = F.generate_keypair()
    mpk, msk = M.generate_keypair()
    payload = {**payload, "sealed_with": {"algs": ["Falcon-1024", "ML-DSA-65"],
                                          "kids": [_kid(fpk), _kid(mpk)]}}
    msg = rfc8785.dumps(payload)
    env = {"payload": payload, "alg": "Falcon-1024", "kid": _kid(fpk),
           "sig": _b64u(F.sign(fsk, msg)),
           "alg2": "ML-DSA-65", "kid2": _kid(mpk), "sig2": _b64u(M.sign(msk, msg))}
    return {"format": FORMAT,
            "attestation": _b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()),
            "attestation_hash": "sha256:" + hashlib_sha256_jcs(payload),
            "signer": {"falcon_pk": _b64u(fpk), "mldsa_pk": _b64u(mpk)}}


def hashlib_sha256_jcs(payload) -> str:
    import hashlib
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _detached_cms():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Signer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365)).sign(key, hashes.SHA256()))
    return (pkcs7.PKCS7SignatureBuilder().set_data(CONTENT).add_signer(cert, key, hashes.SHA256())
            .sign(serialization.Encoding.DER,
                  [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))


class TestInspectOpen:
    def test_inspect_detached_cms(self):
        block = classical.inspect_detached(CONTENT, _detached_cms())
        sig = block["signatures"][0]
        assert sig["verified"] is True
        assert sig["quantum_vulnerable"] is True

    def test_build_payload_records_classical(self):
        payload = build_attestation_payload(CONTENT, "c.txt",
                                            detached_sig_bytes=_detached_cms())
        assert payload["classical"]["signatures"][0]["verified"] is True


class TestVerifyOpen:
    def test_verifies_valid_artifact(self):
        art = _seal_inline(build_attestation_payload(CONTENT, "c.txt"))
        assert verify_artifact(art, file_bytes=CONTENT)["ok"] is True

    def test_rejects_tamper(self):
        art = _seal_inline(build_attestation_payload(CONTENT, "c.txt"))
        assert verify_artifact(art, file_bytes=CONTENT + b"x")["ok"] is False

    def test_rejects_garbage(self):
        assert verify_artifact({"format": "x"})["ok"] is False

    def test_cli_verify_roundtrip(self, tmp_path):
        art = _seal_inline(build_attestation_payload(CONTENT, "c.txt"))
        p = tmp_path / "c.reseal.json"
        p.write_text(json.dumps(art))
        f = tmp_path / "c.txt"
        f.write_bytes(CONTENT)
        assert cli_main(["verify", str(p), "--file", str(f)]) == 3  # intact, unanchored

    def test_no_seal_command(self):
        # The open CLI must NOT expose sealing.
        with pytest.raises(SystemExit):
            cli_main(["seal", "x"])


class TestTrustOpen:
    def test_chain_and_reject(self):
        rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
        now = datetime.datetime.now(datetime.timezone.utc)
        root = (x509.CertificateBuilder().subject_name(rn).issuer_name(rn)
                .public_key(rk.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(rk, hashes.SHA256()))
        der = root.public_bytes(serialization.Encoding.DER)
        assert trust.verify_chain([der], [der])["ok"] is True
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert trust.verify_chain([der], [])["ok"] is False
