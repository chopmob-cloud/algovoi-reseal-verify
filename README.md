# AlgoVoi Reseal — Open Verifier (`av-reseal-verify`)

**An [AlgoVoi](https://algovoi.co.uk) project · Apache-2.0.** This is the free,
open half of AlgoVoi Reseal. It does two things:

- **`inspect`** — triage the classical RSA/ECDSA signatures on a document (PDF
  PAdES/CMS or detached `.p7s`): whether they verify today, who signed, and the
  post-quantum exposure of each. Optional offline trust-path and CRL checks
  (`--trust-roots`, `--crl`).
- **`verify`** — check a post-quantum reseal attestation (`.reseal.json`)
  entirely offline, from the bytes alone, with no AlgoVoi service in the trust
  path. Anchor authenticity with `--expect-kid`; anchor the RFC-3161 time with
  `--tsa-roots`.

Verification is open on purpose: **you should not have to trust the sealer.**
Anyone can run this to independently confirm what a sealed attestation proves.

```
pip install algovoi-reseal-verify
av-reseal-verify inspect contract.pdf
av-reseal-verify verify contract.pdf.reseal.json --file contract.pdf --expect-kid sha256:...
```

## Producing seals

This package does not mint attestations. Sealing (verify the classical signature
today, then bind it under Falcon-1024 + ML-DSA-65 with an RFC-3161 timestamp) is
the commercial **`algovoi-reseal`** package. The two share this exact
verification code, so anything `algovoi-reseal` produces, this open tool checks.

## Trust model (same as the sealer)

An artifact carries its signing public key, so verification proves internal
consistency, not authorship — pin the sealer's published kid with `--expect-kid`
(full 256-bit). The dual signature is bound inside the signed payload, so
ML-DSA-65 cannot be stripped. RFC-3161 time is only trusted when the TSA chains
to a `--tsa-roots` root; otherwise it is labelled UNANCHORED. Exit codes: `0`
verified+anchored, `1` failed, `2` malformed/usage, `3` intact but self-asserted.

## Licensing

This package is Apache-2.0 (see LICENSE / NOTICE). It depends only on permissive
open-source libraries, attributed in THIRD_PARTY_NOTICES.md.
