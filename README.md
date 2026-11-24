# AlgoVoi Reseal — Open Verifier (`av-reseal-verify`)


[![PyPI](https://img.shields.io/pypi/v/algovoi-reseal-verify)](https://pypi.org/project/algovoi-reseal-verify/)

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

## The AlgoVoi Reseal product family

This open verifier is the free entry point. The commercial tiers add producing,
auditing at scale, and the full records estate — and everything they produce is
offline-verifiable by this same Apache-2.0 tool, so you never have to trust the
sealer:

| Product | What it adds | Tier | Docs |
|---|---|---|---|
| **`algovoi-reseal`** | Produce the seals: verify a classical RSA/ECDSA signature today, then bind it under Falcon-1024 + ML-DSA-65 with an RFC-3161 timestamp. | from $39/yr | [reseal](https://docs.algovoi.co.uk/reseal) |
| **Evidence Auditor** (`algovoi-evidence-audit`) | Point it at a whole archive → verify every signature (classical + post-quantum), flag the weak/expired/quantum-exposed, and produce a signed, tamper-evident audit report. | from $299/yr | [evidence-auditor](https://docs.algovoi.co.uk/evidence-auditor) |
| **Verifiable Compliance Suite** | The full self-hosted records estate: write-once vault, retention & legal holds, console, SIEM, HSM/KMS key custody, and at-scale re-anchoring. | enterprise | [verifiable-compliance-suite](https://docs.algovoi.co.uk/verifiable-compliance-suite) |

The licensed packages are distributed from AlgoVoi's own gated index (not PyPI);
this free verifier stays public so anyone can independently check their output.

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
