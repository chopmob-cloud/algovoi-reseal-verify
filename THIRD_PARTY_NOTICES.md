# Third-Party Notices

`algovoi-reseal-verify` depends on the following open-source packages. Each is used
unmodified as an installed dependency (they are not vendored into this package's
source distribution). All are under permissive licenses. Their copyright notices
and licenses are reproduced or referenced below as required.

We are grateful to these projects and their authors.

| Package | Version (floor) | License | Copyright / Author | Source |
|---|---|---|---|---|
| rfc8785 | >=0.1.4 | Apache-2.0 | Trail of Bits | https://github.com/trailofbits/rfc8785.py |
| pqcrypto | >=0.4.0 | Apache-2.0 | Backbone Technologies Ltd. | https://github.com/backbone-hq/pqcrypto |
| cryptography | >=42.0 | Apache-2.0 OR BSD-3-Clause | The Python Cryptographic Authority and individual contributors | https://github.com/pyca/cryptography |
| asn1crypto | >=1.5 | MIT | Will Bond | https://github.com/wbond/asn1crypto |
| cffi | (via cryptography) | MIT-0 | Armin Rigo, Maciej Fijalkowski | https://github.com/python-cffi/cffi |
| pycparser | (via cffi) | BSD-3-Clause | Eli Bendersky | https://github.com/eliben/pycparser |

## Notices required by the licenses

### pqcrypto (Apache-2.0)
Copyright 2025-present Backbone Technologies Ltd.
This product includes software developed by Backbone (https://www.backbone.dev/).
`pqcrypto` provides Python bindings over post-quantum reference implementations
(Falcon-1024 / FN-DSA and ML-DSA-65 / CRYSTALS-Dilithium); the underlying
algorithm implementations retain their own upstream authors' notices as
distributed within that package.

### cryptography (Apache-2.0 OR BSD-3-Clause)
Copyright (c) The Python Cryptographic Authority and individual contributors.
Used under the Apache License, Version 2.0.

### rfc8785 (Apache-2.0)
Copyright (c) Trail of Bits. Used under the Apache License, Version 2.0.

### asn1crypto (MIT)
Copyright (c) Will Bond. Permission is granted under the MIT License.

### cffi (MIT-0) and pycparser (BSD-3-Clause)
Transitive dependencies of `cryptography`. Copyright (c) Armin Rigo and Maciej
Fijalkowski (cffi) and Eli Bendersky (pycparser), used under their respective
licenses.

## Full license texts

The full Apache-2.0, BSD-3-Clause, MIT, and MIT-0 license texts are available at
the source URLs above and in each package's distribution metadata
(`*.dist-info/licenses/`). No listed dependency is copyleft; none imposes
source-disclosure obligations on `algovoi-reseal`.

## Standards implemented (not code dependencies)

`algovoi-reseal` implements the following public standards from their
specifications; they are not incorporated code and impose no license terms:
RFC 8785 (JCS), RFC 3161 (Time-Stamp Protocol), RFC 5652 (CMS), RFC 5280
(X.509 / PKI), FIPS 204 (ML-DSA), and FIPS 206 draft (FN-DSA / Falcon).
