# Independent Swiss Post E-Voting Verifier

This is a Python verifier implemented from the public Swiss Post verifier, system, and crypto-primitives specifications.
It intentionally does not import or call the Java/TypeScript implementation.


This software has been made with a lot of AI help, notably codex.

Current scope:

- Fiat-Shamir proof verifiers from the crypto-primitives specification:
  Schnorr, exponentiation, decryption, plaintext equality, and vector decryptions.
- Mixnet primitives from the crypto-primitives specification:
  RecursiveHashToZq, verifiable commitment keys, bilinear star maps, shuffle challenge
  derivation, zero arguments, single-value-product arguments, Hadamard arguments,
  product arguments, multi-exponentiation arguments, and shuffle arguments.
- Cryptographic parameter helpers from the crypto-primitives specification:
  deterministic small-prime testing, `GetEncryptionParameters`, and
  `GetSmallPrimeGroupMembers`.
- Electoral-model helpers from the system specification:
  blank correctness information, write-in counts, selectable option counts, factorization,
  write-in integer/quadratic-residue encoding, and plaintext vote processing.
- Context-hash algorithms from the system specification, including `GetHashContext`.
- Payload conformance checks against the published Swiss Post JSON schemas bundled in
  `e-voting-libraries`.
- Payload authenticity checks from the verifier specification using RSASSA-PSS/SHA-256
  when an auditor trust-store directory is supplied.
- XML payload authenticity checks using XMLDSig exclusive C14N, SHA-256 digests, and
  RSA signatures for the canton configuration XML and eCH-0222 XML when the corresponding
  trust-store certificates are supplied.
- XML conformance checks against the bundled `evoting-config-7-0.xsd` and
  `eCH-0222-3-0.xsd` schemas when those XML files are present.
- eCH-0222 raw-data content checks comparing decoded selections and normalized write-ins
  against the final tally component votes payloads.
- Setup/tally consistency checks from the verifier specification over the published JSON payload shape,
  including setup public-key group membership, primes mapping table internal consistency,
  encryption-parameter regeneration from the public seed,
  XML/path-dependent checks with explicit unavailable-evidence reporting and voter-total
  comparison when configuration XML is supplied,
  spec-shaped context payload paths,
  config-only context datasets independent of tally evidence,
  spec-shaped per-verification-card-set setup tally payloads,
  spec-shaped per-ballot-box/per-node tally payloads,
  online control-component public-key consistency,
  online control-component Schnorr proof consistency, CCR key-generation Schnorr proofs,
  voting-client proofs, online shuffle proofs, online
  decryption proofs, mix/decrypt chain dimensions, final plaintext dimensions, and final
  tally payload checks when tally-component shuffle/votes payloads are present.
- Tests against published crypto/system test vectors and the `MixOfflineFacadeTest` fixture data.

Run from this directory with `uv`:

```bash
cd independent_verifier
uv sync
uv run python -m unittest discover -s tests
uv run swisspost-independent-verifier config ../e-voting/secure-data-manager/secure-data-manager-backend/src/test/resources/MixOfflineFacadeTest
uv run swisspost-independent-verifier tally ../e-voting/secure-data-manager/secure-data-manager-backend/src/test/resources/MixOfflineFacadeTest
uv run swisspost-independent-verifier config ../testdata/election-events/Post_E2E_DEV
uv run swisspost-independent-verifier tally ../testdata/election-events/Post_E2E_DEV
uv run swisspost-independent-verifier config --trust-store ../testdata/direct-trust ../e-voting/secure-data-manager/secure-data-manager-backend/src/test/resources/MixOfflineFacadeTest
```

`uv sync` creates a local `.venv` and installs the verifier in editable form, so the
commands above do not depend on the global Python environment or `PYTHONPATH`.
The optional `--trust-store` directory may contain signer certificates (`.pem`,
`.crt`, `.cer`, `.der`) or direct-trust PKCS#12 keystores (`.p12`) with sibling
`local_direct_trust_pw_*.txt` password files.

The `../testdata/election-events/Post_E2E_DEV` path is the public synthetic end-to-end
test dataset from `https://gitlab.com/swisspost-evoting/e-voting/testdata.git`. The
verifier auto-discovers its setup evidence under `D2/secure-data-manager-setup` and
its tally evidence under `D3/secure-data-manager-tally`.
