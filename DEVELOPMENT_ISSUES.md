# Development Issues Encountered

This file lists the main non-signature-specific issues encountered while
developing and validating the independent verifier. Signature-specific details
are documented separately in `SIGNATURE_IMPLEMENTATION_NOTES.md`.

## Python Environment Was Initially Global

The original workflow relied on whatever Python interpreter and packages were
available globally. This made the test and CLI behavior dependent on the local
machine state.

Resolution:

- Added `pyproject.toml` project metadata.
- Switched the README workflow to `uv`.
- Added `uv.lock`.
- Removed `requirements.txt`.
- Documented that `uv sync` creates a local `.venv`.

## Dependency Discovery Was Implicit

Some dependencies, especially `lxml` and `cryptography`, were used by the code
but were not managed as project dependencies in a reproducible environment.

Resolution:

- Declared `lxml` and `cryptography` as project dependencies.
- Kept test and CLI execution under `uv run`.

## Public E2E Dataset Layout Differs From Small Fixtures

The local unit fixtures and the public E2E dataset use different directory
layouts. The verifier had to support both compact fixture paths and the real
Swiss Post data exchange layout.

Examples:

- Config payloads under `D2/secure-data-manager-setup/context/...`
- Tally payloads under `D3/secure-data-manager-tally/tally/...`
- Ballot-box-specific final tally payloads under nested ballot box directories

Resolution:

- Added dataset loading paths for both fixture-style and E2E-style layouts.
- Added path-dependent consistency checks where file paths carry ids such as
  node ids, ballot box ids, or verification card set ids.

## Optional Final Tally Payloads

Some smaller fixtures do not contain final tally shuffle/vote payloads, while
the public E2E dataset does.

Resolution:

- Treated absent final tally payloads as explicitly reported "not present" checks
  rather than crashes.
- Kept full final tally checks enabled when those payloads are available.

## XML Schema and eCH Handling

The verifier needed XML schema validation and semantic eCH content checks in
addition to JSON payload validation.

Issues encountered:

- Invalid XML fixtures needed to report schema failures cleanly.
- eCH-0222 can contain additional raw invalid-ballot selections that should not
  be treated as decoded valid selections.
- eCH paths differ from simple file names in the public E2E dataset.

Resolution:

- Added XML schema validation handling.
- Added eCH-0222 content checks against final tally votes.
- Documented/report tolerated raw invalid-ballot selections separately.

## Dataset Consistency Required More Than Schema Validation

JSON schema validation alone was not enough to catch cross-file mistakes.

Important consistency checks added or validated:

- Encryption group consistency.
- Election event id consistency.
- Control component node id consistency.
- File-name node id consistency.
- Ballot box id consistency.
- Verification card set id consistency.
- Verification card id consistency.
- Confirmed encrypted vote consistency.
- Ciphertext and plaintext chain consistency.
- Final tally id and plaintext processing consistency.

## Cryptographic Proof Checks Were Slow

The full proof and vector tests are intentionally expensive. Full `unittest`
discovery took about 25 minutes on the local machine.

Resolution:

- Used focused test commands while iterating.
- Ran the full suite after major changes.
- Verified long-running E2E config and tally commands before considering the
  verifier done.

## Public Swiss Post Java Build Was Not Directly Runnable

Attempting to build the local Swiss Post Java domain module with Maven failed
because a Swiss Post Maven plugin artifact was not available from Maven Central:

```text
ch.post.it.evoting.hashgenerator:hash-generator-maven-plugin:1.0.0.0-b2
```

Impact:

- Could not easily run the official Java payload deserialization/hash path
  directly for comparison.
- Had to inspect Java source code and compare behavior manually.

## Test Fixtures Needed Negative Cases

Several verifier behaviors needed explicit tests for malformed or inconsistent
fixtures, not only happy-path fixtures.

Examples:

- Missing setup/context/tally files.
- Malformed JSON payloads.
- Invalid XML.
- Duplicate or mismatched node ids.
- Mismatched verification card ids.
- Tampered cryptographic proofs.
- Public keys outside the expected group.

Resolution:

- Added targeted unit tests around failure reporting.
- Kept verifier behavior report-oriented rather than crash-oriented where
  possible.

## Long-Running Verification Needed Clear Reporting

The E2E commands do not stream progress while computing. This made it important
to rely on final reports with precise check ids.

Resolution:

- Preserved detailed check names and ids in verifier reports.
- Used exact command outputs to distinguish authenticated signature failures
  from dataset consistency or proof failures.

## Verification Status At Completion

Final verified commands:

```text
uv run swisspost-independent-verifier config --trust-store ../testdata/direct-trust ../testdata/election-events/Post_E2E_DEV
VerifyConfigPhase: OK
```

```text
uv run swisspost-independent-verifier tally --trust-store ../testdata/direct-trust ../testdata/election-events/Post_E2E_DEV
VerifyTally: OK
```

```text
uv run python -m unittest discover -s tests -v
Ran 97 tests
OK
```
