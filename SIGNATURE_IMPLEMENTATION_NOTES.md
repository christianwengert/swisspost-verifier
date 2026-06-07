# Signature Implementation Notes

These are the parts of authenticated verification that could not be reliably
derived from the public specifications alone and required checking the Swiss Post
implementation.

## JSON Signature Message Shape

Swiss Post signs:

```text
recursiveHash([payload.toHashableForm(), context])
```

The verifier must pass the payload hashable form itself into the signed message,
not a precomputed/base64-encoded payload digest.

## Exact `toHashableForm()` Structure

Several signed payloads depend on implementation-level nesting details:

- `ElGamalMultiRecipientCiphertext` is flat: `(gamma, phi0, phi1, ...)`, not
  `(gamma, (phi0, phi1, ...))`.
- `PrimesMappingTable` wraps `pTable` as a single list element.
- `ProductArgument` omits absent `c_b` and Hadamard fields entirely, instead of
  hashing empty placeholders.
- `ControlComponentShufflePayload` includes `nodeId` in the signed payload.
- `TallyComponentShufflePayload` includes the encryption group in the signed
  payload.

## Ordering Before Hashing

`ControlComponentBallotBoxPayload` sorts confirmed encrypted votes by
`verificationCardId` before hashing. This ordering is enforced by the Java
constructor, so it is not enough to preserve JSON file order.

## Direct-Trust Store Layout

The E2E direct-trust material is stored recursively as PKCS#12 keystores:

- `local_direct_trust_keystore_*.p12`
- sibling password files named `local_direct_trust_pw_*.txt`

The verifier must load certificates from these `.p12` files and alias them by
the signer id derived from the keystore name and certificate common name.

## XML Signature Canonicalization

Swiss Post delegates XML signature verification to Java XMLDSig. The relevant
manual behavior is:

- `SignedInfo` is canonicalized with exclusive C14N.
- The referenced document digest, after the enveloped-signature transform, uses
  inclusive canonical XML.

Using exclusive C14N for both steps produces digest mismatches on the real
configuration and eCH XML files.

## Verified Outcome

With these details implemented, the authenticated public E2E dataset verifies:

```text
VerifyConfigPhase: OK
VerifyTally: OK
```

The full unit test suite also passes:

```text
Ran 97 tests
OK
```
