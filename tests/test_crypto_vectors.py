from __future__ import annotations

import json
import unittest
from pathlib import Path

from swisspost_independent_verifier.crypto import (
    GqGroup,
    b64_to_int,
    get_encryption_parameters,
    get_small_prime_group_members,
    verify_decryption,
    verify_exponentiation,
    verify_plaintext_equality,
    verify_schnorr,
)

ROOT = Path(__file__).resolve().parents[2]


def load(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class CryptoVectorTests(unittest.TestCase):
    def test_get_small_prime_group_members_matches_fixture_election_context(self):
        payload = load("e-voting/secure-data-manager/secure-data-manager-backend/src/test/resources/MixOfflineFacadeTest/electionEventContextPayload.json")
        group = GqGroup.from_json(payload["encryptionGroup"])

        self.assertEqual(payload["smallPrimes"], get_small_prime_group_members(group, len(payload["smallPrimes"])))

    def test_get_encryption_parameters_matches_official_vector(self):
        vector = load("crypto-primitives/src/test/resources/elgamal/get-encryption-parameters.json")[0]
        group = get_encryption_parameters(vector["input"]["seed"])

        self.assertEqual(b64_to_int(vector["output"]["p"]), group.p)
        self.assertEqual(b64_to_int(vector["output"]["q"]), group.q)
        self.assertEqual(b64_to_int(vector["output"]["g"]), group.g)

    def test_verify_schnorr_vectors(self):
        for vector in load("crypto-primitives/src/test/resources/zeroknowledgeproofs/verify-schnorr.json"):
            with self.subTest(vector=vector["description"]):
                group = GqGroup.from_json(vector["context"])
                expected = vector["output"]["result"] == "true"
                self.assertIs(
                    verify_schnorr(
                        group,
                        vector["input"]["proof"],
                        b64_to_int(vector["input"]["statement"]),
                        vector["input"].get("additional_information", []),
                    ),
                    expected,
                )


    def test_verify_exponentiation_vectors(self):
        for vector in load("crypto-primitives/src/test/resources/zeroknowledgeproofs/verify-exponentiation.json"):
            with self.subTest(vector=vector["description"]):
                group = GqGroup.from_json(vector["context"])
                expected = vector["output"]["verif_result"] == "true"
                self.assertIs(
                    verify_exponentiation(
                        group,
                        [b64_to_int(item) for item in vector["input"]["bases"]],
                        [b64_to_int(item) for item in vector["input"]["statement"]],
                        vector["input"]["proof"],
                        vector["input"].get("additional_information", []),
                    ),
                    expected,
                )


    def test_verify_decryption_vectors(self):
        for vector in load("crypto-primitives/src/test/resources/zeroknowledgeproofs/verify-decryption.json"):
            with self.subTest(vector=vector["description"]):
                group = GqGroup.from_json(vector["context"])
                expected = vector["output"]["verif_result"] == "true"
                self.assertIs(
                    verify_decryption(
                        group,
                        vector["input"]["ciphertext"],
                        [b64_to_int(item) for item in vector["input"]["public_key"]],
                        [b64_to_int(item) for item in vector["input"]["message"]],
                        vector["input"]["proof"],
                        vector["input"].get("additional_information", []),
                    ),
                    expected,
                )


    def test_verify_plaintext_equality_vectors(self):
        for vector in load("crypto-primitives/src/test/resources/zeroknowledgeproofs/verify-plaintext-equality.json"):
            with self.subTest(vector=vector["description"]):
                group = GqGroup.from_json(vector["context"])
                expected = vector["output"]["output"] == "true"
                self.assertIs(
                    verify_plaintext_equality(
                        group,
                        vector["input"]["upper_c"],
                        vector["input"]["upper_c_prime"],
                        b64_to_int(vector["input"]["h"]),
                        b64_to_int(vector["input"]["h_prime"]),
                        vector["input"]["proof"],
                        vector["input"].get("i_aux", []),
                    ),
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
