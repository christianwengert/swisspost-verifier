from __future__ import annotations

import json
import unittest
from pathlib import Path

from swisspost_independent_verifier.crypto import GqGroup, b64_to_int
from swisspost_independent_verifier.mixnet import (
    CommitmentKey,
    derive_hadamard_argument_challenges,
    derive_multi_exponentiation_challenge,
    derive_shuffle_challenges,
    derive_single_value_product_challenge,
    derive_zero_argument_challenge,
    get_verifiable_commitment_key,
    recursive_hash_to_zq,
    star_map,
    verify_hadamard_argument,
    verify_multi_exponentiation_argument,
    verify_product_argument,
    verify_shuffle_argument,
    verify_single_value_product_argument,
    verify_zero_argument,
)

ROOT = Path(__file__).resolve().parents[2]
MIXNET_DATA = ROOT / "crypto-primitives/src/test/resources/mixnet"


def group_from_context(context: dict[str, str]) -> GqGroup:
    return GqGroup(b64_to_int(context["p"]), b64_to_int(context["q"]), b64_to_int(context["g"]))


def parse_recursive_hash_value(value):
    if isinstance(value, list):
        return [parse_recursive_hash_value(item) for item in value]
    value_type = value["type"]
    if value_type == "string":
        return value["value"]
    if value_type == "bytes":
        import base64

        return base64.b64decode(value["value"])
    if value_type == "integer":
        return b64_to_int(value["value"])
    raise ValueError(f"unsupported recursive-hash vector type: {value_type}")


class MixnetVectorTests(unittest.TestCase):
    def test_recursive_hash_to_zq_vectors(self):
        cases = json.loads((ROOT / "crypto-primitives/src/test/resources/recursive-hash-to-zq.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                q = b64_to_int(case["input"]["q"])
                values = [parse_recursive_hash_value(value) for value in case["input"]["values"]]
                self.assertEqual(b64_to_int(case["output"]["result"]), recursive_hash_to_zq(q, *values))

    def test_get_verifiable_commitment_key_vectors(self):
        cases = json.loads((MIXNET_DATA / "get-verifiable-commitment-key.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                group = group_from_context(case["context"])
                key = get_verifiable_commitment_key(group, case["input"]["k"])
                self.assertEqual(b64_to_int(case["output"]["h"]), key.h)
                self.assertEqual([b64_to_int(value) for value in case["output"]["g"]], key.g)

    def test_star_map_vectors(self):
        cases = json.loads((MIXNET_DATA / "bilinearMap.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                group = group_from_context(case["context"])
                actual = star_map(
                    group,
                    b64_to_int(case["input"]["y"]),
                    [b64_to_int(value) for value in case["input"]["a"]],
                    [b64_to_int(value) for value in case["input"]["b"]],
                )
                self.assertEqual(b64_to_int(case["output"]["value"]), actual)

    def test_derive_shuffle_challenge_vectors(self):
        cases = json.loads((MIXNET_DATA / "verify-shuffle-argument.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                context = case["context"]
                group = group_from_context(context)
                public_key = [b64_to_int(value) for value in context["pk"]]
                commitment_key = CommitmentKey.from_json(context["ck"])
                statement = case["input"]["statement"]
                argument = case["input"]["argument"]
                challenges = derive_shuffle_challenges(
                    group,
                    public_key,
                    commitment_key,
                    statement["ciphertexts"],
                    statement["shuffled_ciphertexts"],
                    [b64_to_int(value) for value in argument["ca"]],
                    [b64_to_int(value) for value in argument["cb"]],
                )
                self.assertEqual(b64_to_int(case["output"]["x"]), challenges.x)
                self.assertEqual(b64_to_int(case["output"]["y"]), challenges.y)
                self.assertEqual(b64_to_int(case["output"]["z"]), challenges.z)

    def test_verify_multi_exponentiation_argument_vectors(self):
        cases = json.loads((MIXNET_DATA / "verify-multiexp-argument.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                context = case["context"]
                group = group_from_context(context)
                public_key = [b64_to_int(value) for value in context["pk"]]
                commitment_key = CommitmentKey.from_json(context["ck"])
                statement = case["input"]["statement"]
                argument = case["input"]["argument"]
                self.assertEqual(
                    b64_to_int(case["output"]["x"]),
                    derive_multi_exponentiation_challenge(
                        group,
                        public_key,
                        commitment_key,
                        statement["ciphertexts"],
                        statement["ciphertext_product"],
                        [b64_to_int(value) for value in statement["c_a"]],
                        argument,
                    ),
                )
                self.assertIs(
                    verify_multi_exponentiation_argument(group, public_key, commitment_key, statement, argument),
                    case["output"]["result"],
                )

    def test_verify_multi_exponentiation_argument_rejects_mutated_scalar(self):
        case = json.loads((MIXNET_DATA / "verify-multiexp-argument.json").read_text(encoding="utf-8"))[0]
        group = group_from_context(case["context"])
        public_key = [b64_to_int(value) for value in case["context"]["pk"]]
        commitment_key = CommitmentKey.from_json(case["context"]["ck"])
        argument = dict(case["input"]["argument"])
        argument["b"] = "AA=="

        self.assertFalse(
            verify_multi_exponentiation_argument(
                group,
                public_key,
                commitment_key,
                case["input"]["statement"],
                argument,
            )
        )

    def test_verify_zero_argument_vectors(self):
        cases = json.loads((MIXNET_DATA / "verify-zero-argument.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                context = case["context"]
                group = group_from_context(context)
                public_key = [b64_to_int(value) for value in context["pk"]]
                commitment_key = CommitmentKey.from_json(context["ck"])
                statement = case["input"]["statement"]
                argument = case["input"]["argument"]
                self.assertEqual(
                    b64_to_int(case["output"]["x"]),
                    derive_zero_argument_challenge(group, public_key, commitment_key, statement, argument),
                )
                self.assertIs(
                    verify_zero_argument(group, public_key, commitment_key, statement, argument),
                    case["output"]["result"],
                )

    def test_verify_zero_argument_rejects_mutated_exponent(self):
        case = json.loads((MIXNET_DATA / "verify-zero-argument.json").read_text(encoding="utf-8"))[0]
        group = group_from_context(case["context"])
        public_key = [b64_to_int(value) for value in case["context"]["pk"]]
        commitment_key = CommitmentKey.from_json(case["context"]["ck"])
        argument = dict(case["input"]["argument"])
        argument["t"] = "AA=="

        self.assertFalse(verify_zero_argument(group, public_key, commitment_key, case["input"]["statement"], argument))

    def test_verify_single_value_product_argument_vectors(self):
        cases = json.loads((MIXNET_DATA / "verify-single-value-product-argument.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                context = case["context"]
                group = group_from_context(context)
                public_key = [b64_to_int(value) for value in context["pk"]]
                commitment_key = CommitmentKey.from_json(context["ck"])
                statement = case["input"]["statement"]
                argument = case["input"]["argument"]
                self.assertEqual(
                    b64_to_int(case["output"]["x"]),
                    derive_single_value_product_challenge(group, public_key, commitment_key, statement, argument),
                )
                self.assertIs(
                    verify_single_value_product_argument(group, public_key, commitment_key, statement, argument),
                    case["output"]["result"],
                )

    def test_verify_single_value_product_argument_rejects_mutated_exponent(self):
        case = json.loads((MIXNET_DATA / "verify-single-value-product-argument.json").read_text(encoding="utf-8"))[0]
        group = group_from_context(case["context"])
        public_key = [b64_to_int(value) for value in case["context"]["pk"]]
        commitment_key = CommitmentKey.from_json(case["context"]["ck"])
        argument = dict(case["input"]["argument"])
        argument["s_tilde"] = "AA=="

        self.assertFalse(
            verify_single_value_product_argument(group, public_key, commitment_key, case["input"]["statement"], argument)
        )

    def test_verify_hadamard_argument_vectors(self):
        cases = json.loads((MIXNET_DATA / "verify-hadamard-argument.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                context = case["context"]
                group = group_from_context(context)
                public_key = [b64_to_int(value) for value in context["pk"]]
                commitment_key = CommitmentKey.from_json(context["ck"])
                statement = case["input"]["statement"]
                argument = case["input"]["argument"]
                challenges = derive_hadamard_argument_challenges(group, public_key, commitment_key, statement, argument)
                self.assertEqual(b64_to_int(case["output"]["x"]), challenges.x)
                self.assertEqual(b64_to_int(case["output"]["y"]), challenges.y)
                self.assertIs(
                    verify_hadamard_argument(group, public_key, commitment_key, statement, argument),
                    case["output"]["result"],
                )

    def test_verify_hadamard_argument_rejects_mutated_commitment(self):
        case = json.loads((MIXNET_DATA / "verify-hadamard-argument.json").read_text(encoding="utf-8"))[0]
        group = group_from_context(case["context"])
        public_key = [b64_to_int(value) for value in case["context"]["pk"]]
        commitment_key = CommitmentKey.from_json(case["context"]["ck"])
        argument = dict(case["input"]["argument"])
        argument["cUpperB"] = list(argument["cUpperB"])
        argument["cUpperB"][0] = "AQ=="

        self.assertFalse(verify_hadamard_argument(group, public_key, commitment_key, case["input"]["statement"], argument))

    def test_verify_product_argument_vectors(self):
        cases = json.loads((MIXNET_DATA / "verify-product-argument.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                context = case["context"]
                group = group_from_context(context)
                public_key = [b64_to_int(value) for value in context["pk"]]
                commitment_key = CommitmentKey.from_json(context["ck"])
                self.assertIs(
                    verify_product_argument(group, public_key, commitment_key, case["input"]["statement"], case["input"]["argument"]),
                    case["output"],
                )

    def test_verify_product_argument_rejects_mutated_single_value_product(self):
        case = json.loads((MIXNET_DATA / "verify-product-argument.json").read_text(encoding="utf-8"))[0]
        group = group_from_context(case["context"])
        public_key = [b64_to_int(value) for value in case["context"]["pk"]]
        commitment_key = CommitmentKey.from_json(case["context"]["ck"])
        argument = {"single_vpa": dict(case["input"]["argument"]["single_vpa"])}
        argument["single_vpa"]["r_tilde"] = "AA=="

        self.assertFalse(verify_product_argument(group, public_key, commitment_key, case["input"]["statement"], argument))

    def test_verify_shuffle_argument_vectors(self):
        cases = json.loads((MIXNET_DATA / "verify-shuffle-argument.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                context = case["context"]
                group = group_from_context(context)
                public_key = [b64_to_int(value) for value in context["pk"]]
                commitment_key = CommitmentKey.from_json(context["ck"])
                self.assertIs(
                    verify_shuffle_argument(group, public_key, commitment_key, case["input"]["statement"], case["input"]["argument"]),
                    case["output"]["result"],
                )

    def test_verify_shuffle_argument_rejects_mutated_commitment(self):
        case = json.loads((MIXNET_DATA / "verify-shuffle-argument.json").read_text(encoding="utf-8"))[0]
        group = group_from_context(case["context"])
        public_key = [b64_to_int(value) for value in case["context"]["pk"]]
        commitment_key = CommitmentKey.from_json(case["context"]["ck"])
        argument = dict(case["input"]["argument"])
        argument["cb"] = list(argument["cb"])
        argument["cb"][0] = "AQ=="

        self.assertFalse(verify_shuffle_argument(group, public_key, commitment_key, case["input"]["statement"], argument))


if __name__ == "__main__":
    unittest.main()
