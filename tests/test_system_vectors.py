from __future__ import annotations

import json
import unittest
from pathlib import Path

from swisspost_independent_verifier.context import get_hash_context
from swisspost_independent_verifier.crypto import GqGroup, b64_to_int, get_mixnet_initial_ciphertexts

ROOT = Path(__file__).resolve().parents[2]
MIXNET_INITIAL_CIPHERTEXTS = (
    ROOT
    / "e-voting-libraries/e-voting-libraries-protocol-algorithms/src/test/resources/getMixnetInitialCiphertexts/get-mixnet-initial-ciphertexts.json"
)


class SystemAlgorithmVectorTests(unittest.TestCase):
    def test_get_hash_context_vectors(self):
        cases = json.loads(
            (ROOT / "e-voting/voting-client/test/protocol/preliminaries/agreement-algorithms/get-hash-context.json").read_text(
                encoding="utf-8"
            )
        )
        for case in cases:
            with self.subTest(case=case["description"]):
                context = case["context"]
                group = GqGroup(
                    _decode_prefixed_int(context["p"]),
                    _decode_prefixed_int(context["q"]),
                    _decode_prefixed_int(context["g"]),
                )
                p_table = [
                    {
                        "actualVotingOption": entry["v"],
                        "encodedVotingOption": entry["pTilde"],
                        "semanticInformation": entry["sigma"],
                        "correctnessInformation": entry["tau"],
                    }
                    for entry in context["pTable"]
                ]
                self.assertEqual(
                    case["output"],
                    get_hash_context(
                        group,
                        context["ee"],
                        context["vcs"],
                        p_table,
                        [_decode_prefixed_int(value) for value in context["ELpk"]],
                        [_decode_prefixed_int(value) for value in context["pkCCR"]],
                    ),
                )

    def test_get_mixnet_initial_ciphertexts_vectors(self):
        cases = json.loads(MIXNET_INITIAL_CIPHERTEXTS.read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                group = GqGroup.from_json(case["context"]["encryptionGroup"])
                election_public_key = [b64_to_int(value) for value in case["context"]["electionPublicKey"]]
                delta = case["context"]["numberOfWriteInsPlusOne"]
                encrypted_hash, ciphertexts = get_mixnet_initial_ciphertexts(
                    group,
                    case["input"]["encryptedConfirmedVotes"],
                    election_public_key,
                    delta,
                )
                self.assertEqual(case["output"]["encryptedConfirmedVotesHash"], encrypted_hash)
                self.assertEqual(case["output"]["mixnetInitialCiphertexts"], ciphertexts)


def _decode_prefixed_int(value: str) -> int:
    if value.startswith("0x"):
        return int(value, 16)
    return b64_to_int(value)


if __name__ == "__main__":
    unittest.main()
