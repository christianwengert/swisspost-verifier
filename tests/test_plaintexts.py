from __future__ import annotations

import json
import unittest
from pathlib import Path

from swisspost_independent_verifier.crypto import GqGroup
from swisspost_independent_verifier.electoral_model import get_blank_correctness_information
from swisspost_independent_verifier.plaintexts import process_plaintexts
from swisspost_independent_verifier.write_ins import write_in_to_quadratic_residue

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "e-voting/secure-data-manager/secure-data-manager-backend/src/test/resources/MixOfflineFacadeTest"


def load_contexts() -> tuple[GqGroup, list[dict]]:
    payload = json.loads((FIXTURE / "electionEventContextPayload.json").read_text(encoding="utf-8"))
    return GqGroup.from_json(payload["encryptionGroup"]), payload["electionEventContext"]["verificationCardSetContexts"]


def select_by_correctness(primes_mapping_table: dict, prefer_semantic_prefix: str | None = None) -> list[dict]:
    selected = []
    used: set[int] = set()
    for correctness in get_blank_correctness_information(primes_mapping_table):
        entries = [
            (index, entry)
            for index, entry in enumerate(primes_mapping_table["pTable"])
            if entry["correctnessInformation"] == correctness and index not in used
        ]
        preferred = next(
            (
                (index, entry)
                for index, entry in entries
                if prefer_semantic_prefix and entry["semanticInformation"].startswith(prefer_semantic_prefix)
            ),
            entries[0],
        )
        used.add(preferred[0])
        selected.append(preferred[1])
    return selected


class ProcessPlaintextsTests(unittest.TestCase):
    def test_process_plaintexts_decodes_real_fixture_blank_vote_and_strips_dummy_row(self):
        group, contexts = load_contexts()
        context = next(ctx for ctx in contexts if ctx["verificationCardSetId"] == "0D87651B9F81BB2837118CE64AE6594B")
        selected = select_by_correctness(context["primesMappingTable"])
        plaintext_product = 1
        for entry in selected:
            plaintext_product *= entry["encodedVotingOption"]

        output = process_plaintexts(group, context["primesMappingTable"], [[plaintext_product], [1]])

        self.assertEqual([[entry["encodedVotingOption"] for entry in selected]], output.votes)
        self.assertEqual([[entry["actualVotingOption"] for entry in selected]], output.decoded_votes)
        self.assertEqual([[]], output.write_ins)

    def test_process_plaintexts_decodes_selected_write_in(self):
        group, contexts = load_contexts()
        context = next(ctx for ctx in contexts if ctx["verificationCardSetId"] == "AB8F062CB698FA56AD8CC75FEDDF7360")
        selected = select_by_correctness(context["primesMappingTable"], "WRITE_IN")
        plaintext_product = selected[0]["encodedVotingOption"]
        encoded_write_in = write_in_to_quadratic_residue(group, "Alice")

        output = process_plaintexts(group, context["primesMappingTable"], [[plaintext_product, encoded_write_in], [1, 1]])

        self.assertEqual([[plaintext_product]], output.votes)
        self.assertEqual([[selected[0]["actualVotingOption"]]], output.decoded_votes)
        self.assertEqual([["Alice"]], output.write_ins)

    def test_process_plaintexts_rejects_invalid_correctness_combination(self):
        group, contexts = load_contexts()
        context = next(ctx for ctx in contexts if ctx["verificationCardSetId"] == "AB8F062CB698FA56AD8CC75FEDDF7360")
        non_matching = context["primesMappingTable"]["pTable"][0]["encodedVotingOption"] * context["primesMappingTable"]["pTable"][1]["encodedVotingOption"]

        with self.assertRaises(ValueError):
            process_plaintexts(group, context["primesMappingTable"], [[non_matching, 1], [1, 1]])


if __name__ == "__main__":
    unittest.main()
