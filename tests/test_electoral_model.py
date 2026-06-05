from __future__ import annotations

import unittest
from pathlib import Path

from swisspost_independent_verifier.dataset import FixtureDataset
from swisspost_independent_verifier.electoral_model import (
    factorize,
    get_actual_voting_options,
    get_blank_correctness_information,
    get_correctness_information,
    get_delta,
    get_encoded_voting_options,
    get_psi,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "e-voting/secure-data-manager/secure-data-manager-backend/src/test/resources/MixOfflineFacadeTest"


class ElectoralModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dataset = FixtureDataset(FIXTURE)
        cls.contexts = dataset.election_event_context["electionEventContext"]["verificationCardSetContexts"]

    def test_psi_and_delta_are_derived_from_blank_and_write_in_options(self):
        observed = {
            ctx["verificationCardSetId"]: (get_psi(ctx["primesMappingTable"]), get_delta(ctx["primesMappingTable"]))
            for ctx in self.contexts
        }
        self.assertEqual(
            {
                "0D87651B9F81BB2837118CE64AE6594B": (11, 1),
                "15E7B3076E775D8097598814912F001F": (12, 2),
                "90F6BD2E34545DF54CEF86FF72D9D62F": (11, 1),
                "AB8F062CB698FA56AD8CC75FEDDF7360": (1, 2),
            },
            observed,
        )

    def test_blank_vote_factorizes_to_blank_correctness_information(self):
        for ctx in self.contexts:
            with self.subTest(vcs=ctx["verificationCardSetId"]):
                table = ctx["primesMappingTable"]
                blank_correctness = get_blank_correctness_information(table)
                blank_actuals = [
                    entry["actualVotingOption"]
                    for entry in table["pTable"]
                    if entry["semanticInformation"].startswith("BLANK")
                ]
                blank_encoded = get_encoded_voting_options(table, blank_actuals)
                product = 1
                for encoded in blank_encoded:
                    product *= encoded

                factors = factorize(table, product)
                actuals = get_actual_voting_options(table, factors)
                correctness = get_correctness_information(table, actuals)
                self.assertEqual(blank_encoded, factors)
                self.assertEqual(blank_correctness, correctness)

    def test_factorize_rejects_missing_selection(self):
        table = self.contexts[0]["primesMappingTable"]
        blank_actuals = [
            entry["actualVotingOption"]
            for entry in table["pTable"]
            if entry["semanticInformation"].startswith("BLANK")
        ]
        incomplete = get_encoded_voting_options(table, blank_actuals[:-1])
        product = 1
        for encoded in incomplete:
            product *= encoded
        with self.assertRaises(ValueError):
            factorize(table, product)


if __name__ == "__main__":
    unittest.main()
