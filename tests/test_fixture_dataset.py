from __future__ import annotations

import json
import unittest
from pathlib import Path

from swisspost_independent_verifier.crypto import int_to_b64
from swisspost_independent_verifier.dataset import FixtureDataset
from swisspost_independent_verifier.electoral_model import get_blank_correctness_information
from swisspost_independent_verifier.result import VerificationReport

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "e-voting/secure-data-manager/secure-data-manager-backend/src/test/resources/MixOfflineFacadeTest"
CONFIG_XML = ROOT / "e-voting/tools/xml-signature/src/test/resources/configuration-anonymized-invalid-signature.xml"


class FixtureDatasetTests(unittest.TestCase):
    def test_valid_mix_offline_fixture_config_phase_checks(self):
        report = FixtureDataset(FIXTURE).verify_config_phase()
        self.assertTrue(report.ok, [check for check in report.checks if not check.ok])

    def test_valid_mix_offline_fixture_tally_consistency_checks(self):
        report = FixtureDataset(FIXTURE).verify_tally()
        self.assertTrue(report.ok, [check for check in report.checks if not check.ok])

    def test_config_phase_reports_missing_setup_file_without_crashing(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "controlComponentBallotBoxPayloads.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            report = FixtureDataset(tmp_path).verify_config_phase()

            self.assertFalse(report.ok)
            self.assertEqual(["1.01"], [check.check_id for check in report.failing()])
            self.assertIn("setupComponentTallyDataPayload.json", report.checks[0].detail)

    def test_config_phase_reports_missing_context_payloads_without_crashing(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            (tmp_path / "setupComponentTallyDataPayload.json").write_bytes((FIXTURE / "setupComponentTallyDataPayload.json").read_bytes())

            report = FixtureDataset(tmp_path).verify_config_phase()

            self.assertFalse(report.ok)
            self.assertEqual(["1.01"], [check.check_id for check in report.failing()])
            self.assertIn("electionEventContextPayload.json", report.checks[0].detail)
            self.assertIn("setupComponentPublicKeysPayload.json", report.checks[0].detail)

    def test_primes_mapping_table_consistency_passes_for_fixture(self):
        dataset = FixtureDataset(FIXTURE)
        report = VerificationReport("unit")
        dataset._check_primes_mapping_table_consistency(report)
        self.assertTrue(report.ok, report.checks)

    def test_primes_mapping_table_consistency_matches_configuration_xml(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.configuration_xml_path = CONFIG_XML

        report = VerificationReport("unit")
        dataset._check_primes_mapping_table_consistency(report)

        self.assertTrue(report.ok, report.failing())
        self.assertEqual("matched configuration XML pTables=4", report.checks[0].detail)

    def test_primes_mapping_table_consistency_fails_inconsistent_reused_actual_option(self):
        dataset = FixtureDataset(FIXTURE)
        contexts = dataset.election_event_context["electionEventContext"]["verificationCardSetContexts"]
        contexts[1]["primesMappingTable"]["pTable"][0]["semanticInformation"] = "tampered"

        report = VerificationReport("unit")
        dataset._check_primes_mapping_table_consistency(report)
        failed = {check.check_id for check in report.failing()}
        self.assertIn("3.13", failed)

    def test_primes_mapping_table_consistency_fails_configuration_xml_mismatch(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.configuration_xml_path = CONFIG_XML
        contexts = dataset.election_event_context["electionEventContext"]["verificationCardSetContexts"]
        contexts[0]["primesMappingTable"]["pTable"][0]["semanticInformation"] = "tampered"

        report = VerificationReport("unit")
        dataset._check_primes_mapping_table_consistency(report)

        failed = {check.check_id for check in report.failing()}
        self.assertIn("3.13", failed)
        self.assertIn("pTable missing XML option", report.failing()[0].detail)

    def test_configuration_xml_schema_validation_reports_invalid_xml(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.configuration_xml_path = CONFIG_XML

        report = VerificationReport("unit")
        dataset._check_config_xml_schema(report)

        self.assertFalse(report.ok)
        self.assertIn("referenceOnPosition", report.failing()[0].detail)

    def test_encryption_parameters_fail_invalid_seed_format(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.election_event_context["seed"] = "invalid"

        report = VerificationReport("unit")
        dataset._check_encryption_parameters(report)
        failed = {check.check_id for check in report.failing()}
        self.assertIn("5.01", failed)

    def test_total_voters_consistency_uses_configuration_xml_when_available(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.configuration_xml_path = CONFIG_XML

        report = VerificationReport("unit")
        dataset._check_total_voters_consistency(report)

        self.assertTrue(report.ok, report.failing())
        self.assertEqual("configuration=43, context=43", report.checks[0].detail)

    def test_total_voters_consistency_detects_configuration_xml_mismatch(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            xml_path = Path(dirname) / "configuration-anonymized.xml"
            xml_text = CONFIG_XML.read_text(encoding="utf-8").replace("<config:voterTotal>43</config:voterTotal>", "<config:voterTotal>44</config:voterTotal>")
            xml_path.write_text(xml_text, encoding="utf-8")
            dataset = FixtureDataset(FIXTURE)
            dataset.configuration_xml_path = xml_path

            report = VerificationReport("unit")
            dataset._check_total_voters_consistency(report)

            failed = {check.check_id for check in report.failing()}
            self.assertIn("3.14", failed)

    def test_canton_config_signature_reports_trust_store_absent_when_xml_present(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.configuration_xml_path = CONFIG_XML

        report = VerificationReport("unit")
        dataset._check_setup_payload_signatures(report)

        check = next(check for check in report.checks if check.check_id == "2.01")
        self.assertTrue(check.ok)
        self.assertEqual("trust store not provided", check.detail)

    def test_xml_and_path_dependent_checks_are_reported_for_fixture_shape(self):
        dataset = FixtureDataset(FIXTURE)
        report = VerificationReport("unit")

        dataset._check_setup_payload_signatures(report)
        dataset._check_setup_file_name_node_ids(report)
        dataset._check_setup_file_name_verification_card_set_ids(report)
        dataset._check_tally_payload_signatures(report)
        dataset._check_tally_file_name_node_ids(report)
        dataset._check_tally_file_name_ballot_box_ids(report)

        checks = {check.check_id: check for check in report.checks}
        for check_id in ("2.01", "3.03", "3.06", "7.05", "8.03", "8.06"):
            self.assertIn(check_id, checks)
            self.assertTrue(checks[check_id].ok)
            self.assertTrue(checks[check_id].detail)

    def test_final_tally_payload_path_must_contain_ballot_box_id_when_path_is_available(self):
        dataset = FixtureDataset(FIXTURE)
        ballot_box_id = dataset.ballot_boxes[0]["ballotBoxId"]
        dataset.final_tally_votes = [("tally/ballotBoxes/wrong/tallyComponentVotesPayload.json", {"ballotBoxId": ballot_box_id})]

        report = VerificationReport("unit")
        dataset._check_tally_file_name_ballot_box_ids(report)
        failed = {check.check_id for check in report.failing()}
        self.assertIn("8.06", failed)

    def test_extra_config_payload_property_fails_schema_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentBallotBoxPayloads.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            context = json.loads((FIXTURE / "electionEventContextPayload.json").read_text(encoding="utf-8"))
            context["unexpected"] = "extra"
            (tmp_path / "electionEventContextPayload.json").write_text(json.dumps(context), encoding="utf-8")

            report = FixtureDataset(tmp_path).verify_config_phase()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("1.02", failed)

    def test_setup_tally_data_loads_from_spec_verification_card_set_path(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "controlComponentBallotBoxPayloads.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            tally_data = json.loads((FIXTURE / "setupComponentTallyDataPayload.json").read_text(encoding="utf-8"))
            vcs_id = tally_data["verificationCardSetId"]
            target = tmp_path / "context" / "verificationCardSets" / vcs_id / "setupComponentTallyDataPayload.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(tally_data), encoding="utf-8")

            dataset = FixtureDataset(tmp_path)
            self.assertEqual(1, len(dataset.setup_tally_data_payloads))
            self.assertIn(vcs_id, dataset.setup_tally_data_payloads[0][0])

    def test_setup_tally_path_verification_card_set_ids_match_context_when_paths_available(self):
        import copy

        dataset = FixtureDataset(FIXTURE)
        payloads = []
        for ctx in dataset._vcs_contexts():
            payload = copy.deepcopy(dataset.setup_tally_data)
            payload["verificationCardSetId"] = ctx["verificationCardSetId"]
            label = f"context/verificationCardSets/{ctx['verificationCardSetId']}/setupComponentTallyDataPayload.json"
            payloads.append((label, payload))
        dataset.setup_tally_data_payloads = payloads

        report = VerificationReport("unit")
        dataset._check_setup_file_name_verification_card_set_ids(report)

        self.assertTrue(report.ok, report.failing())
        self.assertEqual(f"checked={len(dataset._vcs_contexts())}", report.checks[0].detail)

    def test_setup_tally_path_verification_card_set_id_mismatch_fails(self):
        dataset = FixtureDataset(FIXTURE)
        vcs_id = dataset.setup_tally_data["verificationCardSetId"]
        dataset.setup_tally_data_payloads = [
            (f"context/verificationCardSets/{vcs_id}/setupComponentTallyDataPayload.json", {**dataset.setup_tally_data, "verificationCardSetId": "BAD"})
        ]

        report = VerificationReport("unit")
        dataset._check_setup_file_name_verification_card_set_ids(report)

        self.assertIn("3.06", {check.check_id for check in report.failing()})

    def test_context_payloads_load_from_spec_context_paths(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            context_dir = tmp_path / "context"
            context_dir.mkdir()
            for name in ("electionEventContextPayload.json", "setupComponentPublicKeysPayload.json"):
                (context_dir / name).write_bytes((FIXTURE / name).read_bytes())
            for name in (
                "setupComponentTallyDataPayload.json",
                "controlComponentBallotBoxPayloads.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            dataset = FixtureDataset(tmp_path)

            self.assertEqual("context/electionEventContextPayload.json", dataset.election_event_context_label)
            self.assertEqual("context/setupComponentPublicKeysPayload.json", dataset.setup_public_keys_label)

    def test_context_only_dataset_can_be_constructed_without_tally_payloads(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            context_dir = tmp_path / "context"
            context_dir.mkdir()
            for name in ("electionEventContextPayload.json", "setupComponentPublicKeysPayload.json"):
                (context_dir / name).write_bytes((FIXTURE / name).read_bytes())
            tally_data = json.loads((FIXTURE / "setupComponentTallyDataPayload.json").read_text(encoding="utf-8"))
            vcs_id = tally_data["verificationCardSetId"]
            target = context_dir / "verificationCardSets" / vcs_id / "setupComponentTallyDataPayload.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(tally_data), encoding="utf-8")

            dataset = FixtureDataset(tmp_path)

            self.assertEqual([], dataset.ballot_boxes)
            self.assertEqual([], dataset.shuffles)

    def test_tally_on_context_only_dataset_fails_completeness_without_crashing(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            context_dir = tmp_path / "context"
            context_dir.mkdir()
            for name in ("electionEventContextPayload.json", "setupComponentPublicKeysPayload.json"):
                (context_dir / name).write_bytes((FIXTURE / name).read_bytes())
            tally_data = json.loads((FIXTURE / "setupComponentTallyDataPayload.json").read_text(encoding="utf-8"))
            vcs_id = tally_data["verificationCardSetId"]
            target = context_dir / "verificationCardSets" / vcs_id / "setupComponentTallyDataPayload.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(tally_data), encoding="utf-8")

            report = FixtureDataset(tmp_path).verify_tally()

            self.assertFalse(report.ok)
            self.assertEqual(["6.01"], [check.check_id for check in report.failing()])

    def test_control_component_public_keys_load_from_spec_context_paths(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentBallotBoxPayloads.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            dataset = FixtureDataset(tmp_path)
            payloads = make_control_component_public_key_payloads(dataset.setup_public_keys)
            context_dir = tmp_path / "context"
            context_dir.mkdir()
            for _, payload in payloads:
                node_id = payload["controlComponentPublicKeys"]["nodeId"]
                (context_dir / f"controlComponentPublicKeysPayload.{node_id}.json").write_text(json.dumps(payload), encoding="utf-8")

            dataset = FixtureDataset(tmp_path)
            report = VerificationReport("unit")
            dataset._check_setup_file_name_node_ids(report)

            self.assertEqual(4, len(dataset.control_component_public_keys))
            self.assertTrue(report.ok, report.failing())

    def test_control_component_public_key_file_name_must_match_node_id(self):
        dataset = FixtureDataset(FIXTURE)
        payload = make_control_component_public_key_payloads(dataset.setup_public_keys)[0][1]
        dataset.control_component_public_keys = [("context/controlComponentPublicKeysPayload.2.json", payload)]

        report = VerificationReport("unit")
        dataset._check_setup_file_name_node_ids(report)

        self.assertIn("3.03", {check.check_id for check in report.failing()})

    def test_verification_card_ids_detect_duplicates_across_setup_tally_payloads(self):
        import copy

        dataset = FixtureDataset(FIXTURE)
        second_context = next(ctx for ctx in dataset._vcs_contexts() if ctx["numberOfEligibleVoters"] == 1)
        second_payload = copy.deepcopy(dataset.setup_tally_data)
        second_payload["verificationCardSetId"] = second_context["verificationCardSetId"]
        second_payload["verificationCardIds"] = [dataset.setup_tally_data["verificationCardIds"][0]]
        second_payload["verificationCardPublicKeys"] = [dataset.setup_tally_data["verificationCardPublicKeys"][0]]
        dataset.setup_tally_data_payloads.append(("second/setupComponentTallyDataPayload.json", second_payload))

        report = VerificationReport("unit")
        dataset._check_verification_card_ids(report)

        failed = {check.check_id for check in report.failing()}
        self.assertIn("3.07", failed)

    def test_malformed_tally_payload_fails_schema_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            ballot_boxes = json.loads((FIXTURE / "controlComponentBallotBoxPayloads.json").read_text(encoding="utf-8"))
            ballot_boxes[0]["unexpected"] = "extra"
            (tmp_path / "controlComponentBallotBoxPayloads.json").write_text(json.dumps(ballot_boxes), encoding="utf-8")

            report = FixtureDataset(tmp_path).verify_tally()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("6.02", failed)

    def test_tally_payloads_load_from_spec_ballot_box_paths(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            ballot_boxes = json.loads((FIXTURE / "controlComponentBallotBoxPayloads.json").read_text(encoding="utf-8"))
            shuffles = json.loads((FIXTURE / "controlComponentShufflePayloads.json").read_text(encoding="utf-8"))
            ballot_box_id = ballot_boxes[0]["ballotBoxId"]
            target_dir = tmp_path / "tally" / "ballotBoxes" / ballot_box_id
            target_dir.mkdir(parents=True)
            for payload in ballot_boxes:
                (target_dir / f"controlComponentBallotBoxPayload_{payload['nodeId']}.json").write_text(json.dumps(payload), encoding="utf-8")
            for payload in shuffles:
                (target_dir / f"controlComponentShufflePayload_{payload['nodeId']}.json").write_text(json.dumps(payload), encoding="utf-8")

            dataset = FixtureDataset(tmp_path)
            self.assertEqual(4, len(dataset.ballot_boxes))
            self.assertEqual(4, len(dataset.shuffles))

            report = VerificationReport("Tally")
            dataset._check_tally_completeness(report)
            dataset._check_tally_node_ids(report)
            dataset._check_tally_file_name_node_ids(report)
            dataset._check_tally_file_name_ballot_box_ids(report)

            self.assertTrue(report.ok, report.failing())
            details = {check.check_id: check.detail for check in report.checks}
            self.assertEqual("checked=8", details["8.03"])
            self.assertEqual("checked=8", details["8.06"])

    def test_tally_file_name_node_id_check_detects_mismatched_spec_file_name(self):
        dataset = FixtureDataset(FIXTURE)
        payload = dataset.ballot_boxes[0]
        ballot_box_id = payload["ballotBoxId"]
        dataset.ballot_boxes = [payload]
        dataset.ballot_box_payloads = [(f"tally/ballotBoxes/{ballot_box_id}/controlComponentBallotBoxPayload_2.json", payload)]
        dataset.shuffles = []
        dataset.shuffle_payloads = []

        report = VerificationReport("Tally")
        dataset._check_tally_file_name_node_ids(report)

        failed = {check.check_id for check in report.failing()}
        self.assertIn("8.03", failed)

    def test_absent_final_tally_payloads_are_reported_as_not_present(self):
        dataset = FixtureDataset(FIXTURE)
        report = VerificationReport("FinalTally")

        dataset._check_final_tally_payload_schemas(report)
        dataset._check_final_tally_ids(report)
        dataset._check_final_mixdec_offline(report)
        dataset._check_final_process_plaintexts(report)
        dataset._check_ech0222_content(report)

        self.assertTrue(report.ok, report.failing())
        self.assertTrue(all("no " in check.detail for check in report.checks))

    def test_ech0222_xml_schema_validation_reports_invalid_xml(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            xml_path = Path(dirname) / "eCH-0222.xml"
            xml_path.write_text("<not-ech/>", encoding="utf-8")
            dataset = FixtureDataset(FIXTURE)
            dataset.ech0222_xml_path = xml_path

            report = VerificationReport("Tally")
            dataset._check_ech0222_xml_schema(report)

            self.assertFalse(report.ok)
            self.assertIn("No matching global declaration", report.failing()[0].detail)

    def test_control_component_public_key_payloads_match_setup_keys(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.control_component_public_keys = make_control_component_public_key_payloads(dataset.setup_public_keys)
        report = VerificationReport("Config")

        dataset._check_control_component_public_key_consistency(report)
        dataset._check_control_component_schnorr_proof_consistency(report)

        self.assertTrue(report.ok, report.failing())

    def test_setup_node_ids_accept_online_control_component_public_key_nodes(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.control_component_public_keys = make_control_component_public_key_payloads(dataset.setup_public_keys)
        report = VerificationReport("Config")

        dataset._check_setup_node_ids(report)

        self.assertTrue(report.ok, report.failing())
        self.assertIn("online_node_ids", report.checks[0].detail)

    def test_setup_node_ids_detect_duplicate_online_control_component_public_key_nodes(self):
        dataset = FixtureDataset(FIXTURE)
        payloads = make_control_component_public_key_payloads(dataset.setup_public_keys)
        payloads[1][1]["controlComponentPublicKeys"]["nodeId"] = payloads[0][1]["controlComponentPublicKeys"]["nodeId"]
        dataset.control_component_public_keys = payloads
        report = VerificationReport("Config")

        dataset._check_setup_node_ids(report)

        self.assertFalse(report.ok)
        self.assertIn("3.02", {check.check_id for check in report.failing()})

    def test_mismatched_control_component_public_key_payload_fails_consistency_check(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.control_component_public_keys = make_control_component_public_key_payloads(dataset.setup_public_keys)
        dataset.control_component_public_keys[0][1]["controlComponentPublicKeys"]["ccrjChoiceReturnCodesEncryptionPublicKey"][0] = "AQ=="
        report = VerificationReport("Config")

        dataset._check_control_component_public_key_consistency(report)

        self.assertFalse(report.ok)
        self.assertIn("3.08", {check.check_id for check in report.failing()})

    def test_mismatched_control_component_schnorr_proof_payload_fails_consistency_check(self):
        dataset = FixtureDataset(FIXTURE)
        dataset.control_component_public_keys = make_control_component_public_key_payloads(dataset.setup_public_keys)
        dataset.control_component_public_keys[0][1]["controlComponentPublicKeys"]["ccrjSchnorrProofs"][0]["_e"] = "AA=="
        report = VerificationReport("Config")

        dataset._check_control_component_schnorr_proof_consistency(report)

        self.assertFalse(report.ok)
        self.assertIn("3.10", {check.check_id for check in report.failing()})

    def test_final_process_plaintexts_matches_tally_votes_payload(self):
        dataset = FixtureDataset(FIXTURE)
        ballot_box_id = dataset.ballot_boxes[0]["ballotBoxId"]
        context = dataset._vcs_by_ballot_box()[ballot_box_id]
        selected = []
        used: set[int] = set()
        for correctness in get_blank_correctness_information(context["primesMappingTable"]):
            index, entry = next(
                (index, entry)
                for index, entry in enumerate(context["primesMappingTable"]["pTable"])
                if entry["correctnessInformation"] == correctness and index not in used
            )
            used.add(index)
            selected.append(entry)
        plaintext_product = 1
        for entry in selected:
            plaintext_product *= entry["encodedVotingOption"]

        dataset.final_tally_shuffles = [
            (
                "tally/ballotBoxes/test/tallyComponentShufflePayload.json",
                {
                    "ballotBoxId": ballot_box_id,
                    "verifiablePlaintextDecryption": {
                        "decryptedVotes": [
                            {"message": [int_to_b64(plaintext_product)]},
                            {"message": [int_to_b64(1)]},
                        ]
                    },
                },
            )
        ]
        dataset.final_tally_votes = [
            (
                "tally/ballotBoxes/test/tallyComponentVotesPayload.json",
                {
                    "ballotBoxId": ballot_box_id,
                    "decryptedVotes": [[entry["encodedVotingOption"] for entry in selected]],
                    "decodedVotes": [[entry["actualVotingOption"] for entry in selected]],
                    "decodedWriteIns": [[]],
                },
            )
        ]

        report = VerificationReport("FinalTally")
        dataset._check_final_process_plaintexts(report)

        self.assertTrue(report.ok, report.failing())

    def test_final_plaintext_dimensions_detects_wrong_width(self):
        dataset = FixtureDataset(FIXTURE)
        ballot_box_id = dataset.ballot_boxes[0]["ballotBoxId"]
        dataset.final_tally_shuffles = [
            (
                "tally/ballotBoxes/test/tallyComponentShufflePayload.json",
                {
                    "ballotBoxId": ballot_box_id,
                    "verifiablePlaintextDecryption": {
                        "decryptedVotes": [
                            {"message": [int_to_b64(1), int_to_b64(1)]},
                        ]
                    },
                },
            )
        ]
        report = VerificationReport("Tally")

        dataset._check_plaintext_dimensions(report)

        self.assertFalse(report.ok)
        self.assertIn("8.10", {check.check_id for check in report.failing()})

    def test_number_confirmed_votes_accepts_matching_final_tally_counts(self):
        dataset = FixtureDataset(FIXTURE)
        ballot_box_id = dataset.ballot_boxes[0]["ballotBoxId"]
        count = len(dataset.ballot_boxes[0]["confirmedEncryptedVotes"])
        dataset.final_tally_shuffles = [
            (
                f"tally/ballotBoxes/{ballot_box_id}/tallyComponentShufflePayload.json",
                {
                    "ballotBoxId": ballot_box_id,
                    "verifiableShuffle": {"shuffledCiphertexts": [{} for _ in range(count)]},
                    "verifiablePlaintextDecryption": {"decryptedVotes": [{} for _ in range(count)]},
                },
            )
        ]
        dataset.final_tally_votes = [
            (
                f"tally/ballotBoxes/{ballot_box_id}/tallyComponentVotesPayload.json",
                {
                    "ballotBoxId": ballot_box_id,
                    "decryptedVotes": [[] for _ in range(count)],
                    "decodedVotes": [[] for _ in range(count)],
                    "decodedWriteIns": [[] for _ in range(count)],
                },
            )
        ]

        report = VerificationReport("Tally")
        dataset._check_number_confirmed_votes(report)

        self.assertTrue(report.ok, report.failing())

    def test_number_confirmed_votes_detects_final_tally_votes_count_mismatch(self):
        dataset = FixtureDataset(FIXTURE)
        ballot_box_id = dataset.ballot_boxes[0]["ballotBoxId"]
        count = len(dataset.ballot_boxes[0]["confirmedEncryptedVotes"])
        dataset.final_tally_votes = [
            (
                f"tally/ballotBoxes/{ballot_box_id}/tallyComponentVotesPayload.json",
                {
                    "ballotBoxId": ballot_box_id,
                    "decryptedVotes": [[] for _ in range(count - 1)],
                    "decodedVotes": [[] for _ in range(count - 1)],
                    "decodedWriteIns": [[] for _ in range(count - 1)],
                },
            )
        ]

        report = VerificationReport("Tally")
        dataset._check_number_confirmed_votes(report)

        self.assertFalse(report.ok)
        self.assertIn("8.11", {check.check_id for check in report.failing()})

    def test_final_process_plaintexts_detects_tampered_decoded_votes(self):
        dataset = FixtureDataset(FIXTURE)
        ballot_box_id = dataset.ballot_boxes[0]["ballotBoxId"]
        context = dataset._vcs_by_ballot_box()[ballot_box_id]
        selected = []
        used: set[int] = set()
        for correctness in get_blank_correctness_information(context["primesMappingTable"]):
            index, entry = next(
                (index, entry)
                for index, entry in enumerate(context["primesMappingTable"]["pTable"])
                if entry["correctnessInformation"] == correctness and index not in used
            )
            used.add(index)
            selected.append(entry)
        plaintext_product = 1
        for entry in selected:
            plaintext_product *= entry["encodedVotingOption"]

        dataset.final_tally_shuffles = [
            (
                "tally/ballotBoxes/test/tallyComponentShufflePayload.json",
                {
                    "ballotBoxId": ballot_box_id,
                    "verifiablePlaintextDecryption": {
                        "decryptedVotes": [
                            {"message": [int_to_b64(plaintext_product)]},
                            {"message": [int_to_b64(1)]},
                        ]
                    },
                },
            )
        ]
        dataset.final_tally_votes = [
            (
                "tally/ballotBoxes/test/tallyComponentVotesPayload.json",
                {
                    "ballotBoxId": ballot_box_id,
                    "decryptedVotes": [[entry["encodedVotingOption"] for entry in selected]],
                    "decodedVotes": [["tampered"]],
                    "decodedWriteIns": [[]],
                },
            )
        ]

        report = VerificationReport("FinalTally")
        dataset._check_final_process_plaintexts(report)

        self.assertFalse(report.ok)
        self.assertIn("11.03", {check.check_id for check in report.failing()})

    def test_ech0222_content_matches_final_tally_votes(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            dataset = FixtureDataset(FIXTURE)
            answer = dataset._vcs_contexts()[0]["primesMappingTable"]["pTable"][0]["actualVotingOption"]
            candidate = next(
                entry["actualVotingOption"]
                for ctx in dataset._vcs_contexts()
                for entry in ctx["primesMappingTable"]["pTable"]
                if entry["actualVotingOption"].startswith("majorz_test|") and entry["correctnessInformation"].startswith("C|")
            )
            dataset.final_tally_votes = [
                (
                    "tally/ballotBoxes/test/tallyComponentVotesPayload.json",
                    {
                        "ballotBoxId": "test",
                        "decryptedVotes": [[], []],
                        "decodedVotes": [[answer], [candidate]],
                        "decodedWriteIns": [[], [" Alice   Bob "]],
                    },
                )
            ]
            dataset.ech0222_xml_path = Path(dirname) / "eCH-0222.xml"
            dataset.ech0222_xml_path.write_text(make_ech0222_content_xml("Alice Bob"), encoding="utf-8")

            report = VerificationReport("Tally")
            dataset._check_ech0222_content(report)

            self.assertTrue(report.ok, report.failing())

    def test_ech0222_content_detects_decoded_vote_mismatch(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            dataset = FixtureDataset(FIXTURE)
            answer = dataset._vcs_contexts()[0]["primesMappingTable"]["pTable"][0]["actualVotingOption"]
            dataset.final_tally_votes = [
                (
                    "tally/ballotBoxes/test/tallyComponentVotesPayload.json",
                    {
                        "ballotBoxId": "test",
                        "decryptedVotes": [[]],
                        "decodedVotes": [[answer]],
                        "decodedWriteIns": [[]],
                    },
                )
            ]
            dataset.ech0222_xml_path = Path(dirname) / "eCH-0222.xml"
            dataset.ech0222_xml_path.write_text(make_ech0222_content_xml("unused", answer_id="wrong-answer"), encoding="utf-8")

            report = VerificationReport("Tally")
            dataset._check_ech0222_content(report)

            self.assertFalse(report.ok)
            self.assertIn("missing decoded selections", report.failing()[0].detail)

    def test_invalid_node_ids_fixture_fails_tally_node_id_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())
            (tmp_path / "controlComponentBallotBoxPayloads.json").write_bytes(
                (FIXTURE / "controlComponentBallotBoxPayloads_invalidNodeIds.json").read_bytes()
            )
            report = FixtureDataset(tmp_path).verify_tally()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("8.02", failed)

    def test_tampered_ccr_schnorr_proof_fails_config_proof_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentBallotBoxPayloads.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            setup_keys = json.loads((FIXTURE / "setupComponentPublicKeysPayload.json").read_text(encoding="utf-8"))
            setup_keys["setupComponentPublicKeys"]["combinedControlComponentPublicKeys"][0]["ccrjSchnorrProofs"][0]["_e"] = "AA=="
            (tmp_path / "setupComponentPublicKeysPayload.json").write_text(json.dumps(setup_keys), encoding="utf-8")

            report = FixtureDataset(tmp_path).verify_config_phase()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("5.04", failed)

    def test_public_key_outside_group_fails_config_group_membership_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "controlComponentBallotBoxPayloads.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            tally_data = json.loads((FIXTURE / "setupComponentTallyDataPayload.json").read_text(encoding="utf-8"))
            tally_data["verificationCardPublicKeys"][0][0] = "AA=="
            (tmp_path / "setupComponentTallyDataPayload.json").write_text(json.dumps(tally_data), encoding="utf-8")

            report = FixtureDataset(tmp_path).verify_config_phase()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("C.01", failed)

    def test_tampered_small_prime_fails_small_prime_group_member_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentBallotBoxPayloads.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            context = json.loads((FIXTURE / "electionEventContextPayload.json").read_text(encoding="utf-8"))
            context["smallPrimes"][0] = 5
            (tmp_path / "electionEventContextPayload.json").write_text(json.dumps(context), encoding="utf-8")

            report = FixtureDataset(tmp_path).verify_config_phase()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("5.02", failed)

    def test_invalid_voting_client_proofs_fixture_fails_proof_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentShufflePayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())
            (tmp_path / "controlComponentBallotBoxPayloads.json").write_bytes(
                (FIXTURE / "controlComponentBallotBoxPayloads_invalidVotingClientProofs.json").read_bytes()
            )
            report = FixtureDataset(tmp_path).verify_tally()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("10.01", failed)

    def test_tampered_online_decryption_proof_fails_mixdec_decryption_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentBallotBoxPayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            shuffles = json.loads((FIXTURE / "controlComponentShufflePayloads.json").read_text(encoding="utf-8"))
            shuffles[0]["verifiableDecryptions"]["decryptionProofs"][0]["e"] = "AA=="
            (tmp_path / "controlComponentShufflePayloads.json").write_text(json.dumps(shuffles), encoding="utf-8")

            report = FixtureDataset(tmp_path).verify_tally()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("10.02", failed)

    def test_tampered_shuffle_proof_fails_mixdec_shuffle_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentBallotBoxPayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            shuffles = json.loads((FIXTURE / "controlComponentShufflePayloads.json").read_text(encoding="utf-8"))
            shuffles[0]["verifiableShuffle"]["shuffleArgument"]["c_B"][0] = "AQ=="
            (tmp_path / "controlComponentShufflePayloads.json").write_text(json.dumps(shuffles), encoding="utf-8")

            report = FixtureDataset(tmp_path).verify_tally()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("10.04", failed)

    def test_mismatched_mixdec_chain_lengths_fail_chain_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dirname:
            tmp_path = Path(dirname)
            for name in (
                "electionEventContextPayload.json",
                "setupComponentPublicKeysPayload.json",
                "setupComponentTallyDataPayload.json",
                "controlComponentBallotBoxPayloads.json",
            ):
                (tmp_path / name).write_bytes((FIXTURE / name).read_bytes())

            shuffles = json.loads((FIXTURE / "controlComponentShufflePayloads.json").read_text(encoding="utf-8"))
            shuffles[1]["verifiableShuffle"]["shuffledCiphertexts"].pop()
            (tmp_path / "controlComponentShufflePayloads.json").write_text(json.dumps(shuffles), encoding="utf-8")

            report = FixtureDataset(tmp_path).verify_tally()
            failed = {check.check_id for check in report.failing()}
            self.assertIn("10.03", failed)


def make_control_component_public_key_payloads(setup_public_keys: dict) -> list[tuple[str, dict]]:
    payloads = []
    for component in setup_public_keys["setupComponentPublicKeys"]["combinedControlComponentPublicKeys"]:
        node_id = component["nodeId"]
        payloads.append(
            (
                f"controlComponentPublicKeysPayloads.json[{node_id - 1}]",
                {
                    "encryptionGroup": setup_public_keys["encryptionGroup"],
                    "electionEventId": setup_public_keys["electionEventId"],
                    "controlComponentPublicKeys": json.loads(json.dumps(component)),
                    "signature": {"signatureContents": ""},
                },
            )
        )
    return payloads


def make_ech0222_content_xml(write_in: str, answer_id: str = "3aa38c9e-6e93-3159-91e1-c3da90681572") -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<delivery xmlns="http://www.ech.ch/xmlns/eCH-0222/3">
  <rawDataDelivery>
    <rawData>
      <countingCircleRawData>
        <voteRawData>
          <ballotRawData>
            <ballotCasted>
              <questionRawData>
                <questionIdentification>806f52e6-9d49-4906-b2a8-7c89dfdf53e2</questionIdentification>
                <casted>
                  <answerOptionIdentification>{answer_id}</answerOptionIdentification>
                </casted>
              </questionRawData>
            </ballotCasted>
          </ballotRawData>
        </voteRawData>
        <electionGroupBallotRawData>
          <electionRawData>
            <electionIdentification>majorz_test</electionIdentification>
            <ballotPosition>
              <candidate>
                <candidateIdentification>9bfe1f69-6d35-4966-b281-a5dc39655e3a</candidateIdentification>
              </candidate>
            </ballotPosition>
            <ballotPosition>
              <candidate>
                <writeIn>{write_in}</writeIn>
              </candidate>
            </ballotPosition>
          </electionRawData>
        </electionGroupBallotRawData>
      </countingCircleRawData>
    </rawData>
  </rawDataDelivery>
</delivery>
"""


if __name__ == "__main__":
    unittest.main()
