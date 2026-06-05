from __future__ import annotations

import json
import base64
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .crypto import (
    GqGroup,
    b64_to_int,
    combine_public_keys,
    get_encryption_parameters,
    get_mixnet_initial_ciphertexts,
    get_small_prime_group_members,
    group_member,
    verify_decryptions,
    verify_exponentiation,
    verify_plaintext_equality,
    verify_decryption,
    verify_schnorr,
)
from .context import get_hash_context, get_hash_election_event_context
from .electoral_model import get_delta, get_psi
from .mixnet import get_verifiable_commitment_key, verify_shuffle_argument
from .plaintexts import process_plaintexts
from .result import VerificationReport
from .schema import SchemaStore, XmlSchemaStore
from .signatures import (
    TrustStore,
    control_component_public_keys_signed_data,
    control_component_ballot_box_signed_data,
    control_component_shuffle_signed_data,
    election_event_context_signed_data,
    setup_public_keys_signed_data,
    setup_tally_data_signed_data,
    tally_component_shuffle_signed_data,
    tally_component_votes_signed_data,
)


def load_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


CONFIG_NS_URI = "http://www.evoting.ch/xmlns/config/7"
CONFIG_NS = {"config": CONFIG_NS_URI}
CONFIG_LANGUAGES = ("de", "fr", "it", "rm")
ECH0222_NS_URI = "http://www.ech.ch/xmlns/eCH-0222/3"


class FixtureDataset:
    """Verifier-spec checks over the aggregated MixOfflineFacadeTest-style fixture."""

    def __init__(self, root: str | Path, trust_store: TrustStore | None = None):
        self.root = Path(root)
        self.setup_root = self._discover_setup_root(self.root)
        self.tally_root = self._discover_tally_root(self.root)
        self.trust_store = trust_store
        self.missing_setup_files: list[str] = []
        self.election_event_context_label, self.election_event_context = self._load_context_json("electionEventContextPayload.json")
        self.control_component_public_keys = self._load_control_component_public_keys()
        self.setup_public_keys_label, self.setup_public_keys = self._load_context_json("setupComponentPublicKeysPayload.json")
        self.setup_tally_data_payloads = self._load_setup_tally_data()
        self.setup_tally_data = self.setup_tally_data_payloads[0][1] if self.setup_tally_data_payloads else None
        self.ballot_box_payloads = self._load_tally_payloads("controlComponentBallotBoxPayloads.json", "controlComponentBallotBoxPayload_*.json")
        self.shuffle_payloads = self._load_tally_payloads("controlComponentShufflePayloads.json", "controlComponentShufflePayload_*.json")
        self.ballot_boxes = [payload for _, payload in self.ballot_box_payloads]
        self.shuffles = [payload for _, payload in self.shuffle_payloads]
        self.final_tally_shuffles = self._load_optional_payloads("tallyComponentShufflePayload.json")
        self.final_tally_votes = self._load_optional_payloads("tallyComponentVotesPayload.json")
        self.configuration_xml_path = self._find_configuration_xml()
        self.ech0222_xml_path = self._find_ech0222_xml()

    def verify_config_phase(self) -> VerificationReport:
        report = VerificationReport("VerifyConfigPhase")
        self._check_setup_completeness(report)
        if self.missing_setup_files:
            return report
        self._check_config_payload_schemas(report)
        self._check_config_xml_schema(report)
        self._check_setup_payload_signatures(report)
        self._check_group_consistency(report, "3.01")
        self._check_setup_node_ids(report)
        self._check_setup_file_name_node_ids(report)
        self._check_election_event_id_consistency(report, "3.04")
        self._check_verification_card_set_ids(report)
        self._check_setup_file_name_verification_card_set_ids(report)
        self._check_verification_card_ids(report)
        self._check_primes_mapping_table_consistency(report)
        self._check_total_voters_consistency(report)
        self._check_control_component_public_key_consistency(report)
        self._check_control_component_schnorr_proof_consistency(report)
        self._check_setup_public_key_group_membership(report)
        self._check_public_key_consistency(report)
        self._check_encryption_parameters(report)
        self._check_small_prime_group_members(report)
        self._check_voting_options(report)
        self._check_ccr_schnorr_proofs(report)
        return report

    def verify_tally(self) -> VerificationReport:
        report = VerificationReport("VerifyTally")
        self._check_tally_completeness(report)
        if not self.ballot_boxes or not self.shuffles:
            return report
        self._check_tally_payload_schemas(report)
        self._check_final_tally_payload_schemas(report)
        self._check_ech0222_xml_schema(report)
        self._check_tally_payload_signatures(report)
        self._check_group_consistency(report, "8.01")
        self._check_tally_node_ids(report)
        self._check_tally_file_name_node_ids(report)
        self._check_election_event_id_consistency(report, "8.04")
        self._check_ballot_box_ids(report)
        self._check_tally_file_name_ballot_box_ids(report)
        self._check_tally_verification_card_ids(report)
        self._check_confirmed_encrypted_votes_consistency(report)
        self._check_ciphertext_dimensions(report)
        self._check_plaintext_dimensions(report)
        self._check_number_confirmed_votes(report)
        self._check_voting_client_proofs(report)
        self._check_mixdec_chain_consistency(report)
        self._check_mixdec_shuffle_proofs(report)
        self._check_online_decryption_proofs(report)
        self._check_final_tally_ids(report)
        self._check_final_mixdec_offline(report)
        self._check_final_process_plaintexts(report)
        self._check_ech0222_content(report)
        return report

    def _load_optional_payloads(self, filename: str) -> list[tuple[str, Any]]:
        paths = []
        direct = self.tally_root / filename
        if direct.exists():
            paths.append(direct)
        tally_root = self.tally_root / "tally" / "ballotBoxes"
        if tally_root.exists():
            paths.extend(sorted(tally_root.glob(f"*/{filename}")))

        payloads: list[tuple[str, Any]] = []
        for path in paths:
            label = self._label(path)
            value = load_json(path)
            if isinstance(value, list):
                payloads.extend((f"{label}[{index}]", item) for index, item in enumerate(value))
            else:
                payloads.append((label, value))
        return payloads

    def _load_context_json(self, filename: str) -> tuple[str, Any | None]:
        for path in (self.setup_root / filename, self.setup_root / "context" / filename):
            if path.exists():
                return self._label(path), load_json(path)
        self.missing_setup_files.append(filename)
        return filename, None

    def _load_tally_payloads(self, direct_filename: str, spec_glob: str) -> list[tuple[str, Any]]:
        paths: list[Path] = []
        direct = self.tally_root / direct_filename
        if direct.exists():
            paths.append(direct)
        tally_root = self.tally_root / "tally" / "ballotBoxes"
        if tally_root.exists():
            paths.extend(sorted(tally_root.glob(f"*/{spec_glob}")))

        payloads: list[tuple[str, Any]] = []
        for path in paths:
            label = self._label(path)
            value = load_json(path)
            if isinstance(value, list):
                payloads.extend((f"{label}[{index}]", item) for index, item in enumerate(value))
            else:
                payloads.append((label, value))
        return payloads

    def _load_control_component_public_keys(self) -> list[tuple[str, Any]]:
        paths: list[Path] = []
        context_root = self.setup_root / "context"
        if context_root.exists():
            paths.extend(sorted(context_root.glob("controlComponentPublicKeysPayload.*.json")))
        payloads: list[tuple[str, Any]] = []
        for filename in ("controlComponentPublicKeysPayload.json", "controlComponentPublicKeysPayloads.json"):
            path = self.setup_root / filename
            if path.exists():
                paths.append(path)
            context_path = self.setup_root / "context" / filename
            if context_path.exists():
                paths.append(context_path)
        for path in paths:
            label = self._label(path)
            value = load_json(path)
            if isinstance(value, list):
                payloads.extend((f"{label}[{index}]", item) for index, item in enumerate(value))
            else:
                payloads.append((label, value))
        return payloads

    def _load_setup_tally_data(self) -> list[tuple[str, Any]]:
        paths: list[Path] = []
        direct = self.setup_root / "setupComponentTallyDataPayload.json"
        if direct.exists():
            paths.append(direct)
        plural = self.setup_root / "setupComponentTallyDataPayloads.json"
        if plural.exists():
            paths.append(plural)
        context_root = self.setup_root / "context" / "verificationCardSets"
        if context_root.exists():
            paths.extend(sorted(context_root.glob("*/setupComponentTallyDataPayload.json")))

        payloads: list[tuple[str, Any]] = []
        for path in paths:
            label = self._label(path)
            value = load_json(path)
            if isinstance(value, list):
                payloads.extend((f"{label}[{index}]", item) for index, item in enumerate(value))
            else:
                payloads.append((label, value))
        if not payloads:
            self.missing_setup_files.append("setupComponentTallyDataPayload.json")
        return payloads

    def _find_configuration_xml(self) -> Path | None:
        for relative in (
            "context/configuration-anonymized.xml",
            "configuration-anonymized.xml",
            "context/configuration.xml",
            "configuration.xml",
        ):
            path = self.setup_root / relative
            if path.exists():
                return path
        return None

    def _find_ech0222_xml(self) -> Path | None:
        for relative in ("tally/eCH-0222.xml", "eCH-0222.xml"):
            path = self.tally_root / relative
            if path.exists():
                return path
        for pattern in ("tally/eCH-0222*.xml", "eCH-0222*.xml"):
            matches = sorted(self.tally_root.glob(pattern))
            if matches:
                return matches[0]
        return None

    def _discover_setup_root(self, root: Path) -> Path:
        candidate = root / "D2" / "secure-data-manager-setup"
        if (candidate / "context" / "electionEventContextPayload.json").exists():
            return candidate
        return root

    def _discover_tally_root(self, root: Path) -> Path:
        candidate = root / "D3" / "secure-data-manager-tally"
        if (candidate / "tally").exists():
            return candidate
        return root

    def _label(self, path: Path) -> str:
        for base in (self.root, self.setup_root, self.tally_root):
            try:
                return str(path.relative_to(base))
            except ValueError:
                continue
        return str(path)

    def _check_setup_completeness(self, report: VerificationReport) -> None:
        missing = sorted(set(self.missing_setup_files))
        report.add("1.01", "VerifySetupCompleteness", not missing, f"missing={missing}" if missing else "")

    def _check_tally_completeness(self, report: VerificationReport) -> None:
        failures: list[str] = []
        for name, items in (("controlComponentBallotBoxPayloads", self._ballot_box_items()), ("controlComponentShufflePayloads", self._shuffle_items())):
            if not items:
                failures.append(f"missing {name}")
                continue
            by_ballot_box: dict[str, list[int]] = defaultdict(list)
            for label, payload in items:
                try:
                    by_ballot_box[payload["ballotBoxId"]].append(payload["nodeId"])
                except (KeyError, TypeError) as exc:
                    failures.append(f"{label}: malformed {name} ({exc})")
            for ballot_box_id, node_ids in by_ballot_box.items():
                if sorted(node_ids) != [1, 2, 3, 4]:
                    failures.append(f"{ballot_box_id}: {name} node ids {node_ids}")
        detail = f"controlComponentBallotBoxPayloads={len(self.ballot_boxes)}, controlComponentShufflePayloads={len(self.shuffles)}"
        report.add("6.01", "VerifyTallyCompleteness", not failures, detail if not failures else "; ".join(failures[:5]))

    def _check_config_payload_schemas(self, report: VerificationReport) -> None:
        payloads = [
            (self.election_event_context_label, self.election_event_context, "ElectionEventContextPayload.schema.json"),
            (self.setup_public_keys_label, self.setup_public_keys, "SetupComponentPublicKeysPayload.schema.json"),
        ]
        payloads.extend(
            (label, payload, "SetupComponentTallyDataPayload.schema.json")
            for label, payload in self.setup_tally_data_payloads
        )
        payloads.extend(
            (label, payload, "ControlComponentPublicKeysPayload.schema.json")
            for label, payload in self.control_component_public_keys
        )
        failures = self._schema_failures(payloads)
        report.add("1.02", "VerifyConfigPayloadSchemas", not failures, "; ".join(failures[:5]))

    def _check_tally_payload_schemas(self, report: VerificationReport) -> None:
        payloads: list[tuple[str, Any, str]] = []
        payloads.extend((label, payload, "ControlComponentBallotBoxPayload.schema.json") for label, payload in self._ballot_box_items())
        payloads.extend((label, payload, "ControlComponentShufflePayload.schema.json") for label, payload in self._shuffle_items())
        failures = self._schema_failures(payloads)
        report.add("6.02", "VerifyTallyPayloadSchemas", not failures, "; ".join(failures[:5]))

    def _check_final_tally_payload_schemas(self, report: VerificationReport) -> None:
        payloads: list[tuple[str, Any, str]] = []
        payloads.extend(
            (label, payload, "TallyComponentShufflePayload.schema.json")
            for label, payload in self.final_tally_shuffles
        )
        payloads.extend(
            (label, payload, "TallyComponentVotesPayload.schema.json")
            for label, payload in self.final_tally_votes
        )
        if not payloads:
            report.add("6.03", "VerifyFinalTallyPayloadSchemas", True, "no final tally payloads present")
            return
        failures = self._schema_failures(payloads)
        report.add("6.03", "VerifyFinalTallyPayloadSchemas", not failures, "; ".join(failures[:5]))

    def _check_config_xml_schema(self, report: VerificationReport) -> None:
        if self.configuration_xml_path is None:
            report.add("1.03", "VerifyConfigXMLSchema", True, "configuration XML not present")
            return
        failures = self._xml_schema_failures([(self.configuration_xml_path, "evoting-config-7-0.xsd")])
        report.add("1.03", "VerifyConfigXMLSchema", not failures, "; ".join(failures[:5]))

    def _check_ech0222_xml_schema(self, report: VerificationReport) -> None:
        if self.ech0222_xml_path is None:
            report.add("6.04", "VerifyECH0222XMLSchema", True, "eCH-0222 XML not present")
            return
        failures = self._xml_schema_failures([(self.ech0222_xml_path, "eCH-0222-3-0.xsd")])
        report.add("6.04", "VerifyECH0222XMLSchema", not failures, "; ".join(failures[:5]))

    def _check_setup_payload_signatures(self, report: VerificationReport) -> None:
        if self.configuration_xml_path is None:
            report.add("2.01", "VerifySignatureCantonConfig", True, "configuration XML not present")
        elif self.trust_store is None:
            report.add("2.01", "VerifySignatureCantonConfig", True, "trust store not provided")
        else:
            ok, detail = self.trust_store.verify_xml_signature("canton", self.configuration_xml_path, signature_location="root-last-child")
            report.add("2.01", "VerifySignatureCantonConfig", ok, detail)
        if self.trust_store is None:
            report.add("2.02", "VerifySignatureSetupComponentPublicKeys", True, "trust store not provided")
            report.add("2.03", "VerifySignatureControlComponentPublicKeys", True, "trust store not provided")
            report.add("2.04", "VerifySignatureSetupComponentTallyData", True, "trust store not provided")
            report.add("2.05", "VerifySignatureElectionEventContext", True, "trust store not provided")
            return

        group = GqGroup.from_json(self.setup_public_keys["encryptionGroup"])
        checks = []
        ee = self.election_event_context["electionEventContext"]["electionEventId"]
        if not self.control_component_public_keys:
            report.add("2.03", "VerifySignatureControlComponentPublicKeys", True, "no online control component public-key payloads present")
        for label, payload in self.control_component_public_keys:
            node_id = payload["controlComponentPublicKeys"]["nodeId"]
            checks.append(
                (
                    "2.03",
                    f"VerifySignatureControlComponentPublicKeys {label}",
                    f"control_component_{node_id}",
                    control_component_public_keys_signed_data(group, payload),
                    ("OnlineCC keys", node_id, payload["electionEventId"]),
                    payload["signature"],
                )
            )
        checks.append(
            (
                "2.02",
                "VerifySignatureSetupComponentPublicKeys",
                "sdm_config",
                setup_public_keys_signed_data(group, self.setup_public_keys),
                ("public keys", "setup", self.setup_public_keys["electionEventId"]),
                self.setup_public_keys["signature"],
            )
        )
        for label, payload in self.setup_tally_data_payloads:
            checks.append(
                (
                    "2.04",
                    f"VerifySignatureSetupComponentTallyData {label}",
                    "sdm_config",
                    setup_tally_data_signed_data(group, payload),
                    ("tally data", payload["electionEventId"], payload["verificationCardSetId"]),
                    payload["signature"],
                )
            )
        checks.append(
            (
                "2.05",
                "VerifySignatureElectionEventContext",
                "sdm_config",
                election_event_context_signed_data(group, self.election_event_context),
                ("election event context", ee),
                self.election_event_context["signature"],
            )
        )
        self._add_signature_checks(report, checks)

    def _check_tally_payload_signatures(self, report: VerificationReport) -> None:
        if self.trust_store is None:
            report.add("7.01", "VerifySignatureControlComponentBallotBox", True, "trust store not provided")
            report.add("7.02", "VerifySignatureControlComponentShuffle", True, "trust store not provided")
            report.add("7.03", "VerifySignatureTallyComponentShuffle", True, "trust store not provided")
            report.add("7.04", "VerifySignatureTallyComponentVotes", True, "trust store not provided")
            detail = "eCH-0222 XML not present" if self.ech0222_xml_path is None else "trust store not provided"
            report.add("7.05", "VerifySignatureTallyComponentECH0222", True, detail)
            return

        group = GqGroup.from_json(self.setup_public_keys["encryptionGroup"])
        checks = []
        for payload in self.ballot_boxes:
            node_id = payload["nodeId"]
            checks.append(
                (
                    "7.01",
                    f"VerifySignatureControlComponentBallotBox node {node_id}",
                    f"control_component_{node_id}",
                    control_component_ballot_box_signed_data(group, payload),
                    ("ballotbox", node_id, payload["electionEventId"], payload["ballotBoxId"]),
                    payload["signature"],
                )
            )
        for payload in self.shuffles:
            node_id = payload["nodeId"]
            checks.append(
                (
                    "7.02",
                    f"VerifySignatureControlComponentShuffle node {node_id}",
                    f"control_component_{node_id}",
                    control_component_shuffle_signed_data(group, payload),
                    ("shuffle", node_id, payload["electionEventId"], payload["ballotBoxId"]),
                    payload["signature"],
                )
            )
        for label, payload in self.final_tally_shuffles:
            checks.append(
                (
                    "7.03",
                    f"VerifySignatureTallyComponentShuffle {label}",
                    "sdm_tally",
                    tally_component_shuffle_signed_data(payload),
                    ("shuffle", "offline", payload["electionEventId"], payload["ballotBoxId"]),
                    payload["signature"],
                )
            )
        for label, payload in self.final_tally_votes:
            checks.append(
                (
                    "7.04",
                    f"VerifySignatureTallyComponentVotes {label}",
                    "sdm_tally",
                    tally_component_votes_signed_data(group, payload),
                    ("decoded votes", payload["electionEventId"], payload["ballotBoxId"]),
                    payload["signature"],
                )
            )
        if not self.final_tally_shuffles:
            report.add("7.03", "VerifySignatureTallyComponentShuffle", True, "no final tally payloads present")
        if not self.final_tally_votes:
            report.add("7.04", "VerifySignatureTallyComponentVotes", True, "no final tally payloads present")
        if self.ech0222_xml_path is None:
            report.add("7.05", "VerifySignatureTallyComponentECH0222", True, "eCH-0222 XML not present")
        else:
            ok, detail = self.trust_store.verify_xml_signature("sdm_tally", self.ech0222_xml_path, signature_location="extensions-child")
            report.add("7.05", "VerifySignatureTallyComponentECH0222", ok, detail)
        self._add_signature_checks(report, checks)

    def _add_signature_checks(self, report: VerificationReport, checks: list[tuple[str, str, str, str, tuple[Any, ...], dict[str, str]]]) -> None:
        if self.trust_store is None:
            return
        for check_id, name, signer_id, message, context, signature in checks:
            try:
                ok = self.trust_store.verify_signature(signer_id, message, context, signature)
                detail = "" if ok else f"signer={signer_id}"
            except (KeyError, TypeError, ValueError) as exc:
                ok = False
                detail = f"malformed signature input: {exc}"
            report.add(check_id, name, ok, detail)

    def _schema_failures(self, payloads: list[tuple[str, Any, str]]) -> list[str]:
        try:
            schemas = SchemaStore.default()
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            return [f"schema store unavailable: {exc}"]

        failures: list[str] = []
        for label, payload, schema_name in payloads:
            try:
                errors = schemas.validate(schema_name, payload)
            except (KeyError, ValueError) as exc:
                failures.append(f"{label}: schema error {exc}")
                continue
            failures.extend(f"{label}: {error}" for error in errors[:3])
        return failures

    def _xml_schema_failures(self, payloads: list[tuple[Path, str]]) -> list[str]:
        store = XmlSchemaStore.default()
        failures: list[str] = []
        for path, schema_name in payloads:
            label = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
            failures.extend(f"{label}: {error}" for error in store.validate(schema_name, path))
        return failures

    def _check_group_consistency(self, report: VerificationReport, check_id: str) -> None:
        groups = [self.election_event_context["encryptionGroup"], self.setup_public_keys["encryptionGroup"]]
        groups.extend(payload["encryptionGroup"] for _, payload in self.setup_tally_data_payloads)
        groups.extend(payload.get("encryptionGroup") for _, payload in self.control_component_public_keys)
        groups.extend(payload["encryptionGroup"] for payload in self.ballot_boxes)
        groups.extend(payload["encryptionGroup"] for payload in self.shuffles)
        groups.extend(payload.get("encryptionGroup") for _, payload in self.final_tally_shuffles)
        groups.extend(payload.get("encryptionGroup") for _, payload in self.final_tally_votes)
        first = groups[0]
        ok = all(group == first for group in groups)
        report.add(check_id, "VerifyEncryptionGroupConsistency", ok)

    def _check_setup_node_ids(self, report: VerificationReport) -> None:
        keys = self.setup_public_keys["setupComponentPublicKeys"]["combinedControlComponentPublicKeys"]
        setup_ids = [item["nodeId"] for item in keys]
        failures: list[str] = []
        detail = f"setup_node_ids={setup_ids}"
        if self.control_component_public_keys:
            online_ids = []
            for label, payload in self.control_component_public_keys:
                try:
                    online_ids.append(payload["controlComponentPublicKeys"]["nodeId"])
                except (KeyError, TypeError) as exc:
                    failures.append(f"{label}: malformed nodeId ({exc})")
            duplicates = sorted(item for item, count in Counter(online_ids).items() if count > 1)
            missing = sorted(set(range(1, 5)) - set(online_ids))
            extra = sorted(set(online_ids) - set(range(1, 5)))
            if duplicates:
                failures.append(f"duplicate online node ids {duplicates}")
            if missing:
                failures.append(f"missing online node ids {missing}")
            if extra:
                failures.append(f"extra online node ids {extra}")
            detail = f"online_node_ids={online_ids}, setup_node_ids={setup_ids}"
        elif sorted(setup_ids) != [1, 2, 3, 4]:
            failures.append(f"setup node ids {setup_ids}")
        report.add("3.02", "VerifyNodeIdsConsistency", not failures, detail if not failures else "; ".join(failures[:5]))

    def _check_setup_file_name_node_ids(self, report: VerificationReport) -> None:
        if not self.control_component_public_keys:
            report.add("3.03", "VerifyFileNameNodeIdsConsistency", True, "no online control component public-key payload paths present")
            return
        failures: list[str] = []
        for label, payload in self.control_component_public_keys:
            node_id = payload.get("controlComponentPublicKeys", {}).get("nodeId")
            if node_id is None:
                failures.append(f"{label}: missing nodeId")
            elif "/" in label and re.search(r"controlComponentPublicKeysPayload\.\d+\.json$", label):
                if not label.endswith(f".{node_id}.json"):
                    failures.append(f"{label}: does not end with nodeId {node_id}")
            elif str(node_id) not in label:
                failures.append(f"{label}: does not contain nodeId {node_id}")
        report.add("3.03", "VerifyFileNameNodeIdsConsistency", not failures, "; ".join(failures[:5]))

    def _check_tally_node_ids(self, report: VerificationReport) -> None:
        failures: list[str] = []
        detail_parts: list[str] = []
        for name, items in (("ballot_box", self._ballot_box_items()), ("shuffle", self._shuffle_items())):
            by_ballot_box: dict[str, list[int]] = defaultdict(list)
            for _, payload in items:
                by_ballot_box[payload["ballotBoxId"]].append(payload["nodeId"])
            detail_parts.append(f"{name}={dict(by_ballot_box)}")
            for ballot_box_id, node_ids in by_ballot_box.items():
                if sorted(node_ids) != [1, 2, 3, 4]:
                    failures.append(f"{ballot_box_id}: {name} node ids {node_ids}")
        report.add("8.02", "VerifyNodeIdsConsistency", not failures, "; ".join(detail_parts) if not failures else "; ".join(failures[:5]))

    def _check_tally_file_name_node_ids(self, report: VerificationReport) -> None:
        failures: list[str] = []
        checked = 0
        for label, payload in [*self._ballot_box_items(), *self._shuffle_items()]:
            if "/" not in label:
                continue
            checked += 1
            node_id = payload.get("nodeId")
            if node_id is None:
                failures.append(f"{label}: missing nodeId")
            elif not re.search(rf"_{node_id}\.json$", label):
                failures.append(f"{label}: does not end with nodeId {node_id}")
        detail = f"checked={checked}" if checked else "aggregated control-component ballot-box/shuffle payload arrays do not expose per-node file paths"
        report.add("8.03", "VerifyFileNameNodeIdsConsistency", not failures, detail if not failures else "; ".join(failures[:5]))

    def _check_election_event_id_consistency(self, report: VerificationReport, check_id: str) -> None:
        context_id = self.election_event_context["electionEventContext"]["electionEventId"]
        ids = [context_id, self.setup_public_keys["electionEventId"]]
        ids.extend(payload["electionEventId"] for _, payload in self.setup_tally_data_payloads)
        ids.extend(payload.get("electionEventId") for _, payload in self.control_component_public_keys)
        ids.extend(payload["electionEventId"] for payload in self.ballot_boxes)
        ids.extend(payload["electionEventId"] for payload in self.shuffles)
        ids.extend(payload.get("electionEventId") for _, payload in self.final_tally_shuffles)
        ids.extend(payload.get("electionEventId") for _, payload in self.final_tally_votes)
        counts = Counter(ids)
        report.add(check_id, "VerifyElectionEventIdConsistency", len(counts) == 1, f"ids={dict(counts)}")

    def _check_verification_card_set_ids(self, report: VerificationReport) -> None:
        context_vcs = {ctx["verificationCardSetId"] for ctx in self._vcs_contexts()}
        tally_vcs = [payload["verificationCardSetId"] for _, payload in self.setup_tally_data_payloads]
        failures: list[str] = []
        unknown = sorted(set(tally_vcs) - context_vcs)
        if unknown:
            failures.append(f"unknown tally verification card sets {unknown}")
        duplicates = sorted(item for item, count in Counter(tally_vcs).items() if count > 1)
        if duplicates:
            failures.append(f"duplicate tally verification card sets {duplicates}")
        report.add("3.05", "VerifyVerificationCardSetIdsConsistency", not failures, f"context={context_vcs}, tally={set(tally_vcs)}" if not failures else "; ".join(failures[:5]))

    def _check_setup_file_name_verification_card_set_ids(self, report: VerificationReport) -> None:
        expected = {ctx["verificationCardSetId"] for ctx in self._vcs_contexts()}
        observed: set[str] = set()
        failures: list[str] = []
        checked = 0
        for label, payload in self.setup_tally_data_payloads:
            match = re.search(r"(?:^|/)verificationCardSets/([^/]+)/setupComponentTallyDataPayload\.json$", label)
            if not match:
                continue
            checked += 1
            path_vcs = match.group(1)
            observed.add(path_vcs)
            payload_vcs = payload.get("verificationCardSetId")
            if path_vcs != payload_vcs:
                failures.append(f"{label}: path vcs {path_vcs} != payload vcs {payload_vcs}")
            if path_vcs not in expected:
                failures.append(f"{label}: unknown verificationCardSetId {path_vcs}")

        if checked:
            missing = sorted(expected - observed)
            extra = sorted(observed - expected)
            if missing:
                failures.append(f"missing verification-card-set paths {missing}")
            if extra:
                failures.append(f"extra verification-card-set paths {extra}")
            detail = f"checked={checked}" if not failures else "; ".join(failures[:5])
        else:
            detail = "aggregated setup tally payload does not expose verification-card-set directory paths"
        report.add("3.06", "VerifyFileNameVerificationCardSetIdsConsistency", not failures, detail)

    def _check_verification_card_ids(self, report: VerificationReport) -> None:
        vcs_by_id = self._vcs_by_id()
        all_vcids: list[str] = []
        failures: list[str] = []
        counts: dict[str, tuple[int, int]] = {}
        for label, payload in self.setup_tally_data_payloads:
            vcs_id = payload["verificationCardSetId"]
            vcids = payload["verificationCardIds"]
            all_vcids.extend(vcids)
            ctx = vcs_by_id.get(vcs_id)
            if ctx is None:
                failures.append(f"{label}: unknown verificationCardSetId {vcs_id}")
                continue
            expected = ctx["numberOfEligibleVoters"]
            counts[vcs_id] = (len(vcids), expected)
            if len(vcids) != expected:
                failures.append(f"{vcs_id}: count {len(vcids)}!={expected}")
            duplicates = len(vcids) - len(set(vcids))
            if duplicates:
                failures.append(f"{vcs_id}: {duplicates} duplicate verification card IDs")
        cross_duplicates = len(all_vcids) - len(set(all_vcids))
        if cross_duplicates:
            failures.append(f"{cross_duplicates} duplicate verification card IDs across tally payloads")
        report.add("3.07", "VerifyVerificationCardIdsConsistency", not failures, f"counts={counts}" if not failures else "; ".join(failures[:5]))

    def _check_control_component_public_key_consistency(self, report: VerificationReport) -> None:
        if not self.control_component_public_keys:
            report.add("3.08", "VerifyCCRChoiceReturnCodesPublicKeyConsistency", True, "no online control component public-key payloads present")
            report.add("3.09", "VerifyCCMElectionPublicKeyConsistency", True, "no online control component public-key payloads present")
            return

        setup_by_node = {
            component["nodeId"]: component
            for component in self.setup_public_keys["setupComponentPublicKeys"]["combinedControlComponentPublicKeys"]
        }
        online_by_node: dict[int, dict[str, Any]] = {}
        duplicate_nodes: set[int] = set()
        malformed: list[str] = []
        for label, payload in self.control_component_public_keys:
            try:
                component = payload["controlComponentPublicKeys"]
                node_id = component["nodeId"]
            except (KeyError, TypeError):
                malformed.append(label)
                continue
            if node_id in online_by_node:
                duplicate_nodes.add(node_id)
            online_by_node[node_id] = component

        missing_nodes = sorted(set(setup_by_node) - set(online_by_node))
        extra_nodes = sorted(set(online_by_node) - set(setup_by_node))
        ccr_failures = [f"{label}: malformed payload" for label in malformed]
        ccm_failures = [f"{label}: malformed payload" for label in malformed]
        ccr_failures.extend(f"missing node {node_id}" for node_id in missing_nodes)
        ccm_failures.extend(f"missing node {node_id}" for node_id in missing_nodes)
        ccr_failures.extend(f"extra node {node_id}" for node_id in extra_nodes)
        ccm_failures.extend(f"extra node {node_id}" for node_id in extra_nodes)
        ccr_failures.extend(f"duplicate node {node_id}" for node_id in sorted(duplicate_nodes))
        ccm_failures.extend(f"duplicate node {node_id}" for node_id in sorted(duplicate_nodes))

        for node_id in sorted(set(setup_by_node) & set(online_by_node)):
            setup_component = setup_by_node[node_id]
            online_component = online_by_node[node_id]
            if online_component.get("ccrjChoiceReturnCodesEncryptionPublicKey") != setup_component.get("ccrjChoiceReturnCodesEncryptionPublicKey"):
                ccr_failures.append(f"node {node_id}: CCR public key mismatch")
            if online_component.get("ccmjElectionPublicKey") != setup_component.get("ccmjElectionPublicKey"):
                ccm_failures.append(f"node {node_id}: CCM public key mismatch")

        report.add("3.08", "VerifyCCRChoiceReturnCodesPublicKeyConsistency", not ccr_failures, "; ".join(ccr_failures[:5]))
        report.add("3.09", "VerifyCCMElectionPublicKeyConsistency", not ccm_failures, "; ".join(ccm_failures[:5]))

    def _check_control_component_schnorr_proof_consistency(self, report: VerificationReport) -> None:
        if not self.control_component_public_keys:
            report.add("3.10", "VerifyCCMAndCCRSchnorrProofsConsistency", True, "no online control component public-key payloads present")
            return

        setup_by_node = {
            component["nodeId"]: component
            for component in self.setup_public_keys["setupComponentPublicKeys"]["combinedControlComponentPublicKeys"]
        }
        online_by_node: dict[int, dict[str, Any]] = {}
        duplicate_nodes: set[int] = set()
        malformed: list[str] = []
        for label, payload in self.control_component_public_keys:
            try:
                component = payload["controlComponentPublicKeys"]
                node_id = component["nodeId"]
            except (KeyError, TypeError):
                malformed.append(label)
                continue
            if node_id in online_by_node:
                duplicate_nodes.add(node_id)
            online_by_node[node_id] = component

        failures = [f"{label}: malformed payload" for label in malformed]
        failures.extend(f"missing node {node_id}" for node_id in sorted(set(setup_by_node) - set(online_by_node)))
        failures.extend(f"extra node {node_id}" for node_id in sorted(set(online_by_node) - set(setup_by_node)))
        failures.extend(f"duplicate node {node_id}" for node_id in sorted(duplicate_nodes))
        for node_id in sorted(set(setup_by_node) & set(online_by_node)):
            setup_component = setup_by_node[node_id]
            online_component = online_by_node[node_id]
            if online_component.get("ccrjSchnorrProofs") != setup_component.get("ccrjSchnorrProofs"):
                failures.append(f"node {node_id}: CCR Schnorr proofs mismatch")
            if online_component.get("ccmjSchnorrProofs") != setup_component.get("ccmjSchnorrProofs"):
                failures.append(f"node {node_id}: CCM Schnorr proofs mismatch")

        report.add("3.10", "VerifyCCMAndCCRSchnorrProofsConsistency", not failures, "; ".join(failures[:5]))

    def _check_setup_public_key_group_membership(self, report: VerificationReport) -> None:
        group = GqGroup.from_json(self.setup_public_keys["encryptionGroup"])
        setup = self.setup_public_keys["setupComponentPublicKeys"]
        failures: list[str] = []

        def check_values(label: str, values: list[str]) -> None:
            for index, value in enumerate(values):
                if not group_member(group, b64_to_int(value)):
                    failures.append(f"{label}[{index}]")

        for component in setup["combinedControlComponentPublicKeys"]:
            node_id = component["nodeId"]
            check_values(f"node {node_id} ccrjChoiceReturnCodesEncryptionPublicKey", component["ccrjChoiceReturnCodesEncryptionPublicKey"])
            check_values(f"node {node_id} ccmjElectionPublicKey", component["ccmjElectionPublicKey"])
        check_values("electoralBoardPublicKey", setup["electoralBoardPublicKey"])
        check_values("electionPublicKey", setup["electionPublicKey"])
        check_values("choiceReturnCodesEncryptionPublicKey", setup["choiceReturnCodesEncryptionPublicKey"])
        for label, payload in self.setup_tally_data_payloads:
            for index, keys in enumerate(payload["verificationCardPublicKeys"]):
                check_values(f"{label} verificationCardPublicKeys[{index}]", keys)

        report.add("C.01", "VerifySetupPublicKeyGroupMembership", not failures, "; ".join(failures[:5]))

    def _check_primes_mapping_table_consistency(self, report: VerificationReport) -> None:
        seen: dict[str, tuple[int, str, str]] = {}
        failures: list[str] = []
        matched_configuration_tables = 0
        for ctx in self._vcs_contexts():
            vcs_id = ctx.get("verificationCardSetId", "<unknown>")
            p_table = ctx.get("primesMappingTable", {}).get("pTable", [])
            local_actual: set[str] = set()
            local_encoded: set[int] = set()
            actual_triples: list[tuple[str, str, str]] = []
            for index, entry in enumerate(p_table):
                try:
                    actual = entry["actualVotingOption"]
                    encoded = entry["encodedVotingOption"]
                    semantic = entry["semanticInformation"]
                    correctness = entry["correctnessInformation"]
                except KeyError as exc:
                    failures.append(f"{vcs_id}[{index}]: missing {exc.args[0]}")
                    continue

                if actual in local_actual:
                    failures.append(f"{vcs_id}[{index}]: duplicate actual voting option {actual!r}")
                local_actual.add(actual)
                if encoded in local_encoded:
                    failures.append(f"{vcs_id}[{index}]: duplicate encoded voting option {encoded}")
                local_encoded.add(encoded)

                previous = seen.setdefault(actual, (encoded, semantic, correctness))
                if previous != (encoded, semantic, correctness):
                    failures.append(f"{vcs_id}[{index}]: inconsistent mapping for actual voting option {actual!r}")
                actual_triples.append((actual, semantic, correctness))

            if self.configuration_xml_path is not None:
                try:
                    expected_triples = self._configuration_p_table_triples(ctx.get("domainsOfInfluence", []))
                except (ElementTree.ParseError, ValueError, TypeError) as exc:
                    failures.append(f"configuration XML parse error: {exc}")
                    continue
                expected_set = set(expected_triples)
                actual_set = set(actual_triples)
                missing = sorted(expected_set - actual_set)
                extra = sorted(actual_set - expected_set)
                if missing:
                    failures.append(f"{vcs_id}: pTable missing XML option {missing[0][0]!r}")
                if extra:
                    failures.append(f"{vcs_id}: pTable has extra option {extra[0][0]!r}")
                if not missing and not extra and actual_triples != expected_triples:
                    failures.append(f"{vcs_id}: pTable order does not match configuration XML")
                if not missing and not extra:
                    matched_configuration_tables += 1

        detail = "; ".join(failures[:5])
        if not detail:
            if self.configuration_xml_path is None:
                detail = "configuration XML not present; checked pTable internal consistency only"
            else:
                detail = f"matched configuration XML pTables={matched_configuration_tables}"
        report.add("3.13", "VerifyPrimesMappingTableConsistency", not failures, detail)

    def _configuration_p_table_triples(self, domains_of_influence: list[str]) -> list[tuple[str, str, str]]:
        if self.configuration_xml_path is None:
            return []
        root = ElementTree.parse(self.configuration_xml_path).getroot()
        domains = set(domains_of_influence)
        groups: list[tuple[int, str, Any]] = []
        for vote in root.findall(".//config:vote", CONFIG_NS):
            if self._config_text(vote, "domainOfInfluence") in domains:
                groups.append((self._config_int(vote, "votePosition"), "vote", vote))
        for election_group in root.findall(".//config:electionGroupBallot", CONFIG_NS):
            if self._config_text(election_group, "domainOfInfluence") in domains:
                groups.append((self._config_int(election_group, "electionGroupPosition"), "election", election_group))

        triples: list[tuple[str, str, str]] = []
        for _, group_type, element in sorted(groups, key=lambda item: item[0]):
            if group_type == "vote":
                triples.extend(self._configuration_vote_triples(element))
            else:
                triples.extend(self._configuration_election_group_triples(element))
        return triples

    def _configuration_vote_triples(self, vote: Any) -> list[tuple[str, str, str]]:
        triples: list[tuple[str, str, str]] = []
        for ballot in sorted(self._config_children(vote, "ballot"), key=lambda element: self._config_int(element, "ballotPosition")):
            standard_ballot = self._config_child(ballot, "standardBallot")
            variant_ballot = self._config_child(ballot, "variantBallot")
            questions = [standard_ballot] if standard_ballot is not None else []
            if variant_ballot is not None:
                questions = sorted(
                    self._config_children(variant_ballot, "standardQuestion") + self._config_children(variant_ballot, "tieBreakQuestion"),
                    key=lambda element: self._config_int(element, "questionPosition"),
                )
            for question in questions:
                question_id = self._config_text(question, "questionIdentification")
                question_texts = self._config_localized_texts(question, "ballotQuestion", "ballotQuestionInfo", "ballotQuestion")
                for answer in sorted(self._config_children(question, "answer"), key=lambda element: self._config_int(element, "answerPosition")):
                    answer_id = self._config_text(answer, "answerIdentification")
                    answer_texts = self._config_direct_localized_texts(answer, "answerInfo", "answer")
                    kind = "BLANK" if self._configuration_answer_is_blank(answer, answer_texts) else "NON_BLANK"
                    triples.append((f"{question_id}|{answer_id}", "|".join([kind, *question_texts, *answer_texts]), question_id))
        return triples

    def _configuration_election_group_triples(self, election_group: Any) -> list[tuple[str, str, str]]:
        triples: list[tuple[str, str, str]] = []
        for election_information in self._config_children(election_group, "electionInformation"):
            election = self._config_child(election_information, "election")
            if election is None:
                continue
            election_id = self._config_text(election, "electionIdentification")
            accumulation = max(1, self._config_int(election, "candidateAccumulation"))
            list_entries = sorted(self._config_children(election_information, "list"), key=lambda element: self._config_int(element, "listOrderOfPrecedence"))
            for list_entry in list_entries:
                list_id = self._config_text(list_entry, "listIdentification")
                descriptions = self._config_localized_texts(list_entry, "listDescription", "listDescriptionInfo", "listDescription")
                triples.append((f"{election_id}|{list_id}", "|".join(["NON_BLANK", *descriptions]), f"L|{election_id}"))
            if list_entries:
                for empty_list in sorted(self._config_children(election_information, "emptyList"), key=lambda element: self._config_int(element, "listOrderOfPrecedence")):
                    list_id = self._config_text(empty_list, "listIdentification")
                    descriptions = self._config_localized_texts(empty_list, "listDescription", "listDescriptionInfo", "listDescription")
                    triples.append((f"{election_id}|{list_id}", "|".join(["BLANK", *descriptions]), f"L|{election_id}"))

            candidates = {self._config_text(candidate, "candidateIdentification"): candidate for candidate in self._config_children(election_information, "candidate")}
            candidate_ids = [
                self._config_text(candidate, "candidateIdentification")
                for candidate in self._config_children(election_information, "candidate")
            ]
            for candidate_id in candidate_ids:
                candidate = candidates.get(candidate_id)
                if candidate is None:
                    raise ValueError(f"candidate {candidate_id!r} referenced by list position but not defined")
                semantic = "|".join(
                    [
                        "NON_BLANK",
                        self._config_text(candidate, "familyName"),
                        self._config_text(candidate, "callName"),
                        self._config_text(candidate, "dateOfBirth"),
                    ]
                )
                for accumulation_index in range(accumulation):
                    triples.append((f"{election_id}|{candidate_id}|{accumulation_index}", semantic, f"C|{election_id}"))

            empty_positions = [
                empty_position
                for empty_list in self._config_children(election_information, "emptyList")
                for empty_position in self._config_children(empty_list, "emptyPosition")
            ]
            for index, empty_position in enumerate(empty_positions, start=1):
                position = self._config_text(empty_position, "positionOnList") or str(index)
                empty_position_id = self._config_text(empty_position, "emptyPositionIdentification")
                triples.append((f"{election_id}|{empty_position_id}", f"BLANK|EMPTY_CANDIDATE_POSITION-{position}", f"C|{election_id}"))

            if self._config_text(election, "writeInsAllowed").lower() == "true":
                for index, write_in in enumerate(self._config_children(election_information, "writeInPosition"), start=1):
                    position = self._config_text(write_in, "positionOnList") or str(index)
                    write_in_id = self._config_text(write_in, "writeInPositionIdentification")
                    triples.append((f"{election_id}|{write_in_id}", f"WRITE_IN|WRITE_IN_POSITION-{position}", f"C|{election_id}"))
        return triples

    def _configuration_answer_is_blank(self, answer: Any, answer_texts: list[str]) -> bool:
        answer_type = self._config_text(answer, "standardAnswerType").upper()
        return answer_type in {"BLANK", "EMPTY"} or tuple(answer_texts) == ("Leer", "Blanc", "Bianco", "Vid")

    def _config_child(self, element: Any, tag: str) -> Any | None:
        return element.find(f"config:{tag}", CONFIG_NS)

    def _config_children(self, element: Any, tag: str) -> list[Any]:
        return list(element.findall(f"config:{tag}", CONFIG_NS))

    def _config_text(self, element: Any, path: str) -> str:
        text = element.findtext("/".join(f"config:{part}" for part in path.split("/")), namespaces=CONFIG_NS)
        return text.strip() if text else ""

    def _config_int(self, element: Any, path: str) -> int:
        text = self._config_text(element, path)
        return int(text) if text else 0

    def _config_localized_texts(self, element: Any, container_tag: str, info_tag: str, text_tag: str) -> list[str]:
        container = self._config_child(element, container_tag)
        if container is None:
            return [""] * len(CONFIG_LANGUAGES)
        return self._config_direct_localized_texts(container, info_tag, text_tag)

    def _config_direct_localized_texts(self, element: Any, info_tag: str, text_tag: str) -> list[str]:
        values: dict[str, str] = {}
        for info in self._config_children(element, info_tag):
            language = self._config_text(info, "language")
            values[language] = self._config_text(info, text_tag)
        return [values.get(language, "") for language in CONFIG_LANGUAGES]

    def _check_total_voters_consistency(self, report: VerificationReport) -> None:
        if self.configuration_xml_path is None:
            report.add("3.14", "VerifyTotalVotersConsistency", True, "configuration XML not present; cannot compare total authorised voters")
            return

        try:
            tree = ElementTree.parse(self.configuration_xml_path)
            voter_total_text = tree.getroot().findtext("config:header/config:voterTotal", namespaces=CONFIG_NS)
            if voter_total_text is None:
                raise ValueError("missing header/voterTotal")
            voter_total = int(voter_total_text)
        except (ElementTree.ParseError, ValueError) as exc:
            report.add("3.14", "VerifyTotalVotersConsistency", False, f"configuration XML parse error: {exc}")
            return

        eligible_voters = sum(ctx["numberOfEligibleVoters"] for ctx in self._vcs_contexts())
        ok = voter_total == eligible_voters
        report.add("3.14", "VerifyTotalVotersConsistency", ok, f"configuration={voter_total}, context={eligible_voters}")

    def _check_public_key_consistency(self, report: VerificationReport) -> None:
        group = GqGroup.from_json(self.setup_public_keys["encryptionGroup"])
        setup = self.setup_public_keys["setupComponentPublicKeys"]
        component_keys = setup["combinedControlComponentPublicKeys"]
        ccr_keys = [[b64_to_int(v) for v in key["ccrjChoiceReturnCodesEncryptionPublicKey"]] for key in component_keys]
        ccm_keys = [[b64_to_int(v) for v in key["ccmjElectionPublicKey"]] for key in component_keys]
        combined_ccr = combine_public_keys(group, ccr_keys)
        combined_ccm = combine_public_keys(group, ccm_keys)
        expected_ccr = [b64_to_int(v) for v in setup["choiceReturnCodesEncryptionPublicKey"]]
        eb_key = [b64_to_int(v) for v in setup["electoralBoardPublicKey"]]
        expected_election = [b64_to_int(v) for v in setup["electionPublicKey"]]
        expected_ccm_with_eb = combine_public_keys(group, [eb_key, combined_ccm])
        report.add("3.11", "VerifyChoiceReturnCodesPublicKeyConsistency", combined_ccr == expected_ccr)
        report.add("3.12", "VerifyElectionPublicKeyConsistency", expected_ccm_with_eb == expected_election)

    def _check_encryption_parameters(self, report: VerificationReport) -> None:
        seed = self.election_event_context["seed"]
        group = GqGroup.from_json(self.election_event_context["encryptionGroup"])
        failures: list[str] = []
        if not re.fullmatch(r"[A-Z]{2}_[0-9]{8}_(TT|TP|PP)[0-9]{2}", seed):
            failures.append(f"seed {seed!r} does not match CT_YYYYMMDD_XYnm")
        if group.p.bit_length() != 3072:
            failures.append(f"p bit length {group.p.bit_length()}!=3072")
        if group.q.bit_length() != 3071:
            failures.append(f"q bit length {group.q.bit_length()}!=3071")
        if group.p != 2 * group.q + 1:
            failures.append("p != 2q + 1")
        if group.g not in (2, 3) or not group_member(group, group.g, allow_one=False):
            failures.append("g is not the expected generator candidate")

        if not failures:
            expected = get_encryption_parameters(seed)
            if group != expected:
                failures.append("provided encryption group does not match GetEncryptionParameters(seed)")
        report.add("5.01", "VerifyEncryptionParameters", not failures, "; ".join(failures[:5]))

    def _check_small_prime_group_members(self, report: VerificationReport) -> None:
        group = GqGroup.from_json(self.election_event_context["encryptionGroup"])
        provided = self.election_event_context["smallPrimes"]
        expected_count = len(provided)
        failures: list[str] = []
        try:
            expected = get_small_prime_group_members(group, expected_count)
        except ValueError as exc:
            failures.append(str(exc))
            expected = []
        if expected and provided != expected:
            mismatch = next((index for index, (left, right) in enumerate(zip(provided, expected)) if left != right), None)
            if mismatch is None and len(provided) != len(expected):
                mismatch = min(len(provided), len(expected))
            failures.append(f"smallPrimes mismatch at index {mismatch}")
        report.add("5.02", "VerifySmallPrimeGroupMembers", not failures, "; ".join(failures[:5]))

    def _check_ccr_schnorr_proofs(self, report: VerificationReport) -> None:
        group = GqGroup.from_json(self.setup_public_keys["encryptionGroup"])
        election_event_id = self.election_event_context["electionEventContext"]["electionEventId"]
        failures: list[str] = []
        for component in self.setup_public_keys["setupComponentPublicKeys"]["combinedControlComponentPublicKeys"]:
            node_id = component["nodeId"]
            public_keys = component["ccrjChoiceReturnCodesEncryptionPublicKey"]
            proofs = component["ccrjSchnorrProofs"]
            if len(public_keys) != len(proofs):
                failures.append(f"node {node_id}: keys={len(public_keys)} proofs={len(proofs)}")
                continue
            iaux = [election_event_id, "GenKeysCCR", str(node_id)]
            for index, (public_key, proof) in enumerate(zip(public_keys, proofs)):
                ok = verify_schnorr(group, proof, b64_to_int(public_key), iaux)
                if not ok:
                    failures.append(f"node {node_id} key {index}: invalid Schnorr proof")
                    break
        report.add("5.04", "VerifyCCRSchnorrProofs", not failures, "; ".join(failures[:5]))

    def _check_voting_options(self, report: VerificationReport) -> None:
        small_primes = self.election_event_context["smallPrimes"]
        encoded = sorted({entry["encodedVotingOption"] for ctx in self._vcs_contexts() for entry in ctx["primesMappingTable"]["pTable"]})
        prefix = small_primes[: len(encoded)]
        ok_prefix = prefix == encoded
        psi_max = self.election_event_context["electionEventContext"]["maximumNumberOfSelections"]
        product = 1
        for prime in small_primes[-psi_max:]:
            product *= prime
        p = GqGroup.from_json(self.election_event_context["encryptionGroup"]).p
        report.add("5.03", "VerifyVotingOptions", ok_prefix and product < p, f"encoded={len(encoded)}, psi_max={psi_max}")

    def _check_ballot_box_ids(self, report: VerificationReport) -> None:
        expected = {ctx["ballotBoxId"] for ctx in self._vcs_contexts()}
        observed = {payload["ballotBoxId"] for payload in self.ballot_boxes} | {payload["ballotBoxId"] for payload in self.shuffles}
        observed |= {payload.get("ballotBoxId") for _, payload in self.final_tally_shuffles}
        observed |= {payload.get("ballotBoxId") for _, payload in self.final_tally_votes}
        report.add("8.05", "VerifyBallotBoxIdsConsistency", observed <= expected, f"observed={observed}, expected={expected}")

    def _check_tally_file_name_ballot_box_ids(self, report: VerificationReport) -> None:
        expected = {ctx["ballotBoxId"] for ctx in self._vcs_contexts()}
        failures: list[str] = []
        checked = 0
        for label, payload in [*self._ballot_box_items(), *self._shuffle_items(), *self.final_tally_shuffles, *self.final_tally_votes]:
            ballot_box_id = payload.get("ballotBoxId")
            if ballot_box_id is None:
                failures.append(f"{label}: missing ballotBoxId")
            elif ballot_box_id not in expected:
                failures.append(f"{label}: unknown ballotBoxId {ballot_box_id}")
            elif "/" in label:
                checked += 1
                if ballot_box_id not in label:
                    failures.append(f"{label}: does not contain ballotBoxId {ballot_box_id}")
        detail = "; ".join(failures[:5])
        if not detail:
            detail = f"checked={checked}" if checked else "aggregated online tally payload arrays do not expose per-ballot-box paths"
        report.add("8.06", "VerifyFileNameBallotBoxIdsConsistency", not failures, detail)

    def _check_tally_verification_card_ids(self, report: VerificationReport) -> None:
        expected = {vcid for _, payload in self.setup_tally_data_payloads for vcid in payload["verificationCardIds"]}
        observed = {vote["contextIds"]["verificationCardId"] for payload in self.ballot_boxes for vote in payload["confirmedEncryptedVotes"]}
        report.add("8.07", "VerifyVerificationCardIdsConsistency", observed <= expected, f"observed={len(observed)}, expected={len(expected)}")

    def _check_confirmed_encrypted_votes_consistency(self, report: VerificationReport) -> None:
        by_ballot_box: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for payload in self.ballot_boxes:
            by_ballot_box[payload["ballotBoxId"]].append(payload)
        failures: list[str] = []
        for ballot_box_id, payloads in by_ballot_box.items():
            canonical_by_node = {
                payload["nodeId"]: Counter(
                    json.dumps(vote, sort_keys=True, separators=(",", ":"))
                    for vote in payload["confirmedEncryptedVotes"]
                )
                for payload in payloads
            }
            expected = next(iter(canonical_by_node.values()), Counter())
            for node_id, observed in canonical_by_node.items():
                if observed != expected:
                    failures.append(f"{ballot_box_id}: node {node_id} confirmed votes mismatch")
        report.add("8.08", "VerifyConfirmedEncryptedVotesConsistency", not failures, "; ".join(failures[:5]))

    def _check_ciphertext_dimensions(self, report: VerificationReport) -> None:
        by_ballot_box = self._vcs_by_ballot_box()
        failures: list[str] = []
        for payload in self.ballot_boxes:
            delta = self._delta_for_ballot_box(by_ballot_box[payload["ballotBoxId"]])
            for vote in payload["confirmedEncryptedVotes"]:
                for field in ("encryptedVote", "exponentiatedEncryptedVote", "encryptedPartialChoiceReturnCodes"):
                    expected = delta
                    if field == "exponentiatedEncryptedVote":
                        expected = 1
                    elif field == "encryptedPartialChoiceReturnCodes":
                        expected = self._psi_for_ballot_box(by_ballot_box[payload["ballotBoxId"]])
                    if len(vote[field]["phis"]) != expected:
                        failures.append(f"{field}:{len(vote[field]['phis'])}!={expected}")
        for payload in self.shuffles:
            delta = self._delta_for_ballot_box(by_ballot_box[payload["ballotBoxId"]])
            for ciphertext in payload["verifiableShuffle"]["shuffledCiphertexts"]:
                if len(ciphertext["phis"]) != delta:
                    failures.append(f"shuffle:{len(ciphertext['phis'])}!={delta}")
            for ciphertext in payload["verifiableDecryptions"]["ciphertexts"]:
                if len(ciphertext["phis"]) != delta:
                    failures.append(f"decryption:{len(ciphertext['phis'])}!={delta}")
        report.add("8.09", "VerifyCiphertextsConsistency", not failures, "; ".join(failures[:5]))

    def _check_plaintext_dimensions(self, report: VerificationReport) -> None:
        if not self.final_tally_shuffles:
            report.add("8.10", "VerifyPlaintextsConsistency", True, "no tally component shuffle payloads present")
            return

        by_ballot_box = self._vcs_by_ballot_box()
        final_by_ballot_box, duplicates, malformed = self._payloads_by_ballot_box(self.final_tally_shuffles)
        failures = [f"{ballot_box_id}: duplicate tally component shuffle payloads" for ballot_box_id in duplicates]
        failures.extend(f"{label}: missing ballotBoxId" for label in malformed)
        for ballot_box_id, payload in final_by_ballot_box.items():
            ctx = by_ballot_box.get(ballot_box_id)
            if ctx is None:
                failures.append(f"{ballot_box_id}: unknown ballot box")
                continue
            delta = self._delta_for_ballot_box(ctx)
            try:
                messages = payload["verifiablePlaintextDecryption"]["decryptedVotes"]
            except (KeyError, TypeError) as exc:
                failures.append(f"{ballot_box_id}: malformed plaintext decryption ({exc})")
                continue
            for index, message in enumerate(messages):
                try:
                    width = len(message["message"])
                except (KeyError, TypeError) as exc:
                    failures.append(f"{ballot_box_id}: malformed plaintext message {index} ({exc})")
                    continue
                if width != delta:
                    failures.append(f"{ballot_box_id}: plaintext {index} width {width}!={delta}")
                    break
        report.add("8.10", "VerifyPlaintextsConsistency", not failures, "; ".join(failures[:5]))

    def _check_number_confirmed_votes(self, report: VerificationReport) -> None:
        failures: list[str] = []
        confirmed_counts: dict[str, dict[int, int]] = defaultdict(dict)
        shuffled_counts: dict[str, dict[int, int]] = defaultdict(dict)
        expected_nc: dict[str, int] = {}
        expected_nhat: dict[str, int] = {}
        for payload in self.ballot_boxes:
            confirmed_counts[payload["ballotBoxId"]][payload["nodeId"]] = len(payload["confirmedEncryptedVotes"])
        for payload in self.shuffles:
            shuffled_counts[payload["ballotBoxId"]][payload["nodeId"]] = len(payload["verifiableShuffle"]["shuffledCiphertexts"])
        for ballot_box_id, counts_by_node in confirmed_counts.items():
            values = set(counts_by_node.values())
            if len(values) != 1:
                failures.append(f"{ballot_box_id}: inconsistent confirmed counts {counts_by_node}")
                continue
            nc = next(iter(values))
            expected_nc[ballot_box_id] = nc
            expected_nhat[ballot_box_id] = nc + 2 if nc < 2 else nc
        for ballot_box_id, counts_by_node in shuffled_counts.items():
            values = set(counts_by_node.values())
            if len(values) != 1:
                failures.append(f"{ballot_box_id}: inconsistent online shuffle counts {counts_by_node}")
                continue
            n_hat = next(iter(values))
            expected = expected_nhat.get(ballot_box_id)
            if expected is not None and n_hat != expected:
                failures.append(f"{ballot_box_id}: Nhat {n_hat}!={expected}")

        final_vote_counts: dict[str, int] = {}
        for label, payload in self.final_tally_votes:
            try:
                counts = (
                    len(payload["decryptedVotes"]),
                    len(payload["decodedVotes"]),
                    len(payload["decodedWriteIns"]),
                )
                ballot_box_id = payload["ballotBoxId"]
            except (KeyError, TypeError) as exc:
                failures.append(f"{label}: malformed tally component votes ({exc})")
                continue
            if len(set(counts)) != 1:
                failures.append(f"{label}: tally component votes lengths differ {counts}")
                continue
            final_vote_counts[ballot_box_id] = counts[0]
            expected = expected_nc.get(ballot_box_id)
            if expected is not None and counts[0] != expected:
                failures.append(f"{ballot_box_id}: tally component votes NC {counts[0]}!={expected}")

        final_shuffle_counts: dict[str, int] = {}
        for label, payload in self.final_tally_shuffles:
            try:
                shuffle_count = len(payload["verifiableShuffle"]["shuffledCiphertexts"])
                plaintext_count = len(payload["verifiablePlaintextDecryption"]["decryptedVotes"])
                ballot_box_id = payload["ballotBoxId"]
            except (KeyError, TypeError) as exc:
                failures.append(f"{label}: malformed tally component shuffle ({exc})")
                continue
            if shuffle_count != plaintext_count:
                failures.append(f"{label}: tally component shuffle/plaintext counts differ {shuffle_count}!={plaintext_count}")
                continue
            final_shuffle_counts[ballot_box_id] = shuffle_count
            expected = expected_nhat.get(ballot_box_id)
            if expected is not None and shuffle_count != expected:
                failures.append(f"{ballot_box_id}: tally component shuffle Nhat {shuffle_count}!={expected}")

        detail = f"NC={dict(confirmed_counts)}, Nhat={dict(shuffled_counts)}"
        if final_vote_counts or final_shuffle_counts:
            detail += f", finalVotes={final_vote_counts}, finalShuffles={final_shuffle_counts}"
        if failures:
            detail = "; ".join(failures[:5])
        report.add("8.11", "VerifyNumberConfirmedEncryptedVotesConsistency", not failures, detail)

    def _check_voting_client_proofs(self, report: VerificationReport) -> None:
        node_one_payloads = [payload for payload in self.ballot_boxes if payload["nodeId"] == 1]
        if not node_one_payloads:
            report.add("10.01", "VerifyVotingClientProofs", False, "missing node 1 ballot-box payloads")
            return

        group = GqGroup.from_json(node_one_payloads[0]["encryptionGroup"])
        setup_keys = self.setup_public_keys["setupComponentPublicKeys"]
        election_pk = [b64_to_int(value) for value in setup_keys["electionPublicKey"]]
        pk_ccr = [b64_to_int(value) for value in setup_keys["choiceReturnCodesEncryptionPublicKey"]]
        key_map = {
            vcid: b64_to_int(key[0])
            for _, payload in self.setup_tally_data_payloads
            for vcid, key in zip(payload["verificationCardIds"], payload["verificationCardPublicKeys"])
        }
        by_ballot_box = self._vcs_by_ballot_box()
        failures: list[str] = []
        seen: set[str] = set()

        for payload in node_one_payloads:
            ctx = by_ballot_box.get(payload["ballotBoxId"])
            if ctx is None:
                failures.append(f"{payload['ballotBoxId']}: unknown ballot box")
                continue
            psi = self._psi_for_ballot_box(ctx)
            hash_context = self._get_hash_context(ctx)

            for vote in payload["confirmedEncryptedVotes"]:
                vcid = vote["contextIds"]["verificationCardId"]
                if vcid in seen:
                    failures.append(f"duplicate verification card {vcid}")
                    continue
                seen.add(vcid)
                if vcid not in key_map:
                    failures.append(f"unknown verification card {vcid}")
                    continue
                e1 = vote["encryptedVote"]
                e1_tilde = vote["exponentiatedEncryptedVote"]
                e2 = vote["encryptedPartialChoiceReturnCodes"]
                gamma1 = b64_to_int(e1["gamma"])
                phi10 = b64_to_int(e1["phis"][0])
                gamma2 = b64_to_int(e2["gamma"])
                e2_product = 1
                for phi in e2["phis"]:
                    e2_product = (e2_product * b64_to_int(phi)) % group.p
                e2_tilde = {"gamma": e2["gamma"], "phis": [base64.b64encode(e2_product.to_bytes((e2_product.bit_length() + 7) // 8, "big")).decode("ascii")]}
                pk_ccr_tilde = 1
                for value in pk_ccr[:psi]:
                    pk_ccr_tilde = (pk_ccr_tilde * value) % group.p
                iaux = ["CreateVote", vcid, hash_context]
                iaux.append(str(gamma1))
                iaux.extend(str(b64_to_int(phi)) for phi in e1["phis"])
                iaux.extend([str(gamma2)])
                iaux.extend(str(b64_to_int(phi)) for phi in e2["phis"])

                exp_ok = verify_exponentiation(
                    group,
                    [group.g, gamma1, phi10],
                    [key_map[vcid], b64_to_int(e1_tilde["gamma"]), b64_to_int(e1_tilde["phis"][0])],
                    vote["exponentiationProof"],
                    iaux,
                )
                eq_ok = verify_plaintext_equality(
                    group,
                    e1_tilde,
                    e2_tilde,
                    election_pk[0],
                    pk_ccr_tilde,
                    vote["plaintextEqualityProof"],
                    iaux,
                )
                if not exp_ok or not eq_ok:
                    failures.append(f"{vcid}: exp={exp_ok}, eq={eq_ok}")
        report.add("10.01", "VerifyVotingClientProofs", not failures, "; ".join(failures[:5]))

    def _check_online_decryption_proofs(self, report: VerificationReport) -> None:
        group = GqGroup.from_json(self.setup_public_keys["encryptionGroup"])
        component_keys = {
            item["nodeId"]: [b64_to_int(value) for value in item["ccmjElectionPublicKey"]]
            for item in self.setup_public_keys["setupComponentPublicKeys"]["combinedControlComponentPublicKeys"]
        }
        failures: list[str] = []
        for payload in self.shuffles:
            node_id = payload["nodeId"]
            public_key = component_keys.get(node_id)
            if public_key is None:
                failures.append(f"node {node_id}: missing CCM election public key")
                continue
            decryptions = payload["verifiableDecryptions"]
            iaux = [payload["electionEventId"], payload["ballotBoxId"], "MixDecOnline", str(node_id)]
            ok = verify_decryptions(
                group,
                payload["verifiableShuffle"]["shuffledCiphertexts"],
                public_key,
                decryptions["ciphertexts"],
                decryptions["decryptionProofs"],
                iaux,
            )
            if not ok:
                failures.append(f"node {node_id}: invalid decryption proof")
        report.add("10.02", "VerifyMixDecOfflineDecryptions", not failures, "; ".join(failures[:5]))

    def _check_mixdec_chain_consistency(self, report: VerificationReport) -> None:
        failures: list[str] = []
        ballot_boxes_by_id = defaultdict(list)
        shuffles_by_id = defaultdict(list)
        for payload in self.ballot_boxes:
            ballot_boxes_by_id[payload["ballotBoxId"]].append(payload)
        for payload in self.shuffles:
            shuffles_by_id[payload["ballotBoxId"]].append(payload)

        for ballot_box_id, shuffles in sorted(shuffles_by_id.items()):
            first = next((payload for payload in ballot_boxes_by_id[ballot_box_id] if payload["nodeId"] == 1), None)
            if first is None:
                failures.append(f"{ballot_box_id}: missing node 1 ballot-box payload")
                continue
            ctx = self._vcs_by_ballot_box()[ballot_box_id]
            delta = self._delta_for_ballot_box(ctx)
            _, initial_ciphertexts = self._get_mixnet_initial_ciphertexts(first, delta)
            expected_count = len(initial_ciphertexts)
            if expected_count < 2:
                failures.append(f"{ballot_box_id}: mixnet initial ciphertext count {expected_count}<2")

            previous_decryptions_count: int | None = None
            for payload in sorted(shuffles, key=lambda item: item["nodeId"]):
                node_id = payload["nodeId"]
                shuffled = payload["verifiableShuffle"]["shuffledCiphertexts"]
                decrypted = payload["verifiableDecryptions"]["ciphertexts"]
                if len(shuffled) != expected_count:
                    failures.append(f"{ballot_box_id} node {node_id}: shuffled={len(shuffled)}!={expected_count}")
                if len(decrypted) != expected_count:
                    failures.append(f"{ballot_box_id} node {node_id}: decrypted={len(decrypted)}!={expected_count}")
                if previous_decryptions_count is not None and len(shuffled) != previous_decryptions_count:
                    failures.append(f"{ballot_box_id} node {node_id}: shuffled={len(shuffled)}!=previous decrypted={previous_decryptions_count}")
                previous_decryptions_count = len(decrypted)
                for kind, ciphertexts in (("shuffled", shuffled), ("decrypted", decrypted)):
                    bad_width = [index for index, ciphertext in enumerate(ciphertexts) if len(ciphertext["phis"]) != delta]
                    if bad_width:
                        failures.append(f"{ballot_box_id} node {node_id}: {kind} width mismatch at {bad_width[:3]}")
        report.add("10.03", "VerifyMixDecOfflineChain", not failures, "; ".join(failures[:5]))

    def _check_mixdec_shuffle_proofs(self, report: VerificationReport) -> None:
        group = GqGroup.from_json(self.setup_public_keys["encryptionGroup"])
        setup_keys = self.setup_public_keys["setupComponentPublicKeys"]
        election_pk = [b64_to_int(value) for value in setup_keys["electionPublicKey"]]
        electoral_board_pk = [b64_to_int(value) for value in setup_keys["electoralBoardPublicKey"]]
        component_keys = {
            item["nodeId"]: [b64_to_int(value) for value in item["ccmjElectionPublicKey"]]
            for item in setup_keys["combinedControlComponentPublicKeys"]
        }

        failures: list[str] = []
        ballot_boxes_by_id = defaultdict(list)
        shuffles_by_id = defaultdict(list)
        for payload in self.ballot_boxes:
            ballot_boxes_by_id[payload["ballotBoxId"]].append(payload)
        for payload in self.shuffles:
            shuffles_by_id[payload["ballotBoxId"]].append(payload)

        for ballot_box_id, shuffles in sorted(shuffles_by_id.items()):
            node_one_ballot_box = next((payload for payload in ballot_boxes_by_id[ballot_box_id] if payload["nodeId"] == 1), None)
            if node_one_ballot_box is None:
                failures.append(f"{ballot_box_id}: missing node 1 ballot-box payload")
                continue

            ctx = self._vcs_by_ballot_box().get(ballot_box_id)
            if ctx is None:
                failures.append(f"{ballot_box_id}: missing verification-card-set context")
                continue

            delta = self._delta_for_ballot_box(ctx)
            _, previous_ciphertexts = self._get_mixnet_initial_ciphertexts(node_one_ballot_box, delta)
            if len(previous_ciphertexts) < 2:
                failures.append(f"{ballot_box_id}: mixnet initial ciphertext count {len(previous_ciphertexts)}<2")
                continue

            commitment_key = get_verifiable_commitment_key(group, self._matrix_column_count(len(previous_ciphertexts)))
            for payload in sorted(shuffles, key=lambda item: item["nodeId"]):
                node_id = payload["nodeId"]
                shuffled_ciphertexts = payload["verifiableShuffle"]["shuffledCiphertexts"]
                if node_id == 1:
                    public_key = election_pk
                else:
                    missing_keys = [index for index in range(node_id, 5) if index not in component_keys]
                    if missing_keys:
                        failures.append(f"node {node_id}: missing CCM election public keys {missing_keys}")
                        previous_ciphertexts = payload["verifiableDecryptions"]["ciphertexts"]
                        continue
                    public_key = combine_public_keys(
                        group,
                        [component_keys[index] for index in range(node_id, 5)] + [electoral_board_pk],
                    )

                try:
                    ok = verify_shuffle_argument(
                        group,
                        public_key,
                        commitment_key,
                        {
                            "ciphertexts": previous_ciphertexts,
                            "shuffled_ciphertexts": shuffled_ciphertexts,
                        },
                        self._normalize_shuffle_argument(payload["verifiableShuffle"]["shuffleArgument"]),
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    failures.append(f"node {node_id}: malformed shuffle proof ({exc})")
                    ok = True

                if not ok:
                    failures.append(f"node {node_id}: invalid shuffle proof")
                previous_ciphertexts = payload["verifiableDecryptions"]["ciphertexts"]

        report.add("10.04", "VerifyMixDecOfflineShuffles", not failures, "; ".join(failures[:5]))

    def _check_final_tally_ids(self, report: VerificationReport) -> None:
        if not self.final_tally_shuffles and not self.final_tally_votes:
            report.add("11.01", "VerifyFinalTallyPayloadIds", True, "no final tally payloads present")
            return

        context_ee = self.election_event_context["electionEventContext"]["electionEventId"]
        ballot_box_ids = set(self._vcs_by_ballot_box())
        failures: list[str] = []
        for label, payload in [*self.final_tally_shuffles, *self.final_tally_votes]:
            election_event_id = payload.get("electionEventId")
            ballot_box_id = payload.get("ballotBoxId")
            if election_event_id != context_ee:
                failures.append(f"{label}: electionEventId mismatch")
            if ballot_box_id not in ballot_box_ids:
                failures.append(f"{label}: unknown ballotBoxId {ballot_box_id}")
        report.add("11.01", "VerifyFinalTallyPayloadIds", not failures, "; ".join(failures[:5]))

    def _check_final_mixdec_offline(self, report: VerificationReport) -> None:
        if not self.final_tally_shuffles:
            report.add("11.02", "VerifyFinalMixDecOffline", True, "no tally component shuffle payloads present")
            return

        group = GqGroup.from_json(self.setup_public_keys["encryptionGroup"])
        electoral_board_pk = [b64_to_int(value) for value in self.setup_public_keys["setupComponentPublicKeys"]["electoralBoardPublicKey"]]
        final_by_ballot_box, duplicates, malformed = self._payloads_by_ballot_box(self.final_tally_shuffles)
        control_by_ballot_box = defaultdict(list)
        for payload in self.shuffles:
            control_by_ballot_box[payload["ballotBoxId"]].append(payload)

        failures = [f"{ballot_box_id}: duplicate tally component shuffle payloads" for ballot_box_id in duplicates]
        failures.extend(f"{label}: missing ballotBoxId" for label in malformed)
        for ballot_box_id, payload in final_by_ballot_box.items():
            ctx = self._vcs_by_ballot_box().get(ballot_box_id)
            if ctx is None:
                failures.append(f"{ballot_box_id}: unknown ballot box")
                continue
            node_four = next((item for item in control_by_ballot_box[ballot_box_id] if item["nodeId"] == 4), None)
            if node_four is None:
                failures.append(f"{ballot_box_id}: missing node 4 decrypted ciphertexts")
                continue

            previous_ciphertexts = node_four["verifiableDecryptions"]["ciphertexts"]
            shuffled_ciphertexts = payload["verifiableShuffle"]["shuffledCiphertexts"]
            plaintext_decryption = payload["verifiablePlaintextDecryption"]
            try:
                plaintext_votes = [self._plaintext_message(message) for message in plaintext_decryption["decryptedVotes"]]
            except (KeyError, TypeError, ValueError) as exc:
                failures.append(f"{ballot_box_id}: malformed plaintext messages ({exc})")
                continue
            decryption_proofs = plaintext_decryption["decryptionProofs"]
            delta = self._delta_for_ballot_box(ctx)
            public_key = electoral_board_pk[:delta]

            if len(previous_ciphertexts) < 2:
                failures.append(f"{ballot_box_id}: previous ciphertext count {len(previous_ciphertexts)}<2")
                continue
            if not (len(shuffled_ciphertexts) == len(plaintext_votes) == len(decryption_proofs) == len(previous_ciphertexts)):
                failures.append(
                    f"{ballot_box_id}: counts previous={len(previous_ciphertexts)}, shuffled={len(shuffled_ciphertexts)}, "
                    f"plaintexts={len(plaintext_votes)}, proofs={len(decryption_proofs)}"
                )
                continue
            if any(len(message) != delta for message in plaintext_votes):
                failures.append(f"{ballot_box_id}: plaintext width mismatch")
                continue

            commitment_key = get_verifiable_commitment_key(group, self._matrix_column_count(len(previous_ciphertexts)))
            try:
                shuffle_ok = verify_shuffle_argument(
                    group,
                    public_key,
                    commitment_key,
                    {
                        "ciphertexts": previous_ciphertexts,
                        "shuffled_ciphertexts": shuffled_ciphertexts,
                    },
                    self._normalize_shuffle_argument(payload["verifiableShuffle"]["shuffleArgument"]),
                )
            except (KeyError, TypeError, ValueError) as exc:
                failures.append(f"{ballot_box_id}: malformed final shuffle proof ({exc})")
                shuffle_ok = True
            if not shuffle_ok:
                failures.append(f"{ballot_box_id}: invalid final shuffle proof")

            iaux = [payload["electionEventId"], ballot_box_id, "MixDecOffline"]
            for index, (ciphertext, message, proof) in enumerate(zip(shuffled_ciphertexts, plaintext_votes, decryption_proofs)):
                if not verify_decryption(group, ciphertext, public_key, message, proof, iaux):
                    failures.append(f"{ballot_box_id}: invalid final decryption proof at {index}")
                    break

        report.add("11.02", "VerifyFinalMixDecOffline", not failures, "; ".join(failures[:5]))

    def _check_final_process_plaintexts(self, report: VerificationReport) -> None:
        if not self.final_tally_shuffles and not self.final_tally_votes:
            report.add("11.03", "VerifyProcessPlaintexts", True, "no final tally payloads present")
            return
        if not self.final_tally_shuffles or not self.final_tally_votes:
            report.add("11.03", "VerifyProcessPlaintexts", False, "requires both final shuffle and votes payloads")
            return

        group = GqGroup.from_json(self.setup_public_keys["encryptionGroup"])
        shuffles_by_ballot_box, shuffle_duplicates, malformed_shuffles = self._payloads_by_ballot_box(self.final_tally_shuffles)
        votes_by_ballot_box, vote_duplicates, malformed_votes = self._payloads_by_ballot_box(self.final_tally_votes)
        failures = [f"{ballot_box_id}: duplicate tally component shuffle payloads" for ballot_box_id in shuffle_duplicates]
        failures.extend(f"{ballot_box_id}: duplicate tally component votes payloads" for ballot_box_id in vote_duplicates)
        failures.extend(f"{label}: missing ballotBoxId" for label in malformed_shuffles)
        failures.extend(f"{label}: missing ballotBoxId" for label in malformed_votes)
        for ballot_box_id, votes_payload in votes_by_ballot_box.items():
            shuffle_payload = shuffles_by_ballot_box.get(ballot_box_id)
            ctx = self._vcs_by_ballot_box().get(ballot_box_id)
            if shuffle_payload is None:
                failures.append(f"{ballot_box_id}: missing final shuffle payload")
                continue
            if ctx is None:
                failures.append(f"{ballot_box_id}: unknown ballot box")
                continue
            try:
                plaintext_votes = [
                    self._plaintext_message(message)
                    for message in shuffle_payload["verifiablePlaintextDecryption"]["decryptedVotes"]
                ]
            except (KeyError, TypeError, ValueError) as exc:
                failures.append(f"{ballot_box_id}: malformed plaintext messages ({exc})")
                continue
            try:
                output = process_plaintexts(group, ctx["primesMappingTable"], plaintext_votes)
            except ValueError as exc:
                failures.append(f"{ballot_box_id}: ProcessPlaintexts failed ({exc})")
                continue
            if output.votes != votes_payload["decryptedVotes"]:
                failures.append(f"{ballot_box_id}: decryptedVotes mismatch")
            if output.decoded_votes != votes_payload["decodedVotes"]:
                failures.append(f"{ballot_box_id}: decodedVotes mismatch")
            if output.write_ins != votes_payload["decodedWriteIns"]:
                failures.append(f"{ballot_box_id}: decodedWriteIns mismatch")

        missing_votes = set(shuffles_by_ballot_box) - set(votes_by_ballot_box)
        failures.extend(f"{ballot_box_id}: missing final votes payload" for ballot_box_id in sorted(missing_votes))
        report.add("11.03", "VerifyProcessPlaintexts", not failures, "; ".join(failures[:5]))

    def _check_ech0222_content(self, report: VerificationReport) -> None:
        if self.ech0222_xml_path is None:
            report.add("11.04", "VerifyECH0222Content", True, "no eCH-0222 XML present")
            return
        if not self.final_tally_votes:
            report.add("11.04", "VerifyECH0222Content", False, "requires final tally votes payloads")
            return

        try:
            actual_selections, actual_write_ins, actual_empty_positions = self._extract_ech0222_content()
        except (ElementTree.ParseError, ValueError) as exc:
            report.add("11.04", "VerifyECH0222Content", False, f"eCH-0222 parse error: {exc}")
            return

        expected_selections: Counter[str] = Counter()
        expected_write_ins: Counter[str] = Counter()
        expected_empty_positions: Counter[str] = Counter()
        for _, payload in self.final_tally_votes:
            for decoded_vote in payload.get("decodedVotes", []):
                for selection in decoded_vote:
                    canonical = self._ech_canonical_selection(selection)
                    if canonical == "__WRITE_IN__":
                        continue
                    if canonical.startswith("__EMPTY__|"):
                        expected_empty_positions[canonical.split("|", 1)[1]] += 1
                    else:
                        expected_selections[canonical] += 1
            for write_ins in payload.get("decodedWriteIns", []):
                expected_write_ins.update(self._normalize_ech_write_in(write_in) for write_in in write_ins)

        failures: list[str] = []
        missing_selections = expected_selections - actual_selections
        extra_selections = actual_selections - expected_selections
        missing_write_ins = expected_write_ins - actual_write_ins
        extra_write_ins = actual_write_ins - expected_write_ins
        missing_empty_positions = expected_empty_positions - actual_empty_positions
        extra_empty_positions = actual_empty_positions - expected_empty_positions
        if missing_selections:
            failures.append(f"missing decoded selections {dict(missing_selections)}")
        if missing_write_ins:
            failures.append(f"missing write-ins {dict(missing_write_ins)}")
        if extra_write_ins:
            failures.append(f"extra write-ins {dict(extra_write_ins)}")
        if missing_empty_positions:
            failures.append(f"missing empty positions {dict(missing_empty_positions)}")
        if not failures:
            detail = (
                f"decoded selections={sum(actual_selections.values())}, "
                f"write-ins={sum(actual_write_ins.values())}, empty positions={sum(actual_empty_positions.values())}"
            )
            if extra_selections or extra_empty_positions:
                detail += " (eCH contains additional raw invalid-ballot selections)"
        else:
            detail = "; ".join(failures[:4])
        report.add("11.04", "VerifyECH0222Content", not failures, detail)

    def _extract_ech0222_content(self) -> tuple[Counter[str], Counter[str], Counter[str]]:
        if self.ech0222_xml_path is None:
            return Counter(), Counter(), Counter()
        root = ElementTree.parse(self.ech0222_xml_path).getroot()
        selections: Counter[str] = Counter()
        write_ins: Counter[str] = Counter()
        empty_positions: Counter[str] = Counter()

        for question in root.iter():
            if self._xml_local_name(question.tag) != "questionRawData":
                continue
            question_id = self._xml_child_text(question, "questionIdentification")
            casted = self._xml_child(question, "casted")
            if not question_id or casted is None:
                continue
            answer_id = self._xml_descendant_text(self._xml_child(casted, "answerOptionIdentification"), "answerIdentification")
            if not answer_id:
                answer_id = self._xml_child_text(casted, "answerOptionIdentification")
            if answer_id:
                selections[f"{question_id}|{answer_id}"] += self._xml_child_int(casted, "castedVote", 1)

        for election in root.iter():
            if self._xml_local_name(election.tag) != "electionRawData":
                continue
            election_id = self._xml_child_text(election, "electionIdentification")
            if not election_id:
                continue
            list_raw_data = self._xml_child(election, "listRawData")
            list_id = self._xml_child_text(list_raw_data, "listIdentification") if list_raw_data is not None else ""
            if list_id:
                selections[f"{election_id}|{list_id}"] += 1
            for ballot_position in self._xml_children(election, "ballotPosition"):
                if self._xml_child_text(ballot_position, "isEmpty").lower() == "true":
                    empty_positions[election_id] += 1
                    continue
                candidate = self._xml_child(ballot_position, "candidate")
                if candidate is None:
                    continue
                candidate_id = self._xml_child_text(candidate, "candidateIdentification")
                if candidate_id:
                    selections[f"{election_id}|{candidate_id}"] += 1
                    continue
                write_in = self._xml_child_text(candidate, "writeIn")
                if write_in:
                    write_ins[self._normalize_ech_write_in(write_in)] += 1

        return selections, write_ins, empty_positions

    def _ech_canonical_selection(self, actual_voting_option: str) -> str:
        by_actual: dict[str, tuple[str, str]] = {}
        for ctx in self._vcs_contexts():
            for entry in ctx.get("primesMappingTable", {}).get("pTable", []):
                by_actual[entry["actualVotingOption"]] = (entry["correctnessInformation"], entry["semanticInformation"])
        correctness, semantic = by_actual.get(actual_voting_option, ("", ""))
        if semantic.startswith("WRITE_IN|"):
            return "__WRITE_IN__"
        if semantic.startswith("BLANK|EMPTY_CANDIDATE_POSITION"):
            election_id = correctness.split("|", 1)[1] if "|" in correctness else actual_voting_option.split("|", 1)[0]
            return f"__EMPTY__|{election_id}"
        parts = actual_voting_option.split("|")
        if correctness.startswith("C|") and len(parts) == 3:
            return "|".join(parts[:2])
        return actual_voting_option

    def _normalize_ech_write_in(self, value: str) -> str:
        normalized = " ".join(str(value).split())
        return normalized if normalized else "-"

    def _xml_local_name(self, tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    def _xml_child(self, element: Any, local_name: str) -> Any | None:
        for child in list(element):
            if self._xml_local_name(child.tag) == local_name:
                return child
        return None

    def _xml_children(self, element: Any, local_name: str) -> list[Any]:
        return [child for child in list(element) if self._xml_local_name(child.tag) == local_name]

    def _xml_child_text(self, element: Any | None, local_name: str) -> str:
        if element is None:
            return ""
        child = self._xml_child(element, local_name)
        if child is None or child.text is None:
            return ""
        return child.text.strip()

    def _xml_child_int(self, element: Any | None, local_name: str, default: int) -> int:
        text = self._xml_child_text(element, local_name)
        return int(text) if text else default

    def _xml_descendant_text(self, element: Any | None, local_name: str) -> str:
        if element is None:
            return ""
        for descendant in element.iter():
            if descendant is not element and self._xml_local_name(descendant.tag) == local_name and descendant.text:
                return descendant.text.strip()
        return ""

    def _payloads_by_ballot_box(self, payloads: list[tuple[str, Any]]) -> tuple[dict[str, Any], list[str], list[str]]:
        result: dict[str, Any] = {}
        duplicates: set[str] = set()
        malformed: list[str] = []
        for label, payload in payloads:
            ballot_box_id = payload.get("ballotBoxId")
            if not isinstance(ballot_box_id, str):
                malformed.append(label)
                continue
            if ballot_box_id in result:
                duplicates.add(ballot_box_id)
            result[ballot_box_id] = payload
        return result, sorted(duplicates), malformed

    def _plaintext_message(self, message: dict[str, Any]) -> list[int]:
        return [b64_to_int(value) for value in message["message"]]

    def _matrix_column_count(self, count: int) -> int:
        divisors = [candidate for candidate in range(1, int(count**0.5) + 1) if count % candidate == 0]
        if not divisors:
            raise ValueError("ciphertext count must be positive")
        return count // divisors[-1]

    def _normalize_shuffle_argument(self, argument: dict[str, Any]) -> dict[str, Any]:
        return {
            "ca": argument["c_A"],
            "cb": argument["c_B"],
            "product_argument": self._normalize_product_argument(argument["productArgument"]),
            "multi_exp_argument": self._normalize_multi_exponentiation_argument(argument["multiExponentiationArgument"]),
        }

    def _normalize_product_argument(self, argument: dict[str, Any]) -> dict[str, Any]:
        normalized = {
            "single_vpa": self._normalize_single_value_product_argument(argument["singleValueProductArgument"]),
        }
        if "c_b" in argument:
            normalized["c_b"] = argument["c_b"]
        if "hadamardArgument" in argument:
            normalized["hadamard_argument"] = self._normalize_hadamard_argument(argument["hadamardArgument"])
        return normalized

    def _normalize_hadamard_argument(self, argument: dict[str, Any]) -> dict[str, Any]:
        return {
            "cUpperB": argument["c_b"],
            "zero_argument": self._normalize_zero_argument(argument["zeroArgument"]),
        }

    def _normalize_zero_argument(self, argument: dict[str, Any]) -> dict[str, Any]:
        return {
            "c_a0": argument["c_A_0"],
            "c_bm": argument["c_B_m"],
            "c_d": argument["c_d"],
            "a": argument["a_prime"],
            "b": argument["b_prime"],
            "r": argument["r_prime"],
            "s": argument["s_prime"],
            "t": argument["t_prime"],
        }

    def _normalize_single_value_product_argument(self, argument: dict[str, Any]) -> dict[str, Any]:
        return {
            "c_d": argument["c_d"],
            "c_lower_delta": argument["c_delta"],
            "c_upper_delta": argument["c_Delta"],
            "a_tilde": argument["a_tilde"],
            "b_tilde": argument["b_tilde"],
            "r_tilde": argument["r_tilde"],
            "s_tilde": argument["s_tilde"],
        }

    def _normalize_multi_exponentiation_argument(self, argument: dict[str, Any]) -> dict[str, Any]:
        return {
            "c_a_0": argument["c_A_0"],
            "c_b": argument["c_B"],
            "e": argument["E"],
            "a": argument["a"],
            "r": argument["r"],
            "b": argument["b"],
            "s": argument["s"],
            "tau": argument["tau"],
        }

    def _get_mixnet_initial_ciphertexts(self, ballot_box_payload: dict[str, Any], delta: int) -> tuple[str, list[dict[str, Any]]]:
        group = GqGroup.from_json(ballot_box_payload["encryptionGroup"])
        election_pk = [
            b64_to_int(value)
            for value in self.setup_public_keys["setupComponentPublicKeys"]["electionPublicKey"][:delta]
        ]
        encrypted_confirmed_votes = {
            vote["contextIds"]["verificationCardId"]: vote["encryptedVote"]
            for vote in ballot_box_payload["confirmedEncryptedVotes"]
        }
        return get_mixnet_initial_ciphertexts(group, encrypted_confirmed_votes, election_pk, delta)

    def _get_hash_context(self, ctx: dict[str, Any]) -> str:
        group = GqGroup.from_json(self.election_event_context["encryptionGroup"])
        setup_keys = self.setup_public_keys["setupComponentPublicKeys"]
        election_pk = [b64_to_int(value) for value in setup_keys["electionPublicKey"]]
        pk_ccr = [b64_to_int(value) for value in setup_keys["choiceReturnCodesEncryptionPublicKey"]]
        return get_hash_context(
            group,
            self.election_event_context["electionEventContext"]["electionEventId"],
            ctx["verificationCardSetId"],
            ctx["primesMappingTable"]["pTable"],
            election_pk,
            pk_ccr,
        )

    def _get_hash_election_event_context(self) -> str:
        group = GqGroup.from_json(self.election_event_context["encryptionGroup"])
        return get_hash_election_event_context(group, self.election_event_context["electionEventContext"])

    def _vcs_contexts(self) -> list[dict[str, Any]]:
        return self.election_event_context["electionEventContext"]["verificationCardSetContexts"]

    def _ballot_box_items(self) -> list[tuple[str, dict[str, Any]]]:
        if len(self.ballot_box_payloads) == len(self.ballot_boxes) and all(
            payload is current for (_, payload), current in zip(self.ballot_box_payloads, self.ballot_boxes)
        ):
            return self.ballot_box_payloads
        return [(f"controlComponentBallotBoxPayloads[{index}]", payload) for index, payload in enumerate(self.ballot_boxes)]

    def _shuffle_items(self) -> list[tuple[str, dict[str, Any]]]:
        if len(self.shuffle_payloads) == len(self.shuffles) and all(
            payload is current for (_, payload), current in zip(self.shuffle_payloads, self.shuffles)
        ):
            return self.shuffle_payloads
        return [(f"controlComponentShufflePayloads[{index}]", payload) for index, payload in enumerate(self.shuffles)]

    def _vcs_by_id(self) -> dict[str, dict[str, Any]]:
        return {ctx["verificationCardSetId"]: ctx for ctx in self._vcs_contexts()}

    def _vcs_by_ballot_box(self) -> dict[str, dict[str, Any]]:
        return {ctx["ballotBoxId"]: ctx for ctx in self._vcs_contexts()}

    def _delta_for_ballot_box(self, ctx: dict[str, Any]) -> int:
        return get_delta(ctx["primesMappingTable"])

    def _psi_for_ballot_box(self, ctx: dict[str, Any]) -> int:
        return get_psi(ctx["primesMappingTable"])
