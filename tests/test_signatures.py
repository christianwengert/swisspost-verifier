from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from swisspost_independent_verifier.crypto import GqGroup, recursive_hash
from swisspost_independent_verifier.dataset import FixtureDataset
from swisspost_independent_verifier.result import VerificationReport
from swisspost_independent_verifier.signatures import (
    TrustStore,
    control_component_public_keys_signed_data,
    control_component_ballot_box_signed_data,
    control_component_shuffle_signed_data,
    election_event_context_signed_data,
    DSIG_NS,
    EXCLUSIVE_C14N,
    ENVELOPED_SIGNATURE,
    RSA_PSS_SHA256_SIGNATURE_URIS,
    setup_public_keys_signed_data,
    setup_tally_data_signed_data,
    SHA256_DIGEST_URIS,
    signed_message_digest,
)
from lxml import etree

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "e-voting/secure-data-manager/secure-data-manager-backend/src/test/resources/MixOfflineFacadeTest"


class SignatureTests(unittest.TestCase):
    def test_trust_store_verifies_recursive_hash_signature(self):
        private_key, certificate = make_certificate()
        with tempfile.TemporaryDirectory() as dirname:
            cert_path = Path(dirname) / "sdm_config.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            trust_store = TrustStore.from_directory(dirname)

            message = "payload-digest"
            context = ("public keys", "setup", "EE")
            signature = sign(private_key, signed_message_digest(message, context))

            self.assertTrue(
                trust_store.verify_signature(
                    "sdm_config",
                    message,
                    context,
                    {"signatureContents": base64.b64encode(signature).decode("ascii")},
                    at=datetime.now(timezone.utc),
                )
            )
            self.assertFalse(
                trust_store.verify_signature(
                    "sdm_config",
                    message,
                    ("wrong", "context"),
                    {"signatureContents": base64.b64encode(signature).decode("ascii")},
                    at=datetime.now(timezone.utc),
                )
            )

    def test_setup_payload_signature_digests_change_when_payload_changes(self):
        context_payload, setup_keys, tally_data, _, _ = load_fixture_payloads()
        group = GqGroup.from_json(setup_keys["encryptionGroup"])

        original = setup_public_keys_signed_data(group, setup_keys)
        mutated = json.loads(json.dumps(setup_keys))
        mutated["setupComponentPublicKeys"]["choiceReturnCodesEncryptionPublicKey"][0] = "AQ=="

        self.assertNotEqual(original, setup_public_keys_signed_data(group, mutated))

        tally_original = setup_tally_data_signed_data(group, tally_data)
        tally_mutated = json.loads(json.dumps(tally_data))
        tally_mutated["verificationCardIds"][0] = "F" * 32
        self.assertNotEqual(tally_original, setup_tally_data_signed_data(group, tally_mutated))

        context_original = election_event_context_signed_data(group, context_payload)
        context_mutated = json.loads(json.dumps(context_payload))
        context_mutated["electionEventContext"]["maximumNumberOfSelections"] += 1
        self.assertNotEqual(context_original, election_event_context_signed_data(group, context_mutated))

        component_payload = {
            "encryptionGroup": setup_keys["encryptionGroup"],
            "electionEventId": setup_keys["electionEventId"],
            "controlComponentPublicKeys": json.loads(json.dumps(setup_keys["setupComponentPublicKeys"]["combinedControlComponentPublicKeys"][0])),
            "signature": {"signatureContents": ""},
        }
        component_original = control_component_public_keys_signed_data(group, component_payload)
        component_mutated = json.loads(json.dumps(component_payload))
        component_mutated["controlComponentPublicKeys"]["ccmjElectionPublicKey"][0] = "AQ=="
        self.assertNotEqual(component_original, control_component_public_keys_signed_data(group, component_mutated))

    def test_tally_payload_signature_digests_change_when_payload_changes(self):
        _, _, _, ballot_boxes, shuffles = load_fixture_payloads()
        group = GqGroup.from_json(ballot_boxes[0]["encryptionGroup"])

        ballot_original = control_component_ballot_box_signed_data(group, ballot_boxes[0])
        ballot_mutated = json.loads(json.dumps(ballot_boxes[0]))
        ballot_mutated["confirmedEncryptedVotes"][0]["contextIds"]["verificationCardId"] = "F" * 32
        self.assertNotEqual(ballot_original, control_component_ballot_box_signed_data(group, ballot_mutated))

        shuffle_original = control_component_shuffle_signed_data(group, shuffles[0])
        shuffle_mutated = json.loads(json.dumps(shuffles[0]))
        shuffle_mutated["verifiableDecryptions"]["decryptionProofs"][0]["e"] = "AA=="
        self.assertNotEqual(shuffle_original, control_component_shuffle_signed_data(group, shuffle_mutated))

    def test_signed_payload_data_matches_recursive_hash_base64_shape(self):
        _, setup_keys, _, _, _ = load_fixture_payloads()
        group = GqGroup.from_json(setup_keys["encryptionGroup"])
        digest = setup_public_keys_signed_data(group, setup_keys)

        self.assertEqual(32, len(base64.b64decode(digest)))
        self.assertNotEqual(base64.b64encode(recursive_hash(digest)).decode("ascii"), digest)

    def test_dataset_setup_signature_checks_with_supplied_trust_store(self):
        private_key, certificate = make_certificate()
        with tempfile.TemporaryDirectory() as dirname:
            cert_path = Path(dirname) / "sdm_config.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            trust_store = TrustStore.from_directory(dirname)
            dataset = FixtureDataset(FIXTURE, trust_store=trust_store)
            group = GqGroup.from_json(dataset.setup_public_keys["encryptionGroup"])
            ee = dataset.election_event_context["electionEventContext"]["electionEventId"]

            resign(
                private_key,
                dataset.setup_public_keys,
                setup_public_keys_signed_data(group, dataset.setup_public_keys),
                ("public keys", "setup", dataset.setup_public_keys["electionEventId"]),
            )
            resign(
                private_key,
                dataset.setup_tally_data,
                setup_tally_data_signed_data(group, dataset.setup_tally_data),
                ("tally data", dataset.setup_tally_data["electionEventId"], dataset.setup_tally_data["verificationCardSetId"]),
            )
            resign(
                private_key,
                dataset.election_event_context,
                election_event_context_signed_data(group, dataset.election_event_context),
                ("election event context", ee),
            )

            report = VerificationReport("Signatures")
            dataset._check_setup_payload_signatures(report)

            self.assertTrue(report.ok, report.failing())

    def test_xml_signature_verifier_accepts_valid_canton_config_signature(self):
        private_key, certificate = make_certificate("canton")
        with tempfile.TemporaryDirectory() as dirname:
            cert_path = Path(dirname) / "canton.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            xml_path = Path(dirname) / "configuration-anonymized.xml"
            xml_path.write_bytes(make_signed_config_xml(private_key))

            trust_store = TrustStore.from_directory(dirname)
            ok, detail = trust_store.verify_xml_signature("canton", xml_path, signature_location="root-last-child")

            self.assertTrue(ok, detail)

    def test_xml_signature_verifier_rejects_tampered_digest(self):
        private_key, certificate = make_certificate("canton")
        with tempfile.TemporaryDirectory() as dirname:
            cert_path = Path(dirname) / "canton.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            xml_path = Path(dirname) / "configuration-anonymized.xml"
            xml_text = make_signed_config_xml(private_key).decode("utf-8").replace("<config:voterTotal>43</config:voterTotal>", "<config:voterTotal>44</config:voterTotal>")
            xml_path.write_text(xml_text, encoding="utf-8")

            trust_store = TrustStore.from_directory(dirname)
            ok, detail = trust_store.verify_xml_signature("canton", xml_path, signature_location="root-last-child")

            self.assertFalse(ok)
            self.assertEqual("digest mismatch", detail)

    def test_dataset_uses_xml_signature_verification_for_canton_config(self):
        private_key, certificate = make_certificate("canton")
        with tempfile.TemporaryDirectory() as dirname:
            cert_path = Path(dirname) / "canton.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            dataset = FixtureDataset(FIXTURE, trust_store=TrustStore.from_directory(dirname))
            xml_path = Path(dirname) / "configuration-anonymized.xml"
            xml_path.write_bytes(make_signed_config_xml(private_key))
            dataset.configuration_xml_path = xml_path

            report = VerificationReport("Signatures")
            dataset._check_setup_payload_signatures(report)

            check = next(check for check in report.checks if check.check_id == "2.01")
            self.assertTrue(check.ok, check.detail)

    def test_xml_signature_verifier_accepts_ech_signature_in_extensions(self):
        private_key, certificate = make_certificate("sdm_tally")
        with tempfile.TemporaryDirectory() as dirname:
            cert_path = Path(dirname) / "sdm_tally.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            xml_path = Path(dirname) / "eCH-0222.xml"
            xml_path.write_bytes(make_signed_ech_xml(private_key))

            trust_store = TrustStore.from_directory(dirname)
            ok, detail = trust_store.verify_xml_signature("sdm_tally", xml_path, signature_location="extensions-child")

            self.assertTrue(ok, detail)

    def test_xml_signature_verifier_rejects_invalid_repository_fixture(self):
        _, certificate = make_certificate("canton")
        with tempfile.TemporaryDirectory() as dirname:
            cert_path = Path(dirname) / "canton.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

            trust_store = TrustStore.from_directory(dirname)
            ok, detail = trust_store.verify_xml_signature(
                "canton",
                ROOT / "e-voting/tools/xml-signature/src/test/resources/configuration-anonymized-invalid-signature.xml",
                signature_location="root-last-child",
            )

            self.assertFalse(ok)
            self.assertEqual("digest mismatch", detail)


def load_fixture_payloads():
    return (
        json.loads((FIXTURE / "electionEventContextPayload.json").read_text(encoding="utf-8")),
        json.loads((FIXTURE / "setupComponentPublicKeysPayload.json").read_text(encoding="utf-8")),
        json.loads((FIXTURE / "setupComponentTallyDataPayload.json").read_text(encoding="utf-8")),
        json.loads((FIXTURE / "controlComponentBallotBoxPayloads.json").read_text(encoding="utf-8")),
        json.loads((FIXTURE / "controlComponentShufflePayloads.json").read_text(encoding="utf-8")),
    )


def make_certificate(common_name: str = "sdm_config"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate


def sign(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def resign(private_key, payload: dict, message: str, context: tuple) -> None:
    payload["signature"] = {
        "signatureContents": base64.b64encode(sign(private_key, signed_message_digest(message, context))).decode("ascii")
    }


def make_signed_config_xml(private_key) -> bytes:
    config_ns = "http://www.evoting.ch/xmlns/config/7"
    root = etree.Element(f"{{{config_ns}}}configuration", nsmap={"config": config_ns})
    header = etree.SubElement(root, f"{{{config_ns}}}header")
    etree.SubElement(header, f"{{{config_ns}}}voterTotal").text = "43"
    append_xml_signature(root, private_key)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def make_signed_ech_xml(private_key) -> bytes:
    root = etree.Element("ech0222")
    raw_data = etree.SubElement(root, "rawData")
    extensions = etree.SubElement(raw_data, "extensions")
    etree.SubElement(raw_data, "ballot").text = "demo"
    append_xml_signature(root, private_key, signature_parent=extensions)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def append_xml_signature(root, private_key, signature_parent=None) -> None:
    digest = hashlib.sha256(etree.tostring(root, method="c14n", exclusive=True, with_comments=False)).digest()
    signature = etree.Element(f"{{{DSIG_NS}}}Signature", nsmap={"ds": DSIG_NS})
    signed_info = etree.SubElement(signature, f"{{{DSIG_NS}}}SignedInfo")
    etree.SubElement(signed_info, f"{{{DSIG_NS}}}CanonicalizationMethod", Algorithm=EXCLUSIVE_C14N)
    etree.SubElement(signed_info, f"{{{DSIG_NS}}}SignatureMethod", Algorithm=next(iter(RSA_PSS_SHA256_SIGNATURE_URIS)))
    reference = etree.SubElement(signed_info, f"{{{DSIG_NS}}}Reference", URI="")
    transforms = etree.SubElement(reference, f"{{{DSIG_NS}}}Transforms")
    etree.SubElement(transforms, f"{{{DSIG_NS}}}Transform", Algorithm=ENVELOPED_SIGNATURE)
    etree.SubElement(reference, f"{{{DSIG_NS}}}DigestMethod", Algorithm=next(iter(SHA256_DIGEST_URIS)))
    etree.SubElement(reference, f"{{{DSIG_NS}}}DigestValue").text = base64.b64encode(digest).decode("ascii")
    signed_info_c14n = etree.tostring(signed_info, method="c14n", exclusive=True, with_comments=False)
    signature_value = private_key.sign(
        signed_info_c14n,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    etree.SubElement(signature, f"{{{DSIG_NS}}}SignatureValue").text = base64.b64encode(signature_value).decode("ascii")
    (signature_parent if signature_parent is not None else root).append(signature)


if __name__ == "__main__":
    unittest.main()
