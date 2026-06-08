from __future__ import annotations

import base64
import copy
import hashlib
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from .crypto import GqGroup, b64_to_int, recursive_hash

try:
    from lxml import etree
except ModuleNotFoundError:
    deps_path = Path(__file__).resolve().parents[1] / ".deps"
    if deps_path.exists():
        sys.path.insert(0, str(deps_path))
    try:
        from lxml import etree
    except ModuleNotFoundError:
        etree = None


DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
SHA256_DIGEST_URIS = {
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha256",
}
RSA_SHA256_SIGNATURE_URIS = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
}
RSA_PSS_SHA256_SIGNATURE_URIS = {
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
    "http://www.w3.org/2007/05/xmldsig-more#rsa-pss",
    "http://www.w3.org/2007/05/xmldsig-more#rsa-pss-sha256",
}


def signed_message_digest(message: Any, context: Sequence[Any]) -> bytes:
    return recursive_hash(message, tuple(context))


def signed_payload_data(message: Any) -> Any:
    return message


@dataclass(frozen=True)
class CertificateEntry:
    certificate: x509.Certificate

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        public_key = self.certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Swiss Post signatures use RSA public keys")
        return public_key

    def valid_at(self, at: datetime) -> bool:
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        return self.certificate.not_valid_before_utc <= at < self.certificate.not_valid_after_utc


@dataclass(frozen=True)
class TrustStore:
    certificates: dict[str, CertificateEntry]

    @classmethod
    def from_directory(cls, path: str | Path) -> "TrustStore":
        certificates: dict[str, CertificateEntry] = {}
        for cert_path in sorted(Path(path).rglob("*")):
            if cert_path.suffix.lower() not in {".pem", ".crt", ".cer", ".der"}:
                continue
            data = cert_path.read_bytes()
            try:
                certificate = x509.load_pem_x509_certificate(data)
            except ValueError:
                certificate = x509.load_der_x509_certificate(data)
            entry = CertificateEntry(certificate)
            for signer_id in _certificate_signer_ids(cert_path, certificate):
                certificates[signer_id] = entry
        for keystore_path in sorted(Path(path).rglob("*.p12")):
            signer_id = _signer_id_from_pkcs12_path(keystore_path)
            password = _pkcs12_password(keystore_path, signer_id)
            _, certificate, additional_certificates = pkcs12.load_key_and_certificates(keystore_path.read_bytes(), password)
            certificate = certificate or (additional_certificates[0] if additional_certificates else None)
            if certificate is not None:
                entry = CertificateEntry(certificate)
                for alias in {signer_id, _certificate_common_name(certificate)} - {""}:
                    certificates[alias] = entry
        return cls(certificates)

    def verify_signature(
        self,
        signer_id: str,
        message: Any,
        context: Sequence[Any],
        signature: str | dict[str, str],
        *,
        at: datetime | None = None,
    ) -> bool:
        entry = self.certificates.get(signer_id)
        if entry is None:
            return False
        at = at or datetime.now(timezone.utc)
        if not entry.valid_at(at):
            return False
        signature_bytes = base64.b64decode(signature["signatureContents"] if isinstance(signature, dict) else signature)
        digest = signed_message_digest(message, context)
        try:
            entry.public_key.verify(
                signature_bytes,
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False
        return True

    def verify_xml_signature(
        self,
        signer_id: str,
        xml_path: str | Path,
        *,
        at: datetime | None = None,
        signature_location: str = "any",
    ) -> tuple[bool, str]:
        entry = self.certificates.get(signer_id)
        if entry is None:
            return False, f"signer={signer_id}"
        at = at or datetime.now(timezone.utc)
        if not entry.valid_at(at):
            return False, f"signer certificate not valid at {at.isoformat()}"
        try:
            return verify_xml_signature(Path(xml_path), entry.public_key, signature_location=signature_location)
        except (OSError, ValueError, TypeError) as exc:
            return False, str(exc)


def verify_xml_signature(
    xml_path: str | Path,
    public_key: rsa.RSAPublicKey,
    *,
    signature_location: str = "any",
) -> tuple[bool, str]:
    if etree is None:
        return False, "lxml dependency not installed"

    parser = etree.XMLParser(remove_blank_text=False, resolve_entities=False, no_network=True, huge_tree=True)
    tree = etree.parse(str(xml_path), parser)
    root = tree.getroot()
    signatures = root.xpath(".//ds:Signature", namespaces={"ds": DSIG_NS})
    if len(signatures) != 1:
        return False, f"expected exactly one XML signature, found {len(signatures)}"
    signature = signatures[0]
    if signature_location == "root-last-child" and (len(root) == 0 or root[-1] is not signature):
        return False, "signature is not the last child of the root element"
    if signature_location == "extensions-child":
        parent = signature.getparent()
        if parent is None or etree.QName(parent).localname not in {"extension", "extensions"}:
            return False, "signature is not embedded in an extension element"

    signed_info = _single_xml_child(signature, "SignedInfo")
    signature_value = _single_xml_child_text(signature, "SignatureValue")
    canonicalization_method = _single_xml_child(signed_info, "CanonicalizationMethod").get("Algorithm")
    if canonicalization_method != EXCLUSIVE_C14N:
        return False, f"unsupported canonicalization method {canonicalization_method}"
    signature_method = _single_xml_child(signed_info, "SignatureMethod").get("Algorithm")
    reference = _single_xml_child(signed_info, "Reference")
    if reference.get("URI") != "":
        return False, f"unsupported reference URI {reference.get('URI')!r}"
    transforms = _single_xml_child(reference, "Transforms")
    transform_algorithms = [element.get("Algorithm") for element in _xml_children(transforms, "Transform")]
    if transform_algorithms != [ENVELOPED_SIGNATURE]:
        return False, f"unsupported transforms {transform_algorithms}"
    digest_method = _single_xml_child(reference, "DigestMethod").get("Algorithm")
    if digest_method not in SHA256_DIGEST_URIS:
        return False, f"unsupported digest method {digest_method}"

    expected_digest = _b64decode_text(_single_xml_child_text(reference, "DigestValue"))
    transformed_root = copy.deepcopy(root)
    transformed_signatures = transformed_root.xpath(".//ds:Signature", namespaces={"ds": DSIG_NS})
    if len(transformed_signatures) != 1:
        return False, "could not apply enveloped-signature transform"
    transformed_signature = transformed_signatures[0]
    transformed_signature.getparent().remove(transformed_signature)
    canonical_document = etree.tostring(transformed_root, method="c14n", exclusive=False, with_comments=False)
    actual_digest = hashlib.sha256(canonical_document).digest()
    if actual_digest != expected_digest:
        return False, "digest mismatch"

    canonical_signed_info = etree.tostring(signed_info, method="c14n", exclusive=True, with_comments=False)
    signature_bytes = _b64decode_text(signature_value)
    try:
        if signature_method in RSA_PSS_SHA256_SIGNATURE_URIS:
            public_key.verify(
                signature_bytes,
                canonical_signed_info,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        elif signature_method in RSA_SHA256_SIGNATURE_URIS:
            public_key.verify(signature_bytes, canonical_signed_info, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False, f"unsupported signature method {signature_method}"
    except InvalidSignature:
        return False, "signature mismatch"
    return True, ""


def _signer_id_from_pkcs12_path(path: Path) -> str:
    stem = path.stem
    prefix = "local_direct_trust_keystore_"
    if stem.startswith(prefix):
        return stem[len(prefix):]
    return stem


def _certificate_signer_ids(path: Path, certificate: x509.Certificate) -> set[str]:
    signer_ids = {path.stem, _certificate_common_name(certificate)}
    prefix = "local_direct_trust_keystore_"
    if path.stem.startswith(prefix):
        signer_ids.add(path.stem[len(prefix):])
    return signer_ids - {""}


def _certificate_common_name(certificate: x509.Certificate) -> str:
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return common_names[0].value if common_names else ""


def _pkcs12_password(path: Path, signer_id: str) -> bytes | None:
    candidates = [
        path.with_name(f"local_direct_trust_pw_{signer_id}.txt"),
        path.with_suffix(".txt"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.read_text(encoding="utf-8").strip().encode("utf-8")
    return None


def setup_public_keys_signed_data(group: GqGroup, payload: dict[str, Any]) -> str:
    setup = payload["setupComponentPublicKeys"]
    component_public_keys = []
    for component in sorted(setup["combinedControlComponentPublicKeys"], key=lambda item: item["nodeId"]):
        component_public_keys.append(
            (
                component["nodeId"],
                _b64_vector(component["ccrjChoiceReturnCodesEncryptionPublicKey"]),
                tuple(_proof_tuple(proof) for proof in component["ccrjSchnorrProofs"]),
                _b64_vector(component["ccmjElectionPublicKey"]),
                tuple(_proof_tuple(proof) for proof in component["ccmjSchnorrProofs"]),
            )
        )
    public_keys = (
        tuple(component_public_keys),
        _b64_vector(setup["electoralBoardPublicKey"]),
        tuple(_proof_tuple(proof) for proof in setup["electoralBoardSchnorrProofs"]),
        _b64_vector(setup["electionPublicKey"]),
        _b64_vector(setup["choiceReturnCodesEncryptionPublicKey"]),
    )
    return signed_payload_data((group.as_hash_tuple(), payload["electionEventId"], public_keys))


def control_component_public_keys_signed_data(group: GqGroup, payload: dict[str, Any]) -> str:
    public_keys = payload["controlComponentPublicKeys"]
    h_public_keys = (
        public_keys["nodeId"],
        _b64_vector(public_keys["ccrjChoiceReturnCodesEncryptionPublicKey"]),
        tuple(_proof_tuple(proof) for proof in public_keys["ccrjSchnorrProofs"]),
        _b64_vector(public_keys["ccmjElectionPublicKey"]),
        tuple(_proof_tuple(proof) for proof in public_keys["ccmjSchnorrProofs"]),
    )
    return signed_payload_data((group.as_hash_tuple(), payload["electionEventId"], h_public_keys))


def setup_tally_data_signed_data(group: GqGroup, payload: dict[str, Any]) -> str:
    return signed_payload_data(
        (
            group.as_hash_tuple(),
            payload["electionEventId"],
            payload["verificationCardSetId"],
            tuple(payload["verificationCardIds"]),
            payload["ballotBoxDefaultTitle"],
            tuple(tuple(_b64_vector(keys)) for keys in payload["verificationCardPublicKeys"]),
        )
    )


def election_event_context_signed_data(group: GqGroup, payload: dict[str, Any]) -> str:
    context = payload["electionEventContext"]
    verification_card_sets = []
    for vcs_ctx in sorted(context["verificationCardSetContexts"], key=lambda item: item["verificationCardSetId"]):
        hp_table = tuple(
            (
                entry["actualVotingOption"],
                entry["encodedVotingOption"],
                entry["semanticInformation"],
                entry["correctnessInformation"],
            )
            for entry in vcs_ctx["primesMappingTable"]["pTable"]
        )
        verification_card_sets.append(
            (
                vcs_ctx["verificationCardSetId"],
                vcs_ctx["verificationCardSetAlias"],
                vcs_ctx["verificationCardSetDescription"],
                vcs_ctx["ballotBoxId"],
                vcs_ctx["ballotBoxStartTime"],
                vcs_ctx["ballotBoxFinishTime"],
                "true" if vcs_ctx["testBallotBox"] else "false",
                vcs_ctx["numberOfEligibleVoters"],
                vcs_ctx["gracePeriod"],
                (hp_table,),
                tuple(vcs_ctx["domainsOfInfluence"]),
            )
        )
    h_context = (
        group.as_hash_tuple(),
        context["electionEventId"],
        context["electionEventAlias"],
        context["electionEventDescription"],
        tuple(verification_card_sets),
        context["startTime"],
        context["finishTime"],
        context["maximumNumberOfVotingOptions"],
        context["maximumNumberOfSelections"],
        context["maximumNumberOfWriteInsPlusOne"],
    )
    return signed_payload_data(
        (
            group.as_hash_tuple(),
            payload["seed"],
            tuple(payload["smallPrimes"]),
            h_context,
            payload.get("tenantId", ""),
        )
    )


def control_component_ballot_box_signed_data(group: GqGroup, payload: dict[str, Any]) -> str:
    votes = []
    for vote in sorted(payload["confirmedEncryptedVotes"], key=lambda item: item["contextIds"]["verificationCardId"]):
        ids = vote["contextIds"]
        votes.append(
            (
                (ids["electionEventId"], ids["verificationCardSetId"], ids["verificationCardId"]),
                _ciphertext_tuple(vote["encryptedVote"]),
                _ciphertext_tuple(vote["exponentiatedEncryptedVote"]),
                _ciphertext_tuple(vote["encryptedPartialChoiceReturnCodes"]),
                _proof_tuple(vote["exponentiationProof"]),
                _proof_tuple(vote["plaintextEqualityProof"]),
            )
        )
    return signed_payload_data(
        (
            group.as_hash_tuple(),
            payload["electionEventId"],
            payload["ballotBoxId"],
            payload["nodeId"],
            tuple(votes),
        )
    )


def control_component_shuffle_signed_data(group: GqGroup, payload: dict[str, Any]) -> str:
    shuffle = payload["verifiableShuffle"]
    decryptions = payload["verifiableDecryptions"]
    h_shuffle = (
        tuple(_ciphertext_tuple(ciphertext) for ciphertext in shuffle["shuffledCiphertexts"]),
        _shuffle_argument_tuple(shuffle["shuffleArgument"]),
    )
    h_decryption = (
        tuple(_ciphertext_tuple(ciphertext) for ciphertext in decryptions["ciphertexts"]),
        tuple(_proof_tuple(proof) for proof in decryptions["decryptionProofs"]),
    )
    return signed_payload_data((group.as_hash_tuple(), payload["electionEventId"], payload["ballotBoxId"], payload["nodeId"], h_shuffle, h_decryption))


def tally_component_shuffle_signed_data(payload: dict[str, Any]) -> Any:
    shuffle = payload["verifiableShuffle"]
    plaintext_decryption = payload["verifiablePlaintextDecryption"]
    group = GqGroup.from_json(payload["encryptionGroup"])
    h_shuffle = (
        tuple(_ciphertext_tuple(ciphertext) for ciphertext in shuffle["shuffledCiphertexts"]),
        _shuffle_argument_tuple(shuffle["shuffleArgument"]),
    )
    h_decryption = (
        tuple(tuple(_b64_vector(message["message"])) for message in plaintext_decryption["decryptedVotes"]),
        tuple(_proof_tuple(proof) for proof in plaintext_decryption["decryptionProofs"]),
    )
    return signed_payload_data((group.as_hash_tuple(), payload["electionEventId"], payload["ballotBoxId"], h_shuffle, h_decryption))


def tally_component_votes_signed_data(group: GqGroup, payload: dict[str, Any]) -> str:
    return signed_payload_data(
        (
            group.as_hash_tuple(),
            payload["electionEventId"],
            payload["ballotBoxId"],
            tuple(tuple(vote) for vote in payload["decryptedVotes"]),
            tuple(tuple(vote) for vote in payload["decodedVotes"]),
            tuple(tuple(write_ins) for write_ins in payload["decodedWriteIns"]),
        )
    )


def _xml_children(element: Any, local_name: str) -> list[Any]:
    return [child for child in element if etree.QName(child).namespace == DSIG_NS and etree.QName(child).localname == local_name]


def _single_xml_child(element: Any, local_name: str) -> Any:
    children = _xml_children(element, local_name)
    if len(children) != 1:
        raise ValueError(f"expected one ds:{local_name}, found {len(children)}")
    return children[0]


def _single_xml_child_text(element: Any, local_name: str) -> str:
    child = _single_xml_child(element, local_name)
    return child.text or ""


def _b64decode_text(value: str) -> bytes:
    return base64.b64decode("".join(value.split()), validate=True)


def _b64_vector(values: Sequence[str]) -> tuple[int, ...]:
    return tuple(b64_to_int(value) for value in values)


def _ciphertext_tuple(ciphertext: dict[str, Any]) -> tuple[int, ...]:
    return (b64_to_int(ciphertext["gamma"]), *_b64_vector(ciphertext["phis"]))


def _proof_tuple(proof: dict[str, Any]) -> tuple[int, Any]:
    e = b64_to_int(proof.get("e", proof.get("_e")))
    z = proof.get("z", proof.get("_z"))
    if isinstance(z, str):
        return e, b64_to_int(z)
    return e, tuple(b64_to_int(item) for item in z)


def _shuffle_argument_tuple(argument: dict[str, Any]) -> tuple[Any, ...]:
    return (
        _b64_vector(argument["c_A"]),
        _b64_vector(argument["c_B"]),
        _product_argument_tuple(argument["productArgument"]),
        _multi_exponentiation_argument_tuple(argument["multiExponentiationArgument"]),
    )


def _product_argument_tuple(argument: dict[str, Any]) -> tuple[Any, ...]:
    if "c_b" not in argument:
        return (_single_value_product_argument_tuple(argument["singleValueProductArgument"]),)
    return (
        b64_to_int(argument["c_b"]),
        _hadamard_argument_tuple(argument["hadamardArgument"]),
        _single_value_product_argument_tuple(argument["singleValueProductArgument"]),
    )


def _hadamard_argument_tuple(argument: dict[str, Any]) -> tuple[Any, ...]:
    return _b64_vector(argument["c_b"]), _zero_argument_tuple(argument["zeroArgument"])


def _zero_argument_tuple(argument: dict[str, Any]) -> tuple[Any, ...]:
    return (
        b64_to_int(argument["c_A_0"]),
        b64_to_int(argument["c_B_m"]),
        _b64_vector(argument["c_d"]),
        _b64_vector(argument["a_prime"]),
        _b64_vector(argument["b_prime"]),
        b64_to_int(argument["r_prime"]),
        b64_to_int(argument["s_prime"]),
        b64_to_int(argument["t_prime"]),
    )


def _single_value_product_argument_tuple(argument: dict[str, Any]) -> tuple[Any, ...]:
    return (
        b64_to_int(argument["c_d"]),
        b64_to_int(argument["c_delta"]),
        b64_to_int(argument["c_Delta"]),
        _b64_vector(argument["a_tilde"]),
        _b64_vector(argument["b_tilde"]),
        b64_to_int(argument["r_tilde"]),
        b64_to_int(argument["s_tilde"]),
    )


def _multi_exponentiation_argument_tuple(argument: dict[str, Any]) -> tuple[Any, ...]:
    return (
        b64_to_int(argument["c_A_0"]),
        _b64_vector(argument["c_B"]),
        tuple(_ciphertext_tuple(ciphertext) for ciphertext in argument["E"]),
        _b64_vector(argument["a"]),
        b64_to_int(argument["r"]),
        b64_to_int(argument["b"]),
        b64_to_int(argument["s"]),
        b64_to_int(argument["tau"]),
    )
