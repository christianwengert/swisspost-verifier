from __future__ import annotations

import base64
import hashlib
import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Iterable, Sequence


@dataclass(frozen=True)
class GqGroup:
    p: int
    q: int
    g: int

    @classmethod
    def from_json(cls, data: dict[str, str]) -> "GqGroup":
        return cls(b64_to_int(data["p"]), b64_to_int(data["q"]), b64_to_int(data["g"]))

    def as_hash_tuple(self) -> tuple[int, int, int]:
        return self.p, self.q, self.g


def b64_to_int(value: str) -> int:
    return int.from_bytes(base64.b64decode(value), "big")


def int_to_b64(value: int) -> str:
    return base64.b64encode(int_to_bytes(value)).decode("ascii")


def int_to_bytes(value: int) -> bytes:
    if value < 0:
        raise ValueError("expected a non-negative integer")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def byte_array_to_int(value: bytes) -> int:
    return int.from_bytes(value, "big")


def recursive_hash(*values: Any) -> bytes:
    if not values:
        raise ValueError("RecursiveHash requires at least one value")
    if len(values) > 1:
        return recursive_hash(tuple(values))

    value = values[0]
    if isinstance(value, bytes):
        payload = b"\x00" + value
    elif isinstance(value, int):
        if value < 0:
            raise ValueError("RecursiveHash integers must be non-negative")
        payload = b"\x01" + int_to_bytes(value)
    elif isinstance(value, str):
        payload = b"\x02" + value.encode("utf-8")
    elif isinstance(value, (list, tuple)):
        payload = b"\x03" + b"".join(recursive_hash(item) for item in value)
    else:
        raise TypeError(f"unsupported RecursiveHash value: {type(value).__name__}")
    return hashlib.sha3_256(payload).digest()


def recursive_hash_to_int(*values: Any) -> int:
    return byte_array_to_int(recursive_hash(*values))


def group_member(group: GqGroup, value: int, *, allow_one: bool = True) -> bool:
    if not 1 <= value < group.p:
        return False
    if not allow_one and value == 1:
        return False
    return pow(value, group.q, group.p) == 1


def is_small_prime(value: int) -> bool:
    if value == 1:
        return False
    if value in (2, 3):
        return True
    if value % 2 == 0 or value % 3 == 0:
        return False
    divisor = 5
    while divisor * divisor <= value:
        if value % divisor == 0 or value % (divisor + 2) == 0:
            return False
        divisor += 6
    return True


def get_small_prime_group_members(group: GqGroup, count: int) -> list[int]:
    if group.g not in (2, 3):
        raise ValueError("GetSmallPrimeGroupMembers requires generator 2 or 3")
    if count <= 0 or count >= 10_000:
        raise ValueError("GetSmallPrimeGroupMembers count must be in [1, 10000)")
    members: list[int] = []
    current = 5
    while len(members) < count and current < group.p:
        if is_small_prime(current) and _small_prime_quadratic_residue(group.p, current):
            members.append(current)
        current += 2
    if len(members) != count:
        raise ValueError("not enough small prime group members")
    return members


@lru_cache(maxsize=16)
def get_encryption_parameters(seed: str, bit_length: int = 3072, security_strength: int = 128) -> GqGroup:
    if bit_length % 8 != 0:
        raise ValueError("GetEncryptionParameters requires a byte-aligned p bit length")
    if security_strength <= 0 or security_strength % 2 != 0:
        raise ValueError("GetEncryptionParameters requires an even positive security strength")

    q_hat = hashlib.shake_256(seed.encode("utf-8")).digest(bit_length // 8)
    q_prime = int.from_bytes(b"\x02" + q_hat, "big") >> 3
    q = q_prime - (q_prime % 6) + 5
    small_primes = _first_primes_excluding_2_3(2048)
    residues = [q % prime for prime in small_primes]
    delta = 0

    while True:
        while True:
            delta += 6
            i = 0
            while i < len(small_primes):
                prime = small_primes[i]
                residue = residues[i] + delta
                if residue % prime == 0 or (2 * residue + 1) % prime == 0:
                    delta += 6
                    i = 0
                else:
                    i += 1
            candidate_q = q + delta
            if _miller_rabin(candidate_q, 1) and _miller_rabin(2 * candidate_q + 1, 1):
                break

        candidate_q = q + delta
        candidate_p = 2 * candidate_q + 1
        rounds = security_strength // 2
        if _miller_rabin(candidate_q, rounds) and _miller_rabin(candidate_p, rounds):
            generator = 2 if pow(2, candidate_q, candidate_p) == 1 else 3
            return GqGroup(candidate_p, candidate_q, generator)


@lru_cache(maxsize=8)
def _first_primes_excluding_2_3(count: int) -> tuple[int, ...]:
    primes: list[int] = []
    candidate = 5
    while len(primes) < count:
        if is_small_prime(candidate):
            primes.append(candidate)
        candidate += 2
    return tuple(primes)


@lru_cache(maxsize=8)
def _miller_rabin_bases(rounds: int) -> tuple[int, ...]:
    bases = [2, 3]
    candidate = 5
    while len(bases) < rounds:
        if is_small_prime(candidate):
            bases.append(candidate)
        candidate += 2
    return tuple(bases)


def _miller_rabin(value: int, rounds: int) -> bool:
    if value < 2:
        return False
    if value in (2, 3):
        return True
    if value % 2 == 0:
        return False

    d = value - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for base in _miller_rabin_bases(rounds):
        if base >= value:
            continue
        x = pow(base, d, value)
        if x == 1 or x == value - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, value)
            if x == value - 1:
                break
        else:
            return False
    return True


def _small_prime_quadratic_residue(modulus: int, prime: int) -> bool:
    if prime == 2:
        return modulus % 8 in (1, 7)
    if prime == 3:
        return modulus % 12 in (1, 11)
    residue = modulus % prime
    if residue == 0:
        return False
    symbol = pow(residue, (prime - 1) // 2, prime)
    if prime % 4 == 3 and modulus % 4 == 3:
        symbol = (-symbol) % prime
    return symbol == 1


def _proof_e(proof: dict[str, Any]) -> int:
    return b64_to_int(proof.get("e", proof.get("_e")))


def _proof_z_scalar(proof: dict[str, Any]) -> int:
    return b64_to_int(proof.get("z", proof.get("_z")))


def _proof_z_vector(proof: dict[str, Any]) -> list[int]:
    z = proof.get("z", proof.get("_z"))
    if isinstance(z, str):
        return [b64_to_int(z)]
    return [b64_to_int(item) for item in z]


def _haux(name: str, iaux: Sequence[str] | None) -> tuple[Any, ...]:
    if iaux:
        return name, list(iaux)
    return (name,)


def _mod_inverse_power(base: int, exponent: int, modulus: int) -> int:
    return pow(base, (-exponent) % (modulus - 1), modulus)


def verify_schnorr(group: GqGroup, proof: dict[str, Any], statement: int, iaux: Sequence[str] | None = None) -> bool:
    e = _proof_e(proof)
    z = _proof_z_scalar(proof)
    if not (0 <= e < group.q and 0 <= z < group.q and group_member(group, statement, allow_one=False)):
        return False
    x = pow(group.g, z, group.p)
    c_prime = (x * pow(statement, -e, group.p)) % group.p
    expected = recursive_hash_to_int(group.as_hash_tuple(), statement, c_prime, _haux("SchnorrProof", iaux))
    return e == expected


def verify_exponentiation(
    group: GqGroup,
    bases: Sequence[int],
    statement: Sequence[int],
    proof: dict[str, Any],
    iaux: Sequence[str] | None = None,
) -> bool:
    e = _proof_e(proof)
    z = _proof_z_scalar(proof)
    if len(bases) != len(statement) or not bases:
        return False
    if not (0 <= e < group.q and 0 <= z < group.q):
        return False
    if not all(group_member(group, v, allow_one=False) for v in [*bases, *statement]):
        return False
    x = [pow(base, z, group.p) for base in bases]
    c_prime = [(x_i * pow(y_i, -e, group.p)) % group.p for x_i, y_i in zip(x, statement)]
    expected = recursive_hash_to_int((group.p, group.q, list(bases)), list(statement), c_prime, _haux("ExponentiationProof", iaux))
    return e == expected


def verify_decryption(
    group: GqGroup,
    ciphertext: dict[str, Any],
    public_key: Sequence[int],
    message: Sequence[int],
    proof: dict[str, Any],
    iaux: Sequence[str] | None = None,
) -> bool:
    gamma = b64_to_int(ciphertext["gamma"]) if isinstance(ciphertext["gamma"], str) else int(ciphertext["gamma"])
    phis = _decode_int_vector(ciphertext["phis"])
    e = _proof_e(proof)
    z = _proof_z_vector(proof)
    ell = len(phis)
    if ell == 0 or len(message) != ell or len(z) != ell or len(public_key) < ell:
        return False
    if not (0 <= e < group.q and all(0 <= item < group.q for item in z)):
        return False
    if not group_member(group, gamma, allow_one=False):
        return False
    if not all(group_member(group, v, allow_one=False) for v in [*phis, *public_key[:ell]]):
        return False
    if not all(group_member(group, v, allow_one=True) for v in message):
        return False

    x = [pow(group.g, zi, group.p) for zi in z] + [pow(gamma, zi, group.p) for zi in z]
    y = list(public_key[:ell]) + [(phis[i] * pow(message[i], -1, group.p)) % group.p for i in range(ell)]
    c_prime = [(x_i * pow(y_i, -e, group.p)) % group.p for x_i, y_i in zip(x, y)]
    haux = _haux("DecryptionProof", iaux)
    if iaux:
        haux = ("DecryptionProof", phis, list(message), list(iaux))
    else:
        haux = ("DecryptionProof", phis, list(message))
    expected = recursive_hash_to_int((group.p, group.q, group.g, gamma), y, c_prime, haux)
    return e == expected


def verify_plaintext_equality(
    group: GqGroup,
    upper_c: dict[str, Any],
    upper_c_prime: dict[str, Any],
    h: int,
    h_prime: int,
    proof: dict[str, Any],
    iaux: Sequence[str] | None = None,
) -> bool:
    c0 = b64_to_int(upper_c["gamma"])
    c1 = b64_to_int(upper_c["phis"][0])
    c0_prime = b64_to_int(upper_c_prime["gamma"])
    c1_prime = b64_to_int(upper_c_prime["phis"][0])
    e = _proof_e(proof)
    z = _proof_z_vector(proof)
    if len(z) != 2 or not (0 <= e < group.q and all(0 <= item < group.q for item in z)):
        return False
    if not all(group_member(group, v, allow_one=False) for v in [c0, c1, c0_prime, c1_prime, h, h_prime]):
        return False

    x = (
        pow(group.g, z[0], group.p),
        pow(group.g, z[1], group.p),
        (pow(h, z[0], group.p) * pow(h_prime, -z[1], group.p)) % group.p,
    )
    y = (c0, c0_prime, (c1 * pow(c1_prime, -1, group.p)) % group.p)
    c_prime = tuple((x_i * pow(y_i, -e, group.p)) % group.p for x_i, y_i in zip(x, y))
    if iaux:
        haux = ("PlaintextEqualityProof", c1, c1_prime, list(iaux))
    else:
        haux = ("PlaintextEqualityProof", c1, c1_prime)
    expected = recursive_hash_to_int((group.p, group.q, group.g, h, h_prime), y, c_prime, haux)
    return e == expected


def verify_decryptions(
    group: GqGroup,
    ciphertexts: Sequence[dict[str, Any]],
    public_key: Sequence[int],
    partially_decrypted: Sequence[dict[str, Any]],
    proofs: Sequence[dict[str, Any]],
    iaux: Sequence[str] | None = None,
) -> bool:
    if not ciphertexts or not (len(ciphertexts) == len(partially_decrypted) == len(proofs)):
        return False
    for ciphertext, decrypted, proof in zip(ciphertexts, partially_decrypted, proofs):
        if ciphertext["gamma"] != decrypted["gamma"]:
            return False
        message = _decode_int_vector(decrypted["phis"])
        if not verify_decryption(group, ciphertext, public_key, message, proof, iaux):
            return False
    return True


def combine_public_keys(group: GqGroup, keys: Sequence[Sequence[int]]) -> list[int]:
    if not keys:
        return []
    width = len(keys[0])
    if any(len(key) != width for key in keys):
        raise ValueError("public keys have inconsistent lengths")
    combined = []
    for i in range(width):
        value = 1
        for key in keys:
            value = (value * key[i]) % group.p
        combined.append(value)
    return combined


def _decode_int_vector(values: Iterable[Any]) -> list[int]:
    return [b64_to_int(v) if isinstance(v, str) else int(v) for v in values]


def decode_ciphertexts(values: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"gamma": item["gamma"], "phis": item["phis"]} for item in values]


def ciphertext_hash_tuple(ciphertext: dict[str, Any]) -> tuple[int, ...]:
    return (b64_to_int(ciphertext["gamma"]), *[b64_to_int(value) for value in ciphertext["phis"]])


def get_mixnet_initial_ciphertexts(
    group: GqGroup,
    encrypted_confirmed_votes: dict[str, dict[str, Any]],
    election_public_key: Sequence[int],
    delta: int,
) -> tuple[str, list[dict[str, Any]]]:
    ordered = tuple(
        (verification_card_id, ciphertext_hash_tuple(ciphertext))
        for verification_card_id, ciphertext in sorted(encrypted_confirmed_votes.items(), key=lambda item: item[0])
    )
    encrypted_confirmed_votes_hash = base64.b64encode(recursive_hash(ordered)).decode("ascii")
    ciphertexts = [ciphertext for _, ciphertext in sorted(encrypted_confirmed_votes.items(), key=lambda item: item[0])]
    if len(ciphertexts) < 2:
        trivial = {
            "gamma": int_to_b64(group.g),
            "phis": [int_to_b64(value) for value in election_public_key[:delta]],
        }
        ciphertexts = [*ciphertexts, trivial, trivial]
    return encrypted_confirmed_votes_hash, ciphertexts


def matrix_dimensions(count: int) -> tuple[int, int]:
    if count < 2:
        raise ValueError("shuffle verification requires at least two ciphertexts")
    divisors = [candidate for candidate in range(1, int(math.sqrt(count)) + 1) if count % candidate == 0]
    m = divisors[-1]
    return m, count // m
