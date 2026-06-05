from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Sequence, TypeVar

from .crypto import GqGroup, b64_to_int, group_member, int_to_bytes, matrix_dimensions, recursive_hash_to_int

T = TypeVar("T")


@dataclass(frozen=True)
class CommitmentKey:
    h: int
    g: list[int]

    @classmethod
    def from_json(cls, data: dict[str, Any] | Sequence[str | int]) -> "CommitmentKey":
        if isinstance(data, dict):
            return cls(_decode_int(data["h"]), [_decode_int(value) for value in data["g"]])
        values = [_decode_int(value) for value in data]
        if not values:
            raise ValueError("commitment key must not be empty")
        return cls(values[0], values[1:])

    def as_hash_list(self) -> list[int]:
        return [self.h, *self.g]


@dataclass(frozen=True)
class ShuffleChallenges:
    x: int
    y: int
    z: int


@dataclass(frozen=True)
class HadamardChallenges:
    x: int
    y: int


def _decode_int(value: str | int) -> int:
    return b64_to_int(value) if isinstance(value, str) else int(value)


def _recursive_hash_of_length(bit_length: int, *values: Any) -> bytes:
    if not values:
        raise ValueError("RecursiveHashOfLength requires at least one value")
    if len(values) > 1:
        return _recursive_hash_of_length(bit_length, tuple(values))

    byte_length = (bit_length + 7) // 8
    value = values[0]
    if isinstance(value, bytes):
        payload = b"\x00" + value
    elif isinstance(value, int):
        if value < 0:
            raise ValueError("RecursiveHashOfLength integers must be non-negative")
        payload = b"\x01" + int_to_bytes(value)
    elif isinstance(value, str):
        payload = b"\x02" + value.encode("utf-8")
    elif isinstance(value, (list, tuple)):
        payload = b"\x03" + b"".join(_recursive_hash_of_length(bit_length, item) for item in value)
    else:
        raise TypeError(f"unsupported RecursiveHashOfLength value: {type(value).__name__}")

    digest = bytearray(hashlib.shake_256(payload).digest(byte_length))
    extra_bits = byte_length * 8 - bit_length
    if extra_bits:
        digest[0] &= (1 << (8 - extra_bits)) - 1
    return bytes(digest)


def recursive_hash_to_zq(q: int, *values: Any) -> int:
    bit_length = q.bit_length() + 256
    return int.from_bytes(_recursive_hash_of_length(bit_length, q, "RecursiveHash", *values), "big") % q


def ciphertext_as_hash_tuple(ciphertext: dict[str, Any]) -> tuple[int, ...]:
    return (_decode_int(ciphertext["gamma"]), *[_decode_int(value) for value in ciphertext["phis"]])


def _decode_ciphertext(ciphertext: dict[str, Any]) -> tuple[int, list[int]]:
    return _decode_int(ciphertext["gamma"]), [_decode_int(value) for value in ciphertext["phis"]]


def _ciphertext_equal(left: tuple[int, Sequence[int]], right: tuple[int, Sequence[int]]) -> bool:
    return left[0] == right[0] and list(left[1]) == list(right[1])


def _ciphertext_product(
    group: GqGroup,
    left: tuple[int, Sequence[int]],
    right: tuple[int, Sequence[int]],
) -> tuple[int, list[int]]:
    if len(left[1]) != len(right[1]):
        raise ValueError("ciphertext widths do not match")
    return (
        (left[0] * right[0]) % group.p,
        [(a * b) % group.p for a, b in zip(left[1], right[1])],
    )


def _ciphertext_power(group: GqGroup, ciphertext: tuple[int, Sequence[int]], exponent: int) -> tuple[int, list[int]]:
    return (
        pow(ciphertext[0], exponent % group.q, group.p),
        [pow(value, exponent % group.q, group.p) for value in ciphertext[1]],
    )


def _neutral_ciphertext(width: int) -> tuple[int, list[int]]:
    return 1, [1] * width


def _encrypt_constant_message(group: GqGroup, message: int, randomness: int, public_key: Sequence[int], width: int) -> tuple[int, list[int]]:
    if len(public_key) < width:
        raise ValueError("public key is shorter than ciphertext width")
    return (
        pow(group.g, randomness % group.q, group.p),
        [(pow(public_key[index], randomness % group.q, group.p) * message) % group.p for index in range(width)],
    )


def _ciphertext_vector_exponentiation(
    group: GqGroup,
    ciphertexts: Sequence[dict[str, Any] | tuple[int, Sequence[int]]],
    exponents: Sequence[int],
) -> tuple[int, list[int]]:
    if len(ciphertexts) != len(exponents) or not ciphertexts:
        raise ValueError("ciphertext vector and exponent vector dimensions do not match")
    decoded = [_decode_ciphertext(item) if isinstance(item, dict) else (item[0], list(item[1])) for item in ciphertexts]
    result = _neutral_ciphertext(len(decoded[0][1]))
    for ciphertext, exponent in zip(decoded, exponents):
        result = _ciphertext_product(group, result, _ciphertext_power(group, ciphertext, exponent))
    return result


def to_matrix(values: Sequence[T], rows: int, columns: int) -> list[list[T]]:
    if rows <= 0 or columns <= 0 or len(values) != rows * columns:
        raise ValueError("matrix dimensions do not match vector length")
    return [list(values[row * columns : (row + 1) * columns]) for row in range(rows)]


def transpose(matrix: Sequence[Sequence[T]]) -> list[list[T]]:
    if not matrix or not matrix[0]:
        raise ValueError("matrix must not be empty")
    width = len(matrix[0])
    if any(len(row) != width for row in matrix):
        raise ValueError("matrix rows must have equal length")
    return [[row[column] for row in matrix] for column in range(width)]


def get_verifiable_commitment_key(group: GqGroup, nu: int) -> CommitmentKey:
    if nu <= 0 or nu > group.q - 3:
        raise ValueError("invalid commitment-key size")
    values: list[int] = []
    index = 0
    count = 0
    while count <= nu:
        u = recursive_hash_to_zq(group.q, "commitmentKey", index, count) + 1
        candidate = pow(u, 2, group.p)
        if candidate not in {1, group.g, *values}:
            values.append(candidate)
            count += 1
        index += 1
    return CommitmentKey(values[0], values[1:])


def get_commitment(group: GqGroup, values: Sequence[int], randomness: int, commitment_key: CommitmentKey) -> int:
    if not values or len(values) > len(commitment_key.g):
        raise ValueError("invalid commitment width")
    result = pow(commitment_key.h, randomness % group.q, group.p)
    for value, generator in zip(values, commitment_key.g):
        result = (result * pow(generator, value % group.q, group.p)) % group.p
    return result


def get_commitment_matrix(
    group: GqGroup,
    matrix: Sequence[Sequence[int]],
    randomness: Sequence[int],
    commitment_key: CommitmentKey,
) -> list[int]:
    if not matrix or len(matrix[0]) != len(randomness):
        raise ValueError("commitment matrix dimensions do not match randomness")
    width = len(randomness)
    if any(len(row) != width for row in matrix):
        raise ValueError("commitment matrix rows must have equal length")
    return [
        get_commitment(group, [row[column] for row in matrix], randomness[column], commitment_key)
        for column in range(width)
    ]


def star_map(group: GqGroup, y: int, first: Sequence[int], second: Sequence[int]) -> int:
    if len(first) != len(second):
        raise ValueError("star-map vectors must have equal length")
    result = 0
    y_power = y % group.q
    for a_value, b_value in zip(first, second):
        result = (result + (a_value % group.q) * (b_value % group.q) * y_power) % group.q
        y_power = (y_power * y) % group.q
    return result


def derive_shuffle_challenges(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    ciphertexts: Sequence[dict[str, Any]],
    shuffled_ciphertexts: Sequence[dict[str, Any]],
    c_a: Sequence[int],
    c_b: Sequence[int],
) -> ShuffleChallenges:
    ciphertext_hashes = [ciphertext_as_hash_tuple(ciphertext) for ciphertext in ciphertexts]
    shuffled_hashes = [ciphertext_as_hash_tuple(ciphertext) for ciphertext in shuffled_ciphertexts]
    common = (
        group.p,
        group.q,
        list(public_key),
        commitment_key.as_hash_list(),
        ciphertext_hashes,
        shuffled_hashes,
        list(c_a),
    )
    x = recursive_hash_to_int(*common)
    y = recursive_hash_to_int(list(c_b), *common)
    z = recursive_hash_to_int("1", list(c_b), *common)
    return ShuffleChallenges(x, y, z)


def derive_multi_exponentiation_challenge(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    ciphertext_matrix: Sequence[Sequence[dict[str, Any]]],
    ciphertext_product: dict[str, Any],
    c_a: Sequence[int],
    argument: dict[str, Any],
) -> int:
    return recursive_hash_to_int(
        group.p,
        group.q,
        list(public_key),
        commitment_key.as_hash_list(),
        [[ciphertext_as_hash_tuple(ciphertext) for ciphertext in row] for row in ciphertext_matrix],
        ciphertext_as_hash_tuple(ciphertext_product),
        list(c_a),
        _decode_int(argument["c_a_0"]),
        [_decode_int(value) for value in argument["c_b"]],
        [ciphertext_as_hash_tuple(ciphertext) for ciphertext in argument["e"]],
    )


def derive_zero_argument_challenge(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    statement: dict[str, Any],
    argument: dict[str, Any],
) -> int:
    return recursive_hash_to_int(
        group.p,
        group.q,
        list(public_key),
        commitment_key.as_hash_list(),
        _decode_int(argument["c_a0"]),
        _decode_int(argument["c_bm"]),
        [_decode_int(value) for value in argument["c_d"]],
        [_decode_int(value) for value in statement["c_b"]],
        [_decode_int(value) for value in statement["c_a"]],
    )


def derive_single_value_product_challenge(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    statement: dict[str, Any],
    argument: dict[str, Any],
) -> int:
    return recursive_hash_to_int(
        group.p,
        group.q,
        list(public_key),
        commitment_key.as_hash_list(),
        _decode_int(argument["c_upper_delta"]),
        _decode_int(argument["c_lower_delta"]),
        _decode_int(argument["c_d"]),
        _decode_int(statement["b"]),
        _decode_int(statement["c_a"]),
    )


def derive_hadamard_argument_challenges(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    statement: dict[str, Any],
    argument: dict[str, Any],
) -> HadamardChallenges:
    c_a = [_decode_int(value) for value in statement["c_a"]]
    c_b = _decode_int(statement["c_b"])
    c_upper_b = [_decode_int(value) for value in argument["cUpperB"]]
    x = recursive_hash_to_int(group.p, group.q, list(public_key), commitment_key.as_hash_list(), c_a, c_b, c_upper_b)
    y = recursive_hash_to_int("1", group.p, group.q, list(public_key), commitment_key.as_hash_list(), c_a, c_b, c_upper_b)
    return HadamardChallenges(x, y)


def verify_zero_argument(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    statement: dict[str, Any],
    argument: dict[str, Any],
) -> bool:
    c_a = [_decode_int(value) for value in statement["c_a"]]
    c_b = [_decode_int(value) for value in statement["c_b"]]
    y = _decode_int(statement["y"])
    c_a0 = _decode_int(argument["c_a0"])
    c_bm = _decode_int(argument["c_bm"])
    c_d = [_decode_int(value) for value in argument["c_d"]]
    a_prime = [_decode_int(value) for value in argument["a"]]
    b_prime = [_decode_int(value) for value in argument["b"]]
    r_prime = _decode_int(argument["r"])
    s_prime = _decode_int(argument["s"])
    t_prime = _decode_int(argument["t"])
    m = len(c_a)
    n = len(a_prime)

    if not (
        m > 0
        and len(c_b) == m
        and len(c_d) == 2 * m + 1
        and len(b_prime) == n
        and n > 0
        and len(commitment_key.g) >= n
    ):
        return False
    if any(not 0 <= value < group.q for value in [y, *a_prime, *b_prime, r_prime, s_prime, t_prime]):
        return False
    if any(not group_member(group, value) for value in [*public_key, commitment_key.h, *commitment_key.g, *c_a, *c_b, c_a0, c_bm, *c_d]):
        return False

    x = derive_zero_argument_challenge(group, public_key, commitment_key, statement, argument)
    verif_cd = c_d[m + 1] == 1

    all_c_a = [c_a0, *c_a]
    prod_ca = 1
    x_power = 1
    for commitment in all_c_a:
        prod_ca = (prod_ca * pow(commitment, x_power, group.p)) % group.p
        x_power = (x_power * x) % group.q
    verif_a = prod_ca == get_commitment(group, a_prime, r_prime, commitment_key)

    all_c_b = [*c_b, c_bm]
    prod_cb = 1
    x_power = 1
    for commitment in reversed(all_c_b):
        prod_cb = (prod_cb * pow(commitment, x_power, group.p)) % group.p
        x_power = (x_power * x) % group.q
    verif_b = prod_cb == get_commitment(group, b_prime, s_prime, commitment_key)

    prod_cd = 1
    x_power = 1
    for commitment in c_d:
        prod_cd = (prod_cd * pow(commitment, x_power, group.p)) % group.p
        x_power = (x_power * x) % group.q
    prod = star_map(group, y, a_prime, b_prime)
    verif_d = prod_cd == get_commitment(group, [prod], t_prime, commitment_key)

    return verif_cd and verif_a and verif_b and verif_d


def verify_single_value_product_argument(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    statement: dict[str, Any],
    argument: dict[str, Any],
) -> bool:
    c_a = _decode_int(statement["c_a"])
    b = _decode_int(statement["b"])
    c_d = _decode_int(argument["c_d"])
    c_lower_delta = _decode_int(argument["c_lower_delta"])
    c_upper_delta = _decode_int(argument["c_upper_delta"])
    a_tilde = [_decode_int(value) for value in argument["a_tilde"]]
    b_tilde = [_decode_int(value) for value in argument["b_tilde"]]
    r_tilde = _decode_int(argument["r_tilde"])
    s_tilde = _decode_int(argument["s_tilde"])
    n = len(a_tilde)

    if not (n >= 2 and len(b_tilde) == n and len(commitment_key.g) >= n):
        return False
    if any(not 0 <= value < group.q for value in [b, *a_tilde, *b_tilde, r_tilde, s_tilde]):
        return False
    if any(not group_member(group, value) for value in [*public_key, commitment_key.h, *commitment_key.g, c_a, c_d, c_lower_delta, c_upper_delta]):
        return False

    x = derive_single_value_product_challenge(group, public_key, commitment_key, statement, argument)
    prod_ca = (pow(c_a, x, group.p) * c_d) % group.p
    verif_a = prod_ca == get_commitment(group, a_tilde, r_tilde, commitment_key)

    prod_delta = (pow(c_upper_delta, x, group.p) * c_lower_delta) % group.p
    e_values = [
        (x * b_tilde[index + 1] - b_tilde[index] * a_tilde[index + 1]) % group.q
        for index in range(n - 1)
    ]
    verif_delta = prod_delta == get_commitment(group, e_values, s_tilde, commitment_key)
    verif_b = b_tilde[0] == a_tilde[0] and b_tilde[-1] == (x * b) % group.q

    return verif_a and verif_delta and verif_b


def verify_hadamard_argument(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    statement: dict[str, Any],
    argument: dict[str, Any],
) -> bool:
    c_a = [_decode_int(value) for value in statement["c_a"]]
    c_b = _decode_int(statement["c_b"])
    c_upper_b = [_decode_int(value) for value in argument["cUpperB"]]
    zero_argument = argument["zero_argument"]
    m = len(c_a)
    n = len(zero_argument["a"])

    if not (m >= 2 and len(c_upper_b) == m and n > 0 and len(commitment_key.g) >= n):
        return False
    if any(not group_member(group, value) for value in [*public_key, commitment_key.h, *commitment_key.g, *c_a, c_b, *c_upper_b]):
        return False

    challenges = derive_hadamard_argument_challenges(group, public_key, commitment_key, statement, argument)
    c_d_prefix = [
        pow(c_upper_b[index], pow(challenges.x, index + 1, group.q), group.p)
        for index in range(m - 1)
    ]
    c_d = 1
    for index in range(1, m):
        c_d = (c_d * pow(c_upper_b[index], pow(challenges.x, index, group.q), group.p)) % group.p
    c_minus_one = get_commitment(group, [group.q - 1] * n, 0, commitment_key)
    zero_statement = {
        "c_a": [*c_a[1:], c_minus_one],
        "c_b": [*c_d_prefix, c_d],
        "y": challenges.y,
    }

    return (
        c_upper_b[0] == c_a[0]
        and c_upper_b[-1] == c_b
        and verify_zero_argument(group, public_key, commitment_key, zero_statement, zero_argument)
    )


def verify_product_argument(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    statement: dict[str, Any],
    argument: dict[str, Any],
) -> bool:
    c_a = [_decode_int(value) for value in statement["c_a"]]
    b = _decode_int(statement["b"])
    m = len(c_a)
    if not (m > 0 and 0 <= b < group.q and len(commitment_key.g) >= 2):
        return False
    if any(not group_member(group, value) for value in [*public_key, commitment_key.h, *commitment_key.g, *c_a]):
        return False

    if m == 1:
        return verify_single_value_product_argument(
            group,
            public_key,
            commitment_key,
            {"c_a": c_a[0], "b": b},
            argument["single_vpa"],
        )

    c_b = _decode_int(argument["c_b"])
    if not group_member(group, c_b):
        return False
    return verify_hadamard_argument(
        group,
        public_key,
        commitment_key,
        {"c_a": c_a, "c_b": c_b},
        argument["hadamard_argument"],
    ) and verify_single_value_product_argument(
        group,
        public_key,
        commitment_key,
        {"c_a": c_b, "b": b},
        argument["single_vpa"],
    )


def verify_shuffle_argument(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    statement: dict[str, Any],
    argument: dict[str, Any],
) -> bool:
    ciphertexts = statement["ciphertexts"]
    shuffled_ciphertexts = statement["shuffled_ciphertexts"]
    if not ciphertexts or len(ciphertexts) != len(shuffled_ciphertexts):
        return False
    m, n = matrix_dimensions(len(ciphertexts))
    if n > len(commitment_key.g):
        return False

    c_a = [_decode_int(value) for value in argument["ca"]]
    c_b = [_decode_int(value) for value in argument["cb"]]
    if len(c_a) != m or len(c_b) != m:
        return False
    decoded_ciphertexts = [_decode_ciphertext(ciphertext) for ciphertext in ciphertexts]
    decoded_shuffled = [_decode_ciphertext(ciphertext) for ciphertext in shuffled_ciphertexts]
    width = len(decoded_ciphertexts[0][1])
    if not (
        len(public_key) >= width
        and all(len(ciphertext[1]) == width for ciphertext in [*decoded_ciphertexts, *decoded_shuffled])
        and all(group_member(group, value) for value in [*public_key[:width], commitment_key.h, *commitment_key.g, *c_a, *c_b])
        and all(group_member(group, value) for ciphertext in [*decoded_ciphertexts, *decoded_shuffled] for value in (ciphertext[0], *ciphertext[1]))
    ):
        return False

    challenges = derive_shuffle_challenges(group, public_key, commitment_key, ciphertexts, shuffled_ciphertexts, c_a, c_b)
    zneg = [(-challenges.z) % group.q] * len(ciphertexts)
    c_minus_z = get_commitment_matrix(group, transpose(to_matrix(zneg, m, n)), [0] * m, commitment_key)
    c_d = [(pow(a_value, challenges.y % group.q, group.p) * b_value) % group.p for a_value, b_value in zip(c_a, c_b)]
    product_statement = {
        "c_a": [(d_value * minus_z_value) % group.p for d_value, minus_z_value in zip(c_d, c_minus_z)],
        "b": _shuffle_product_value(group, challenges.x, challenges.y, challenges.z, len(ciphertexts)),
    }
    product_ok = verify_product_argument(group, public_key, commitment_key, product_statement, argument["product_argument"])

    x_vector = [pow(challenges.x, index, group.q) for index in range(len(ciphertexts))]
    ciphertext_product = _ciphertext_vector_exponentiation(group, ciphertexts, x_vector)
    multi_statement = {
        "ciphertexts": to_matrix(shuffled_ciphertexts, m, n),
        "ciphertext_product": {"gamma": ciphertext_product[0], "phis": ciphertext_product[1]},
        "c_a": c_b,
    }
    multi_ok = verify_multi_exponentiation_argument(group, public_key, commitment_key, multi_statement, argument["multi_exp_argument"])

    return product_ok and multi_ok


def _shuffle_product_value(group: GqGroup, x: int, y: int, z: int, count: int) -> int:
    result = 1
    z_mod = z % group.q
    for index in range(count):
        result = (result * (((y * index) + pow(x, index, group.q) - z_mod) % group.q)) % group.q
    return result


def verify_multi_exponentiation_argument(
    group: GqGroup,
    public_key: Sequence[int],
    commitment_key: CommitmentKey,
    statement: dict[str, Any],
    argument: dict[str, Any],
) -> bool:
    ciphertext_matrix = statement["ciphertexts"]
    if not ciphertext_matrix or not ciphertext_matrix[0]:
        return False
    m = len(ciphertext_matrix)
    n = len(ciphertext_matrix[0])
    if any(len(row) != n for row in ciphertext_matrix):
        return False

    c_a = [_decode_int(value) for value in statement["c_a"]]
    c_a_0 = _decode_int(argument["c_a_0"])
    c_b = [_decode_int(value) for value in argument["c_b"]]
    e_values = argument["e"]
    a_vector = [_decode_int(value) for value in argument["a"]]
    r = _decode_int(argument["r"])
    b = _decode_int(argument["b"])
    s = _decode_int(argument["s"])
    tau = _decode_int(argument["tau"])
    ciphertext_product = _decode_ciphertext(statement["ciphertext_product"])
    e_ciphertexts = [_decode_ciphertext(value) for value in e_values]
    width = len(ciphertext_product[1])

    if not (
        len(c_a) == m
        and len(c_b) == 2 * m
        and len(e_ciphertexts) == 2 * m
        and len(a_vector) == n
        and all(len(_decode_ciphertext(ciphertext)[1]) == width for row in ciphertext_matrix for ciphertext in row)
        and all(len(ciphertext[1]) == width for ciphertext in e_ciphertexts)
        and len(public_key) >= width
    ):
        return False
    scalar_values = [*a_vector, r, b, s, tau]
    if any(not 0 <= value < group.q for value in scalar_values):
        return False
    group_values = [
        *public_key[:width],
        commitment_key.h,
        *commitment_key.g,
        *c_a,
        c_a_0,
        *c_b,
        ciphertext_product[0],
        *ciphertext_product[1],
        *(value for ciphertext in e_ciphertexts for value in (ciphertext[0], *ciphertext[1])),
    ]
    if any(not group_member(group, value) for value in group_values):
        return False

    x = derive_multi_exponentiation_challenge(group, public_key, commitment_key, ciphertext_matrix, statement["ciphertext_product"], c_a, argument)
    verif_c_b_m = c_b[m] == 1
    verif_e_m = _ciphertext_equal(e_ciphertexts[m], ciphertext_product)

    prod_c_a = c_a_0
    x_power = x % group.q
    for commitment in c_a:
        prod_c_a = (prod_c_a * pow(commitment, x_power, group.p)) % group.p
        x_power = (x_power * x) % group.q
    verif_a = prod_c_a == get_commitment(group, a_vector, r, commitment_key)

    prod_c_b = c_b[0]
    x_power = x % group.q
    for commitment in c_b[1:]:
        prod_c_b = (prod_c_b * pow(commitment, x_power, group.p)) % group.p
        x_power = (x_power * x) % group.q
    verif_b = prod_c_b == get_commitment(group, [b], s, commitment_key)

    prod_e = e_ciphertexts[0]
    x_power = x % group.q
    for ciphertext in e_ciphertexts[1:]:
        prod_e = _ciphertext_product(group, prod_e, _ciphertext_power(group, ciphertext, x_power))
        x_power = (x_power * x) % group.q

    encrypted_g_b = _encrypt_constant_message(group, pow(group.g, b, group.p), tau, public_key, width)
    prod_c = _neutral_ciphertext(width)
    for row_index, row in enumerate(ciphertext_matrix):
        scale = pow(x, m - row_index - 1, group.q)
        exponents = [(scale * value) % group.q for value in a_vector]
        prod_c = _ciphertext_product(group, prod_c, _ciphertext_vector_exponentiation(group, row, exponents))
    verif_e_c = _ciphertext_equal(prod_e, _ciphertext_product(group, encrypted_g_b, prod_c))

    return verif_c_b_m and verif_e_m and verif_a and verif_b and verif_e_c
