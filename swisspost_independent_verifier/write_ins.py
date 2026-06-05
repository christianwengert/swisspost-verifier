from __future__ import annotations

from typing import Sequence

from .crypto import GqGroup
from .electoral_model import get_write_in_encoded_voting_options

ALATIN = (
    "# '(),-./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "¢ŠšŽžŒœŸÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞß"
    "àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ"
)
WRITE_IN_MAX_LENGTH = 400


def write_in_to_integer(value: str, q: int | None = None) -> int:
    if not value:
        raise ValueError("write-in must not be empty")
    if value[0] == ALATIN[0]:
        raise ValueError("write-in must not start with the rank 0 character")
    ranks = {character: rank for rank, character in enumerate(ALATIN)}
    result = 0
    for character in value:
        if character not in ranks:
            raise ValueError("all characters in write-in must be in A_latin alphabet")
        result = result * len(ALATIN) + ranks[character]
    if q is not None and len(ALATIN) ** (len(value) + 1) >= q:
        raise ValueError("the exponential form of a to s_length must be smaller than q")
    return result


def integer_to_write_in(value: int) -> str:
    if value <= 0:
        raise ValueError("write-in integer must be positive")
    result = ""
    while value > 0:
        rank = value % len(ALATIN)
        result = ALATIN[rank] + result
        value = (value - rank) // len(ALATIN)
    return result


def write_in_to_quadratic_residue(group: GqGroup, value: str) -> int:
    encoded = write_in_to_integer(value, group.q)
    return pow(encoded, 2, group.p)


def quadratic_residue_to_write_in(group: GqGroup, value: int) -> str:
    root = pow(value, (group.p + 1) // 4, group.p)
    if root > group.q:
        root = group.p - root
    return integer_to_write_in(root)


def encode_write_ins(group: GqGroup, selected_write_ins: Sequence[str], delta: int) -> list[int]:
    if len(selected_write_ins) > delta - 1:
        raise ValueError("too many selected write-ins for delta")
    encoded = [write_in_to_quadratic_residue(group, value) for value in selected_write_ins]
    encoded.extend([1] * (delta - 1 - len(encoded)))
    return encoded


def is_write_in_option(primes_mapping_table: dict, encoded_voting_option: int) -> bool:
    return encoded_voting_option in set(get_write_in_encoded_voting_options(primes_mapping_table))


def decode_write_ins(
    group: GqGroup,
    primes_mapping_table: dict,
    selected_encoded_voting_options: Sequence[int],
    encoded_write_ins: Sequence[int],
    max_length: int = WRITE_IN_MAX_LENGTH,
) -> list[str]:
    if not encoded_write_ins:
        return []
    decoded: list[str] = []
    write_in_index = 0
    for encoded_option in selected_encoded_voting_options:
        if is_write_in_option(primes_mapping_table, encoded_option):
            if write_in_index >= len(encoded_write_ins):
                raise ValueError("not enough encoded write-ins for selected write-in options")
            decoded.append(quadratic_residue_to_write_in(group, encoded_write_ins[write_in_index])[:max_length])
            write_in_index += 1
    return decoded
