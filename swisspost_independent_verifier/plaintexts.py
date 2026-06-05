from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from .crypto import GqGroup
from .electoral_model import (
    factorize,
    get_actual_voting_options,
    get_blank_correctness_information,
    get_correctness_information,
    get_delta,
)
from .write_ins import decode_write_ins


@dataclass(frozen=True)
class ProcessPlaintextsOutput:
    votes: list[list[int]]
    decoded_votes: list[list[str]]
    write_ins: list[list[str]]


def process_plaintexts(
    group: GqGroup,
    primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]],
    plaintext_votes: Sequence[Sequence[int]],
) -> ProcessPlaintextsOutput:
    if len(plaintext_votes) < 2:
        raise ValueError("ProcessPlaintexts requires at least two plaintext votes")

    delta = get_delta(primes_mapping_table)
    blank_correctness = get_blank_correctness_information(primes_mapping_table)
    votes: list[list[int]] = []
    decoded_votes: list[list[str]] = []
    write_ins: list[list[str]] = []

    for plaintext_vote in plaintext_votes:
        row = list(plaintext_vote)
        if len(row) != delta:
            raise ValueError("plaintext vote width does not match delta")
        if row == [1] * delta:
            continue

        selected_encoded = factorize(primes_mapping_table, row[0])
        selected_actual = get_actual_voting_options(primes_mapping_table, selected_encoded)
        selected_correctness = get_correctness_information(primes_mapping_table, selected_actual)
        if selected_correctness != blank_correctness:
            raise ValueError("plaintext vote contains an invalid combination of voting options")

        votes.append(selected_encoded)
        decoded_votes.append(selected_actual)
        write_ins.append(decode_write_ins(group, primes_mapping_table, selected_encoded, row[1:]))

    return ProcessPlaintextsOutput(votes, decoded_votes, write_ins)
