from __future__ import annotations

from typing import Any, Sequence


def ptable_entries(primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(primes_mapping_table, dict):
        return list(primes_mapping_table["pTable"])
    return list(primes_mapping_table)


def get_encoded_voting_options(
    primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]],
    actual_voting_options: Sequence[str] | None = None,
) -> list[int]:
    entries = ptable_entries(primes_mapping_table)
    if actual_voting_options is None:
        return [entry["encodedVotingOption"] for entry in entries]
    by_actual = {entry["actualVotingOption"]: entry["encodedVotingOption"] for entry in entries}
    return [by_actual[actual] for actual in actual_voting_options]


def get_actual_voting_options(
    primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]],
    encoded_voting_options: Sequence[int] | None = None,
) -> list[str]:
    entries = ptable_entries(primes_mapping_table)
    if encoded_voting_options is None:
        return [entry["actualVotingOption"] for entry in entries]
    by_encoded = {entry["encodedVotingOption"]: entry["actualVotingOption"] for entry in entries}
    return [by_encoded[encoded] for encoded in encoded_voting_options]


def get_correctness_information(
    primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]],
    actual_voting_options: Sequence[str] | None = None,
) -> list[str]:
    entries = ptable_entries(primes_mapping_table)
    if actual_voting_options is None:
        return [entry["correctnessInformation"] for entry in entries]
    by_actual = {entry["actualVotingOption"]: entry["correctnessInformation"] for entry in entries}
    return [by_actual[actual] for actual in actual_voting_options]


def get_blank_correctness_information(primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]]) -> list[str]:
    blanks = [
        entry["correctnessInformation"]
        for entry in ptable_entries(primes_mapping_table)
        if entry["semanticInformation"].startswith("BLANK")
    ]
    if not blanks:
        raise ValueError("primes mapping table has no blank voting options")
    return blanks


def get_write_in_encoded_voting_options(primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]]) -> list[int]:
    return [
        entry["encodedVotingOption"]
        for entry in ptable_entries(primes_mapping_table)
        if entry["semanticInformation"].startswith("WRITE_IN")
    ]


def get_psi(primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]]) -> int:
    return len(get_blank_correctness_information(primes_mapping_table))


def get_delta(primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]]) -> int:
    return len(get_write_in_encoded_voting_options(primes_mapping_table)) + 1


def factorize(
    primes_mapping_table: dict[str, Any] | Sequence[dict[str, Any]],
    value: int,
) -> list[int]:
    encoded_options = get_encoded_voting_options(primes_mapping_table)
    expected_count = get_psi(primes_mapping_table)
    factors: list[int] = []
    product = 1
    for encoded in encoded_options:
        if value % encoded == 0:
            factors.append(encoded)
            product *= encoded
    if len(factors) != expected_count or product != value:
        raise ValueError("plaintext vote does not factor into the expected encoded voting options")
    return factors
