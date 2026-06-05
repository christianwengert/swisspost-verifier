from __future__ import annotations

import base64
from typing import Any, Sequence

from .crypto import GqGroup, recursive_hash


def get_hash_context(
    group: GqGroup,
    election_event_id: str,
    verification_card_set_id: str,
    p_table: Sequence[dict[str, Any]],
    election_public_key: Sequence[int],
    choice_return_codes_public_key: Sequence[int],
) -> str:
    h: tuple[Any, ...] = ()
    h = (*h, "EncryptionParameters", group.p, group.q, group.g)
    h = (*h, "ElectionEventContext", election_event_id, verification_card_set_id)
    h = (*h, "ActualVotingOptions", *(entry["actualVotingOption"] for entry in p_table))
    h = (*h, "EncodedVotingOptions", *(entry["encodedVotingOption"] for entry in p_table))
    h = (*h, "SemanticInformation", *(entry["semanticInformation"] for entry in p_table))
    h = (*h, "CorrectnessInformation", *(entry["correctnessInformation"] for entry in p_table))
    h = (*h, "ELpk", *election_public_key)
    h = (*h, "pkCCR", *choice_return_codes_public_key)
    return _hash_to_base64(h)


def get_hash_election_event_context(group: GqGroup, election_event_context: dict[str, Any]) -> str:
    verification_card_sets = []
    for vcs_ctx in sorted(election_event_context["verificationCardSetContexts"], key=lambda item: item["verificationCardSetId"]):
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
                hp_table,
                tuple(vcs_ctx["domainsOfInfluence"]),
            )
        )
    h = (
        group.as_hash_tuple(),
        election_event_context["electionEventId"],
        election_event_context["electionEventAlias"],
        election_event_context["electionEventDescription"],
        tuple(verification_card_sets),
        election_event_context["startTime"],
        election_event_context["finishTime"],
        election_event_context["maximumNumberOfVotingOptions"],
        election_event_context["maximumNumberOfSelections"],
        election_event_context["maximumNumberOfWriteInsPlusOne"],
    )
    return _hash_to_base64(h)


def _hash_to_base64(value: Any) -> str:
    return base64.b64encode(recursive_hash(value)).decode("ascii")
