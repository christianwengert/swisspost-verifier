from __future__ import annotations

import json
import unittest
from pathlib import Path

from swisspost_independent_verifier.crypto import GqGroup, b64_to_int
from swisspost_independent_verifier.write_ins import (
    encode_write_ins,
    integer_to_write_in,
    quadratic_residue_to_write_in,
    write_in_to_integer,
    write_in_to_quadratic_residue,
)

ROOT = Path(__file__).resolve().parents[2]
WRITE_IN_DATA = ROOT / "e-voting/voting-client/test/tools/data"


def parse_int(value: str) -> int:
    return int(value, 16) if value.startswith("0x") else b64_to_int(value)


def group_from_context(context: dict[str, str]) -> GqGroup:
    return GqGroup(parse_int(context["p"]), parse_int(context["q"]), parse_int(context["g"]))


class WriteInTests(unittest.TestCase):
    def test_write_in_to_integer_vectors(self):
        cases = json.loads((WRITE_IN_DATA / "write-in-to-integer.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                group = group_from_context(case["context"])
                if "error" in case["output"]:
                    with self.assertRaises(ValueError):
                        write_in_to_integer(case["input"]["s"], group.q)
                else:
                    self.assertEqual(parse_int(case["output"]["output"]), write_in_to_integer(case["input"]["s"], group.q))

    def test_integer_to_write_in_reverses_write_in_to_integer_vectors(self):
        cases = json.loads((WRITE_IN_DATA / "write-in-to-integer.json").read_text(encoding="utf-8"))
        for case in cases:
            if "error" in case["output"]:
                continue
            with self.subTest(case=case["description"]):
                self.assertEqual(case["input"]["s"], integer_to_write_in(parse_int(case["output"]["output"])))

    def test_write_in_to_quadratic_residue_vectors(self):
        cases = json.loads((WRITE_IN_DATA / "write-in-to-quadratic-residue.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                group = group_from_context(case["context"])
                if "error" in case["output"]:
                    with self.assertRaises(ValueError):
                        write_in_to_quadratic_residue(group, case["input"]["s"])
                else:
                    self.assertEqual(
                        parse_int(case["output"]["output"]),
                        write_in_to_quadratic_residue(group, case["input"]["s"]),
                    )

    def test_quadratic_residue_to_write_in_reverses_valid_vectors(self):
        cases = json.loads((WRITE_IN_DATA / "write-in-to-quadratic-residue.json").read_text(encoding="utf-8"))
        for case in cases:
            if "error" in case["output"]:
                continue
            with self.subTest(case=case["description"]):
                group = group_from_context(case["context"])
                self.assertEqual(case["input"]["s"], quadratic_residue_to_write_in(group, parse_int(case["output"]["output"])))

    def test_encode_write_ins_vectors(self):
        cases = json.loads((WRITE_IN_DATA / "encode-write-ins.json").read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["description"]):
                group = group_from_context(case["context"])
                expected = [b64_to_int(value) for value in case["output"]["w"]]
                self.assertEqual(expected, encode_write_ins(group, case["input"]["s_hat"], case["context"]["delta"]))


if __name__ == "__main__":
    unittest.main()
