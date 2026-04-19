#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from sharehound.utils.utils import parse_lm_nt_hashes

LM_DEFAULT = "aad3b435b51404eeaad3b435b51404ee"
NT_DEFAULT = "31d6cfe0d16ae931b73c59d7e0c089c0"
LM_SAMPLE = "11111111111111111111111111111111"
NT_SAMPLE = "22222222222222222222222222222222"


class ParseLmNtHashesTests(unittest.TestCase):
    def test_none_input(self):
        self.assertEqual(parse_lm_nt_hashes(None), ("", ""))

    def test_empty_string(self):
        self.assertEqual(parse_lm_nt_hashes(""), ("", ""))

    def test_both_hashes_preserved(self):
        self.assertEqual(
            parse_lm_nt_hashes(f"{LM_SAMPLE}:{NT_SAMPLE}"), (LM_SAMPLE, NT_SAMPLE)
        )

    def test_nt_only_substitutes_lm_default(self):
        self.assertEqual(parse_lm_nt_hashes(f":{NT_SAMPLE}"), (LM_DEFAULT, NT_SAMPLE))

    def test_lm_only_substitutes_nt_default(self):
        self.assertEqual(parse_lm_nt_hashes(f"{LM_SAMPLE}:"), (LM_SAMPLE, NT_DEFAULT))

    def test_both_hashes_case_normalized(self):
        self.assertEqual(
            parse_lm_nt_hashes(f"{LM_SAMPLE.upper()}:{NT_SAMPLE.upper()}"),
            (LM_SAMPLE, NT_SAMPLE),
        )

    def test_whitespace_trimmed(self):
        self.assertEqual(
            parse_lm_nt_hashes(f"  {LM_SAMPLE}:{NT_SAMPLE}  "),
            (LM_SAMPLE, NT_SAMPLE),
        )


if __name__ == "__main__":
    unittest.main()
