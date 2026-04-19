#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from sharehound.core.Credentials import Credentials


class CanPassTheHashTests(unittest.TestCase):
    def test_no_hashes_false(self):
        c = Credentials(domain="", username="", password="", hashes=None)
        self.assertFalse(c.canPassTheHash())

    def test_anonymous_false(self):
        c = Credentials(domain="", username="user", password="pw")
        self.assertFalse(c.canPassTheHash())

    def test_hex_but_empty_raw_false(self):
        c = Credentials(domain="", username="u", password="", hashes=None)
        c.lm_hex = "aad3b435b51404eeaad3b435b51404ee"
        c.nt_hex = "31d6cfe0d16ae931b73c59d7e0c089c0"
        self.assertFalse(c.canPassTheHash())

    def test_both_hashes_populated_true(self):
        c = Credentials(domain="", username="u", password="", hashes=None)
        c.lm_hex = "aad3b435b51404eeaad3b435b51404ee"
        c.nt_hex = "31d6cfe0d16ae931b73c59d7e0c089c0"
        c.lm_raw = b"\xaa\xd3\xb4\x35\xb5\x14\x04\xee\xaa\xd3\xb4\x35\xb5\x14\x04\xee"
        c.nt_raw = b"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"
        self.assertTrue(c.canPassTheHash())

    def test_only_nt_populated_false(self):
        c = Credentials(domain="", username="u", password="", hashes=None)
        c.nt_hex = "31d6cfe0d16ae931b73c59d7e0c089c0"
        c.nt_raw = b"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"
        self.assertFalse(c.canPassTheHash())


if __name__ == "__main__":
    unittest.main()
