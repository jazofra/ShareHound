#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from sharehound.targets import load_targets


def _base_options(**overrides):
    opts = argparse.Namespace(
        auth_dc_ip=None,
        auth_user=None,
        auth_password=None,
        auth_hashes=None,
        auth_key=None,
        auth_domain="",
        use_kerberos=False,
        kdc_host=None,
        ldaps=False,
        subnets=False,
        targets_file=None,
        target=[],
    )
    for k, v in overrides.items():
        setattr(opts, k, v)
    return opts


class LoadTargetsMessagingTests(unittest.TestCase):
    def test_missing_targets_file_logs_error(self):
        logger = MagicMock()
        opts = _base_options(targets_file="/nonexistent/path.txt")
        result = load_targets(opts, MagicMock(), logger)
        self.assertEqual(result, [])
        logger.error.assert_called()
        msg = logger.error.call_args_list[0][0][0]
        self.assertIn("/nonexistent/path.txt", msg)
        self.assertIn("does not exist", msg)

    def test_targets_file_skips_blank_and_comment_lines(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        )
        try:
            tmp.write("# a comment\n")
            tmp.write("\n")
            tmp.write("10.0.0.1\n")
            tmp.write("   \n")
            tmp.write("srv1.corp.example.com\n")
            tmp.close()

            logger = MagicMock()
            opts = _base_options(targets_file=tmp.name)
            result = load_targets(opts, MagicMock(), logger)

            self.assertIn(("ipv4", "10.0.0.1"), result)
            self.assertIn(("fqdn", "srv1.corp.example.com"), result)
        finally:
            os.unlink(tmp.name)

    def test_invalid_targets_warn_with_list(self):
        logger = MagicMock()
        opts = _base_options(target=["10.0.0.1", "not a host!!"])
        load_targets(opts, MagicMock(), logger)
        logger.warning.assert_called_once()
        msg = logger.warning.call_args_list[0][0][0]
        self.assertIn("Skipped 1", msg)
        self.assertIn("not a host!!", msg)

    def test_valid_targets_do_not_warn(self):
        logger = MagicMock()
        opts = _base_options(target=["10.0.0.1", "srv1.corp.example.com"])
        result = load_targets(opts, MagicMock(), logger)
        self.assertIn(("ipv4", "10.0.0.1"), result)
        self.assertIn(("fqdn", "srv1.corp.example.com"), result)
        logger.warning.assert_not_called()


if __name__ == "__main__":
    unittest.main()
