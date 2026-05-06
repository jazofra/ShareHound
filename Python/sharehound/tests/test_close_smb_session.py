#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import MagicMock, patch

from sharehound.core.SMBSession import SMBSession


def _make_session() -> SMBSession:
    # Avoid calling __init__ which tries to list_shares() over the wire.
    with patch.object(SMBSession, "list_shares", return_value={}):
        return SMBSession(
            host="10.0.0.1",
            port=445,
            timeout=1,
            credentials=MagicMock(),
            remote_name="10.0.0.1",
            advertisedName=None,
            config=MagicMock(),
            logger=MagicMock(),
        )


class CloseSmbSessionTests(unittest.TestCase):
    def test_close_when_connected(self):
        s = _make_session()
        s.smbClient = MagicMock()
        s.connected = True
        s.close_smb_session()
        self.assertFalse(s.connected)
        self.assertIsNone(s.smbClient)

    def test_close_dead_connection_still_closes_client(self):
        """ping_smb_session sets connected=False; close must still close."""
        s = _make_session()
        mock_client = MagicMock()
        s.smbClient = mock_client
        s.connected = False  # already marked dead by ping

        s.close_smb_session()

        mock_client.close.assert_called_once()
        self.assertFalse(s.connected)
        self.assertIsNone(s.smbClient)

    def test_close_swallows_underlying_error(self):
        s = _make_session()
        mock_client = MagicMock()
        mock_client.close.side_effect = RuntimeError("broken pipe")
        s.smbClient = mock_client
        s.connected = False

        # Must not raise.
        s.close_smb_session()

        mock_client.close.assert_called_once()
        self.assertFalse(s.connected)
        self.assertIsNone(s.smbClient)

    def test_close_without_smb_client_raises(self):
        s = _make_session()
        s.smbClient = None
        with self.assertRaises(Exception):
            s.close_smb_session()


if __name__ == "__main__":
    unittest.main()
