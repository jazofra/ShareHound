#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from sharehound.worker import ConnectionPool


class _FakeSession:
    """Fake SMBSession that reports how long ping/close block the caller."""

    def __init__(self, alive: bool = True, op_delay: float = 0.0):
        self._alive = alive
        self._op_delay = op_delay
        self.ping_calls = 0
        self.close_calls = 0

    def ping_smb_session(self) -> bool:
        self.ping_calls += 1
        if self._op_delay:
            time.sleep(self._op_delay)
        return self._alive

    def close_smb_session(self):
        self.close_calls += 1
        if self._op_delay:
            time.sleep(self._op_delay)


class ConnectionPoolLockScopeTests(unittest.TestCase):
    def test_pooled_ping_runs_outside_lock(self):
        pool = ConnectionPool(max_connections_per_host=2)
        slow_session = _FakeSession(alive=True, op_delay=0.2)
        pool._connections["host-a"].append(slow_session)

        options = MagicMock()
        other_thread_saw_lock_free = threading.Event()

        def watcher():
            # If the lock is held across the network I/O in ping, this
            # acquire will block until the ping finishes.
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                if pool._lock.acquire(blocking=False):
                    try:
                        other_thread_saw_lock_free.set()
                        return
                    finally:
                        pool._lock.release()
                time.sleep(0.01)

        t = threading.Thread(target=watcher)
        t.start()
        # Let the watcher start before we enter get_connection.
        time.sleep(0.02)
        got = pool.get_connection("host-a", "host-a", options, MagicMock(), MagicMock())
        t.join()

        self.assertIs(got, slow_session)
        self.assertEqual(slow_session.ping_calls, 1)
        self.assertTrue(
            other_thread_saw_lock_free.is_set(),
            "ConnectionPool lock was held across ping_smb_session",
        )

    def test_return_connection_full_pool_closes_outside_lock(self):
        pool = ConnectionPool(max_connections_per_host=1)
        pool._connections["host-a"].append(_FakeSession())

        slow_session = _FakeSession(op_delay=0.2)
        other_thread_saw_lock_free = threading.Event()

        def watcher():
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                if pool._lock.acquire(blocking=False):
                    try:
                        other_thread_saw_lock_free.set()
                        return
                    finally:
                        pool._lock.release()
                time.sleep(0.01)

        t = threading.Thread(target=watcher)
        t.start()
        time.sleep(0.02)
        pool.return_connection("host-a", slow_session)
        t.join()

        self.assertEqual(slow_session.close_calls, 1)
        self.assertTrue(
            other_thread_saw_lock_free.is_set(),
            "ConnectionPool lock was held across close_smb_session",
        )

    def test_close_all_closes_outside_lock(self):
        pool = ConnectionPool(max_connections_per_host=2)
        sessions = [_FakeSession(op_delay=0.1) for _ in range(3)]
        pool._connections["host-a"].extend(sessions[:2])
        pool._connections["host-b"].append(sessions[2])

        other_thread_saw_lock_free = threading.Event()

        def watcher():
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                if pool._lock.acquire(blocking=False):
                    try:
                        other_thread_saw_lock_free.set()
                        return
                    finally:
                        pool._lock.release()
                time.sleep(0.01)

        t = threading.Thread(target=watcher)
        t.start()
        time.sleep(0.02)
        pool.close_all()
        t.join()

        for s in sessions:
            self.assertEqual(s.close_calls, 1)
        self.assertTrue(
            other_thread_saw_lock_free.is_set(),
            "ConnectionPool lock was held across close_all's close_smb_session calls",
        )
        self.assertEqual(pool._connections, {})

    def test_new_connection_path_does_not_hold_lock_during_init(self):
        pool = ConnectionPool(max_connections_per_host=2)
        options = MagicMock()
        # parse_lm_nt_hashes will see these values — they must be real strings.
        options.auth_domain = ""
        options.auth_user = "u"
        options.auth_password = "p"
        options.auth_hashes = None
        options.use_kerberos = False
        options.auth_key = None
        options.kdc_host = None
        options.advertised_name = None
        logger = MagicMock()
        other_thread_saw_lock_free = threading.Event()

        def watcher():
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                if pool._lock.acquire(blocking=False):
                    try:
                        other_thread_saw_lock_free.set()
                        return
                    finally:
                        pool._lock.release()
                time.sleep(0.01)

        fake_session = MagicMock()

        def slow_constructor(*_a, **_kw):
            time.sleep(0.2)
            return fake_session

        with patch("sharehound.worker.SMBSession", side_effect=slow_constructor):
            fake_session.init_smb_session.return_value = True
            t = threading.Thread(target=watcher)
            t.start()
            time.sleep(0.02)
            got = pool.get_connection("host-new", "host-new", options, MagicMock(), logger)
            t.join()

        self.assertIs(got, fake_session)
        self.assertTrue(
            other_thread_saw_lock_free.is_set(),
            "ConnectionPool lock was held across new SMB session construction",
        )


if __name__ == "__main__":
    unittest.main()
