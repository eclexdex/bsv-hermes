"""Durable, transaction-identity-only attempt journal; never stores raw tx or keys.

Use an application-owned private directory. This is not a hostile-directory
sandbox or a spend-budget ledger. Keep one shared journal for all callers.
The live instance pins one SQLite connection and never reopens its pathname.
Identity checks detect replacement but are NOT a hostile-filesystem race proof:
initial SQLite open and its auxiliary files still require a trusted directory.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time


class JournalError(RuntimeError):
    pass


class Journal:
    def __init__(self, path):
        self.path = Path(os.path.abspath(path))
        self._db = None
        self._lock = threading.RLock()
        try:
            fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        # Do not keep an extra OS fd for the database: closing it can release
        # SQLite's process-wide POSIX locks held by another live connection.
        # Only SQLite owns persistent database descriptors. Initial opening is
        # explicitly inside the trusted-directory boundary, not a race sandbox.
        info = self.path.lstat()
        self._identity = (info.st_dev, info.st_ino)
        try:
            self._check_identity()
            # Pin the live SQLite connection; never reopen a replacement pathname.
            self._db = sqlite3.connect(str(self.path), timeout=0.2, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            with self._connect() as db:
                db.execute('CREATE TABLE IF NOT EXISTS attempts ('
                           'network TEXT NOT NULL, txid TEXT NOT NULL, provider TEXT NOT NULL, '
                           'attempts INTEGER NOT NULL, state TEXT NOT NULL, lease_until REAL NOT NULL, '
                           'PRIMARY KEY(network, txid))')
        except (sqlite3.Error, JournalError):
            self.close()
            raise JournalError('journal unavailable') from None

    def _check_identity(self):
        try:
            info = self.path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_mode & 0o077 or (info.st_dev, info.st_ino) != self._identity):
                raise JournalError('journal identity or permissions changed')
        except OSError:
            raise JournalError('journal unavailable') from None

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None


    def __del__(self):
        if hasattr(self, '_lock'):
            self.close()

    @contextmanager
    def _connect(self):
        with self._lock:
            self._check_identity()
            if self._db is None:
                raise JournalError('journal closed')
            with self._db:
                yield self._db

    def get(self, network, txid):
        try:
            with self._connect() as db:
                row = db.execute('SELECT * FROM attempts WHERE network=? AND txid=?', (network, txid)).fetchone()
                return dict(row) if row else None
        except sqlite3.Error:
            raise JournalError('journal unavailable') from None

    def claim(self, network, txid, provider, *, retry=False):
        try:
            with self._connect() as db:
                db.execute('BEGIN IMMEDIATE')
                row = db.execute('SELECT * FROM attempts WHERE network=? AND txid=?', (network, txid)).fetchone()
                if row is not None:
                    if (retry is not True or row['provider'] != provider or row['attempts'] >= 2
                            or row['state'] != 'ambiguous' or row['lease_until'] > time.time()):
                        return False
                    db.execute('UPDATE attempts SET attempts=attempts+1, lease_until=? '
                               'WHERE network=? AND txid=?', (time.time() + 35, network, txid))
                    return True
                if db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0] >= 10000:
                    raise JournalError('journal capacity reached; do not delete unresolved records')
                db.execute('INSERT INTO attempts VALUES (?, ?, ?, 1, ?, ?)',
                           (network, txid, provider, 'ambiguous', time.time() + 35))
                return True
        except sqlite3.Error:
            raise JournalError('journal unavailable') from None

    def observe(self, network, txid, provider, state):
        """Remember non-ambiguous readback without claiming a POST or its lease."""
        if state not in ('seen', 'accepted', 'processing', 'mined',
                         'rejected', 'conflict', 'identity_mismatch'):
            return
        try:
            with self._connect() as db:
                db.execute('BEGIN IMMEDIATE')
                row = db.execute('SELECT * FROM attempts WHERE network=? AND txid=?',
                                 (network, txid)).fetchone()
                if row is not None:
                    if row['provider'] != provider:
                        raise JournalError('observation provider differs from pinned provider')
                    db.execute("UPDATE attempts SET state=CASE WHEN state='identity_mismatch' "
                               'THEN state ELSE ? END WHERE network=? AND txid=?',
                               (state, network, txid))
                else:
                    if db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0] >= 10000:
                        raise JournalError('journal capacity reached; keep unresolved records')
                    db.execute('INSERT INTO attempts VALUES (?, ?, ?, 0, ?, 0)',
                               (network, txid, provider, state))
        except sqlite3.Error:
            raise JournalError('journal unavailable') from None

    def finish(self, network, txid, state):
        try:
            with self._connect() as db:
                # A stale ambiguous completion must not make an observed tx
                # retryable again. Merge in SQLite, atomically with the update.
                db.execute("UPDATE attempts SET state=CASE WHEN state='identity_mismatch' THEN state "
                           "WHEN ?='ambiguous' "
                           "AND state!='ambiguous' THEN state ELSE ? END, lease_until=0 "
                           'WHERE network=? AND txid=?', (state, state, network, txid))
        except sqlite3.Error:
            raise JournalError('journal unavailable') from None
