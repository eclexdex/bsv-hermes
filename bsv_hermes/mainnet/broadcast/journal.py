"""Durable, transaction-identity-only attempt journal; never stores raw tx or keys.

Use an application-owned private directory. This is not a hostile-directory
sandbox or a spend-budget ledger. Keep one shared journal for all callers.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import time


class JournalError(RuntimeError):
    pass


class Journal:
    def __init__(self, path):
        self.path = Path(path)
        try:
            fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise JournalError('journal must be a regular private file')
            if info.st_mode & 0o077:
                raise JournalError('journal permissions must be private')
        else:
            os.close(fd)
        try:
            with self._connect() as db:
                db.execute('CREATE TABLE IF NOT EXISTS attempts ('
                           'network TEXT NOT NULL, txid TEXT NOT NULL, provider TEXT NOT NULL, '
                           'attempts INTEGER NOT NULL, state TEXT NOT NULL, lease_until REAL NOT NULL, '
                           'PRIMARY KEY(network, txid))')
        except sqlite3.Error:
            raise JournalError('journal unavailable') from None

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=0.2)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

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
