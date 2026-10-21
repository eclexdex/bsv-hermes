"""Custody-free BSV spending policy. Authority is trusted local code, not JSON.

No signing/network code. Ledger/state and authority must be protected from the
untrusted tool caller by the embedding application's OS/process boundary.
"""
from __future__ import annotations

import hashlib
import json
import re
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager

MAX_SAT = 2100000000000000
MAX_JSON = 262144
MAX_ITEMS = 128
HEX = re.compile(r'(?:[0-9a-f]{2})*\Z')
IDENT = re.compile(r'[A-Za-z0-9_-]{1,96}\Z')


class PolicyError(ValueError):
    """Fail-closed, deliberately non-secret error code."""


def require(condition, code):
    if not condition:
        raise PolicyError(code)


def integer(value, name, lo=0, hi=MAX_SAT):
    require(type(value) is int and lo <= value <= hi, 'invalid_' + name)
    return value


def keys(value, expected, name):
    require(type(value) is dict and set(value) == set(expected.split()), 'invalid_' + name)


def script(value):
    require(type(value) is str and 0 < len(value) <= 20000 and HEX.fullmatch(value), 'invalid_script')
    return value


def identifier(value):
    require(type(value) is str and IDENT.fullmatch(value), 'invalid_identifier')
    return value


def bounded_json(value):
    """Bound before serialization; reject floats, non-JSON types, and deep trees."""
    budget = [MAX_JSON, 4096]

    def visit(obj, depth=0):
        require(depth <= 12, 'json_too_deep')
        budget[1] -= 1
        require(budget[1] >= 0, 'json_too_many_nodes')
        if type(obj) is str:
            require(len(obj) <= MAX_JSON, 'json_too_large')
            budget[0] -= len(obj.encode('utf-8')) * 6 + 2
        elif type(obj) is dict:
            require(len(obj) <= MAX_ITEMS, 'json_too_many_items')
            for k, v in obj.items():
                require(type(k) is str, 'invalid_json_key')
                visit(k, depth + 1); visit(v, depth + 1)
            budget[0] -= 2 + len(obj) * 2
        elif type(obj) is list:
            require(len(obj) <= MAX_ITEMS, 'json_too_many_items')
            for v in obj:
                visit(v, depth + 1)
            budget[0] -= 2 + len(obj)
        elif type(obj) in (int, bool) or obj is None:
            if type(obj) is int:
                integer(obj, 'json_integer', -MAX_SAT, MAX_SAT)
            budget[0] -= 32
        else:
            raise PolicyError('invalid_json_scalar')
        require(budget[0] >= 0, 'json_too_large')
    visit(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def loads(text):
    require(type(text) in (str, bytes) and len(text) <= MAX_JSON, 'json_too_large')
    def pairs(items):
        d = {}
        for k, v in items:
            require(k not in d, 'duplicate_json_key')
            d[k] = v
        return d
    try:
        result = json.loads(text, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(PolicyError('invalid_json_constant')))
        bounded_json(result)
        return result
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise PolicyError('invalid_json') from exc


def validate_policy(policy):
    bounded_json(policy)
    keys(policy, 'version network total_cap_sat session_cap_sat action_caps_sat min_fee_sat max_fee_sat min_fee_rate_sat_kb max_fee_rate_sat_kb recipient_scripts change_scripts allow_data_outputs', 'policy')
    integer(policy['version'], 'version', 1, 1)
    require(policy['network'] in ('mainnet', 'testnet'), 'explicit_network_required')
    total = integer(policy['total_cap_sat'], 'total_cap_sat', 1)
    session = integer(policy['session_cap_sat'], 'session_cap_sat', 1, total)
    actions = policy['action_caps_sat']
    require(type(actions) is dict and 0 < len(actions) <= 16, 'invalid_actions')
    for action, cap in actions.items():
        identifier(action); integer(cap, 'action_cap_sat', 1, session)
    low = integer(policy['min_fee_sat'], 'min_fee_sat')
    integer(policy['max_fee_sat'], 'max_fee_sat', low)
    low = integer(policy['min_fee_rate_sat_kb'], 'min_fee_rate_sat_kb')
    integer(policy['max_fee_rate_sat_kb'], 'max_fee_rate_sat_kb', low)
    for name in ('recipient_scripts', 'change_scripts'):
        values = policy[name]
        require(type(values) is list and len(values) <= MAX_ITEMS, 'invalid_scripts')
        for v in values:
            script(v)
        require(len(values) == len(set(values)), 'duplicate_scripts')
    require(policy['change_scripts'], 'owner_change_scripts_required')
    require(not set(policy['change_scripts']) & set(policy['recipient_scripts']), 'ambiguous_script_ownership')
    require(type(policy['allow_data_outputs']) is bool, 'invalid_allow_data_outputs')
    return policy


def validate_plan(plan, policy):
    bounded_json(plan)
    validate_policy(policy)
    keys(plan, 'version network action tx_version locktime max_signed_bytes inputs outputs fee_sat', 'plan')
    integer(plan['version'], 'version', 1, 1)
    require(plan['network'] == policy['network'], 'network_mismatch')
    require(type(plan['action']) is str and plan['action'] in policy['action_caps_sat'], 'action_denied')
    integer(plan['tx_version'], 'tx_version', 1, 2)
    integer(plan['locktime'], 'locktime', 0, 4294967295)
    integer(plan['max_signed_bytes'], 'max_signed_bytes', 10, 100000)
    fee = integer(plan['fee_sat'], 'fee_sat', policy['min_fee_sat'], policy['max_fee_sat'])
    ins = plan['inputs']; outs = plan['outputs']
    require(type(ins) is list and 0 < len(ins) <= MAX_ITEMS, 'invalid_inputs')
    require(type(outs) is list and 0 < len(outs) <= MAX_ITEMS, 'invalid_outputs')
    points = set(); input_sat = 0; output_sat = 0; change_sat = 0
    for inp in ins:
        keys(inp, 'txid vout satoshis locking_script sequence', 'input')
        txid = inp['txid']
        require(type(txid) is str and len(txid) == 64 and HEX.fullmatch(txid), 'invalid_txid')
        integer(inp['vout'], 'vout', 0, 4294967295)
        integer(inp['sequence'], 'sequence', 0, 4294967295)
        integer(inp['satoshis'], 'input_satoshis', 1)
        require(script(inp['locking_script']) in policy['change_scripts'], 'input_not_owner_allowlisted')
        point = (txid, inp['vout'])
        require(point not in points, 'duplicate_input')
        points.add(point); input_sat += inp['satoshis']
    for out in outs:
        keys(out, 'satoshis locking_script kind', 'output')
        sat = integer(out['satoshis'], 'output_satoshis')
        locking = script(out['locking_script'])
        kind = out['kind']
        if kind == 'change':
            require(locking in policy['change_scripts'], 'change_not_owner_allowlisted')
            change_sat += sat
        elif kind == 'recipient':
            require(locking in policy['recipient_scripts'], 'destination_denied')
        elif kind == 'data':
            require(policy['allow_data_outputs'] and locking.startswith('006a'), 'data_output_denied')
        else:
            raise PolicyError('invalid_output_kind')
        output_sat += sat
    integer(input_sat, 'total_inputs'); integer(output_sat, 'total_outputs')
    require(input_sat == output_sat + fee, 'unbalanced_plan')
    cost = output_sat - change_sat + fee
    require(cost <= policy['action_caps_sat'][plan['action']], 'action_cap_exceeded')
    return {'input_sat': input_sat, 'output_sat': output_sat, 'change_sat': change_sat,
            'fee_sat': fee, 'irreversible_output_sat': output_sat - change_sat, 'cost_sat': cost}


def plan_digest(session_id, plan):
    identifier(session_id)
    encoded = bounded_json({'domain': 'hermes-bsv-spend-plan-v1', 'session_id': session_id, 'plan': plan})
    return hashlib.sha256(encoded.encode('ascii')).hexdigest()


def clock(now=None):
    return integer(int(time.time()) if now is None else now, 'time', 0, 9223372036854775807)


def private_path(path, exists=True):
    """Basic hardening, not protection against a compromised same-UID process."""
    path = Path(path).absolute()
    require(path.resolve() == path, 'symlink_path_denied')
    parent = path.parent.stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
            and parent.st_mode & 0o077 == 0, 'private_directory_required')
    if exists:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0 and info.st_nlink == 1, 'private_ledger_required')
    return path


@contextmanager
def database(path, write=False):
    path = private_path(path)
    conn = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA synchronous=FULL')
        conn.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        raise PolicyError('ledger_unavailable_or_conflict') from exc
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def audit(c, event, subject):
    c.execute('INSERT INTO events(event,subject,at) VALUES(?,?,?)', (event, subject, clock()))


def read_policy(c):
    row = c.execute('SELECT document FROM policy WHERE id=1').fetchone()
    require(row is not None, 'policy_missing')
    return validate_policy(loads(row['document']))


def session_record(c, session_id):
    r = c.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
    require(r is not None, 'session_not_operator_authorized')
    require(r['closed'] == 0, 'session_closed')
    return r


def usage(c, session_id=None):
    sql = 'SELECT state,cost_sat FROM reservations'
    rows = c.execute(sql + (' WHERE session_id=?' if session_id else ''), (session_id,) if session_id else ())
    reserved = 0; spent = 0
    for r in rows:
        if r['state'] == 'settled':
            spent += r['cost_sat']
        elif r['state'] != 'cancelled':
            reserved += r['cost_sat']
    return {'reserved_sat': reserved, 'spent_sat': spent, 'committed_sat': reserved + spent}


def approval(c, session_id, digest, now):
    r = c.execute('SELECT * FROM approvals WHERE session_id=? AND digest=?', (session_id, digest)).fetchone()
    require(r is not None, 'operator_approval_required')
    require(r['revoked'] == 0, 'approval_revoked')
    require(now < r['expires_at'], 'approval_expired')
    return r


SCHEMA = '''
CREATE TABLE policy(id INTEGER PRIMARY KEY CHECK(id=1), document TEXT NOT NULL);
CREATE TABLE sessions(id TEXT PRIMARY KEY, cap_sat INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE approvals(
 session_id TEXT REFERENCES sessions(id), digest TEXT, plan TEXT NOT NULL,
 expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(session_id,digest));
CREATE TABLE reservations(
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id), digest TEXT NOT NULL,
 cost_sat INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN
 ('reserved','signing','prepared','dispatching','uncertain','settled','cancelled')),
 raw_hex TEXT, txid TEXT, UNIQUE(session_id,digest),
 FOREIGN KEY(session_id,digest) REFERENCES approvals(session_id,digest));
CREATE TABLE input_locks(network TEXT, txid TEXT, vout INTEGER,
 reservation_id TEXT NOT NULL REFERENCES reservations(id), PRIMARY KEY(network,txid,vout));
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,subject TEXT NOT NULL,at INTEGER NOT NULL);
'''


class Authority:
    """Trusted local operator-only administration. NEVER register as agent tools.

    This object does not authenticate a human. The embedding app must restrict
    access to it and the ledger; a supplied approval token is not accepted.
    """
    def __init__(self, db_path):
        self.db_path = private_path(db_path)

    @classmethod
    def create(cls, db_path, policy):
        document = bounded_json(validate_policy(policy))
        path = private_path(db_path, exists=False)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError as exc:
            raise PolicyError('ledger_already_exists') from exc
        os.close(fd)
        c = sqlite3.connect(path)
        try:
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('PRAGMA synchronous=FULL')
            c.executescript(SCHEMA)
            c.execute('INSERT INTO policy(id,document) VALUES(1,?)', (document,))
            audit(c, 'policy_created', '1')
            c.commit()
        finally:
            c.close()
        return cls(path)

    def open_session(self, session_id, cap_sat=None):
        identifier(session_id)
        with database(self.db_path, write=True) as c:
            policy = read_policy(c)
            cap = policy['session_cap_sat'] if cap_sat is None else cap_sat
            integer(cap, 'session_cap_sat', 1, policy['session_cap_sat'])
            require(c.execute('SELECT 1 FROM sessions WHERE id=?', (session_id,)).fetchone() is None, 'session_already_exists')
            c.execute('INSERT INTO sessions(id,cap_sat) VALUES(?,?)', (session_id, cap))
            audit(c, 'session_opened', session_id)

    def approve(self, session_id, plan, expected_digest, *, expires_at, now=None):
        now = clock(now); integer(expires_at, 'expires_at', now + 1, 9223372036854775807)
        digest = plan_digest(session_id, plan)
        require(type(expected_digest) is str and expected_digest == digest, 'review_digest_mismatch')
        with database(self.db_path, write=True) as c:
            session_record(c, session_id)
            validate_plan(plan, read_policy(c))
            require(c.execute('SELECT 1 FROM approvals WHERE session_id=? AND digest=?',
                              (session_id, digest)).fetchone() is None, 'intent_already_approved')
            c.execute('INSERT INTO approvals(session_id,digest,plan,expires_at) VALUES(?,?,?,?)',
                      (session_id, digest, bounded_json(plan), expires_at))
            audit(c, 'plan_approved', digest)
        return digest

    def revoke(self, session_id, digest):
        with database(self.db_path, write=True) as c:
            changed = c.execute('UPDATE approvals SET revoked=1 WHERE session_id=? AND digest=?', (session_id, digest)).rowcount
            require(changed == 1, 'approval_not_found')
            audit(c, 'approval_revoked', digest)

    def close_session(self, session_id):
        with database(self.db_path, write=True) as c:
            require(c.execute('UPDATE sessions SET closed=1 WHERE id=?', (session_id,)).rowcount == 1, 'session_not_found')
            audit(c, 'session_closed', session_id)

    def reconcile_settled(self, reservation_id, network, raw_hex):
        """Operator attests independent acceptance evidence for these exact bytes.

        No network verification is implied. Never expose this method to the model.
        Negative/absent evidence does NOT permit refunding an ambiguous submission.
        """
        with database(self.db_path) as c:
            r = c.execute('SELECT * FROM reservations WHERE id=?', (reservation_id,)).fetchone()
            require(r is not None, 'reservation_not_found')
            require(network == read_policy(c)['network'], 'network_mismatch')
            require(type(raw_hex) is str and raw_hex == r['raw_hex'], 'reconciliation_bytes_mismatch')
            session_id, txid = r['session_id'], r['txid']
        SpendGate(self.db_path, session_id).settle(reservation_id, txid)

    def cancel(self, reservation_id):
        with database(self.db_path, write=True) as c:
            r = c.execute('SELECT * FROM reservations WHERE id=?', (reservation_id,)).fetchone()
            require(r is not None and r['state'] == 'reserved', 'only_unprepared_reservation_cancellable')
            c.execute("UPDATE reservations SET state='cancelled' WHERE id=?", (reservation_id,))
            c.execute('DELETE FROM input_locks WHERE reservation_id=?', (reservation_id,))
            audit(c, 'reservation_cancelled', reservation_id)


class SpendGate:
    """Bind ledger and operator session at trusted construction, never from JSON."""
    def __init__(self, db_path, session_id):
        self.db_path = private_path(db_path)
        self.session_id = identifier(session_id)

    def status(self):
        with database(self.db_path) as c:
            policy = read_policy(c)
            session = c.execute('SELECT * FROM sessions WHERE id=?', (self.session_id,)).fetchone()
            require(session is not None, 'session_not_operator_authorized')
            total = usage(c); current = usage(c, self.session_id)
            total.update(cap_sat=policy['total_cap_sat'], remaining_sat=policy['total_cap_sat'] - total['committed_sat'])
            current.update(cap_sat=session['cap_sat'], remaining_sat=session['cap_sat'] - current['committed_sat'])
            return {'network': policy['network'], 'session_id': self.session_id,
                    'session_closed': bool(session['closed']), 'total': total, 'session': current}

    def check(self, plan, *, now=None):
        """Advisory inspection only; cannot substitute for atomic reserve."""
        now = clock(now)
        digest = plan_digest(self.session_id, plan)
        with database(self.db_path) as c:
            session_record(c, self.session_id)
            account = validate_plan(plan, read_policy(c))
            a = c.execute('SELECT * FROM approvals WHERE session_id=? AND digest=?', (self.session_id, digest)).fetchone()
            state = 'missing' if a is None else ('revoked' if a['revoked'] else
                    ('expired' if now >= a['expires_at'] else 'approved'))
            return {**account, 'plan_digest': digest, 'approval_status': state,
                    'advisory_only': True, 'network': plan['network']}

    def reserve(self, plan, *, now=None):
        now = clock(now)
        digest = plan_digest(self.session_id, plan)
        with database(self.db_path, write=True) as c:
            policy = read_policy(c); account = validate_plan(plan, policy)
            session = session_record(c, self.session_id)
            prior = c.execute('SELECT * FROM reservations WHERE session_id=? AND digest=?', (self.session_id, digest)).fetchone()
            if prior:
                require(prior['state'] != 'cancelled', 'intent_cancelled')
                return {'reservation_id': prior['id'], 'created': False, 'state': prior['state'], 'cost_sat': prior['cost_sat']}
            approval(c, self.session_id, digest, now)
            cost = account['cost_sat']
            require(usage(c, self.session_id)['committed_sat'] + cost <= session['cap_sat'], 'session_cap_exceeded')
            require(usage(c)['committed_sat'] + cost <= policy['total_cap_sat'], 'total_cap_exceeded')
            for inp in plan['inputs']:
                require(c.execute('SELECT 1 FROM input_locks WHERE network=? AND txid=? AND vout=?',
                                  (plan['network'], inp['txid'], inp['vout'])).fetchone() is None, 'input_already_reserved')
            rid = uuid.uuid4().hex
            c.execute("INSERT INTO reservations(id,session_id,digest,cost_sat,state) VALUES(?,?,?,?,'reserved')",
                      (rid, self.session_id, digest, cost))
            for inp in plan['inputs']:
                c.execute('INSERT INTO input_locks VALUES(?,?,?,?)', (plan['network'], inp['txid'], inp['vout'], rid))
            audit(c, 'funds_reserved', rid)
            return {'reservation_id': rid, 'created': True, 'state': 'reserved', 'cost_sat': cost}

    def _record(self, c, reservation_id):
        identifier(reservation_id)
        r = c.execute('SELECT * FROM reservations WHERE id=? AND session_id=?', (reservation_id, self.session_id)).fetchone()
        require(r is not None, 'reservation_not_found')
        return r

    def receipt(self, reservation_id):
        with database(self.db_path) as c:
            r = self._record(c, reservation_id)
            a = c.execute('SELECT plan FROM approvals WHERE session_id=? AND digest=?',
                          (self.session_id, r['digest'])).fetchone()
            stored = loads(a['plan'])
            require(plan_digest(self.session_id, stored) == r['digest'], 'stored_plan_digest_mismatch')
            account = validate_plan(stored, read_policy(c))
            require(account['cost_sat'] == r['cost_sat'], 'stored_cost_mismatch')
            return {**account, 'reservation_id': r['id'], 'state': r['state'], 'txid': r['txid'],
                    'network': read_policy(c)['network'], 'plan_digest': r['digest'],
                    'confirmations': None, 'chain_verified': False}

    def begin_signing(self, reservation_id, *, now=None):
        """Durable no-refund boundary BEFORE invoking any signing adapter.

        Revocation/cancellation/closure wins if committed before this claim. Once
        claimed, even a crash or signing failure must keep input locks and budget.
        Never expose this transition as a native caller operation.
        """
        with database(self.db_path, write=True) as c:
            r = self._record(c, reservation_id)
            require(r['state'] == 'reserved', 'reservation_not_reserved')
            session_record(c, self.session_id)
            approval(c, self.session_id, r['digest'], clock(now))
            c.execute("UPDATE reservations SET state='signing' WHERE id=?", (reservation_id,))
            audit(c, 'signing_started', reservation_id)

    def prepare(self, reservation_id, raw_hex, *, now=None):
        with database(self.db_path, write=True) as c:
            r = self._record(c, reservation_id)
            require(r['state'] == 'signing', 'reservation_not_signing')
            session_record(c, self.session_id)
            a = approval(c, self.session_id, r['digest'], clock(now))
            stored = loads(a['plan'])
            require(plan_digest(self.session_id, stored) == r['digest'], 'stored_plan_digest_mismatch')
            tx = validate_signed_transaction(raw_hex, stored, read_policy(c))
            require(tx['cost_sat'] == r['cost_sat'], 'stored_cost_mismatch')
            c.execute("UPDATE reservations SET state='prepared',raw_hex=?,txid=? WHERE id=?",
                      (raw_hex, tx['txid'], reservation_id))
            audit(c, 'signed_bytes_prepared', reservation_id)
        return self.receipt(reservation_id)

    def begin_dispatch(self, reservation_id, *, now=None):
        with database(self.db_path, write=True) as c:
            r = self._record(c, reservation_id)
            require(r['state'] == 'prepared', 'reservation_not_prepared')
            session_record(c, self.session_id)
            approval(c, self.session_id, r['digest'], clock(now))
            c.execute("UPDATE reservations SET state='dispatching' WHERE id=?", (reservation_id,))
            audit(c, 'dispatch_started', reservation_id)
            return {'network': read_policy(c)['network'], 'raw_hex': r['raw_hex'], 'txid': r['txid']}

    def uncertain(self, reservation_id):
        with database(self.db_path, write=True) as c:
            r = self._record(c, reservation_id)
            require(r['state'] in ('dispatching', 'uncertain'), 'reservation_not_dispatching')
            if r['state'] == 'dispatching':
                c.execute("UPDATE reservations SET state='uncertain' WHERE id=?", (reservation_id,))
                audit(c, 'dispatch_ambiguous', reservation_id)
        return self.receipt(reservation_id)

    def settle(self, reservation_id, txid):
        """Trusted transport/operator receipt only; not an agent-facing operation."""
        with database(self.db_path, write=True) as c:
            r = self._record(c, reservation_id)
            require(r['state'] in ('dispatching', 'uncertain', 'settled'), 'reservation_not_submitted')
            require(type(txid) is str and txid == r['txid'], 'settlement_txid_mismatch')
            if r['state'] != 'settled':
                c.execute("UPDATE reservations SET state='settled' WHERE id=?", (reservation_id,))
                audit(c, 'spend_settled', reservation_id)
        return self.receipt(reservation_id)


def validate_signed_transaction(raw_hex, plan, policy):
    """Parse bounded canonical legacy serialization and bind all economic fields.

    This is NOT script/signature/consensus validation. Prevout values must also be
    independently supplied by the trusted lookup in GuardedExecutor.
    """
    account = validate_plan(plan, policy)
    require(type(raw_hex) is str and 20 <= len(raw_hex) <= plan['max_signed_bytes'] * 2
            and HEX.fullmatch(raw_hex), 'invalid_signed_transaction')
    raw = bytes.fromhex(raw_hex)
    pos = 0
    def take(n):
        nonlocal pos
        require(0 <= n <= len(raw) - pos, 'transaction_truncated')
        v = raw[pos:pos+n]; pos += n
        return v
    def uint(n):
        return int.from_bytes(take(n), 'little')
    def varint():
        tag = uint(1)
        if tag < 253:
            return tag
        n = {253: 2, 254: 4, 255: 8}[tag]
        val = uint(n)
        require(val >= {2: 253, 4: 65536, 8: 4294967296}[n], 'noncanonical_varint')
        return val
    require(uint(4) == plan['tx_version'], 'tx_version_mismatch')
    require(varint() == len(plan['inputs']), 'input_count_mismatch')
    for inp in plan['inputs']:
        require(take(32)[::-1].hex() == inp['txid'] and uint(4) == inp['vout'], 'input_outpoint_mismatch')
        length = varint()
        require(0 < length <= 10000, 'invalid_unlocking_script_length')
        take(length)
        require(uint(4) == inp['sequence'], 'input_sequence_mismatch')
    require(varint() == len(plan['outputs']), 'output_count_mismatch')
    for out in plan['outputs']:
        require(uint(8) == out['satoshis'], 'output_amount_mismatch')
        length = varint()
        require(length <= 10000, 'locking_script_too_large')
        require(take(length).hex() == out['locking_script'], 'output_script_mismatch')
    require(uint(4) == plan['locktime'], 'locktime_mismatch')
    require(pos == len(raw), 'transaction_trailing_bytes')
    size = len(raw)
    fee_scaled = account['fee_sat'] * 1000
    require(policy['min_fee_rate_sat_kb'] * size <= fee_scaled <= policy['max_fee_rate_sat_kb'] * size,
            'fee_rate_out_of_bounds')
    return {**account, 'size_bytes': size,
            'txid': hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()}


class GuardedExecutor:
    """Trusted integration boundary. Callbacks never come from native arguments.

    sign(plan)->canonical raw hex: MUST NOT broadcast, reserve elsewhere, or
    change the intent. lookup_prevout(network,txid,vout)->exact independently
    verified record. broadcast(network,raw_hex,txid)->acceptance record; MUST use
    the explicit network, never perform automatic cross-network fallback.
    """
    def __init__(self, gate, *, lookup_prevout, sign, broadcast):
        require(isinstance(gate, SpendGate), 'invalid_gate')
        require(all(callable(x) for x in (lookup_prevout, sign, broadcast)), 'callbacks_required')
        self.gate = gate
        self.lookup_prevout = lookup_prevout
        self.sign = sign
        self.broadcast = broadcast

    def execute(self, plan, *, now=None):
        # Isolate caller/callback mutations from the approved canonical snapshot.
        frozen = loads(bounded_json(plan))
        reservation = self.gate.reserve(frozen, now=now)
        rid = reservation['reservation_id']
        if not reservation['created']:
            # Never re-sign/rebroadcast/reallocate a replay, including after crash.
            return self.gate.receipt(rid)
        try:
            for inp in frozen['inputs']:
                try:
                    record = self.lookup_prevout(frozen['network'], inp['txid'], inp['vout'])
                except Exception:
                    raise PolicyError('prevout_lookup_failed_reservation_held') from None
                keys(record, 'network txid vout satoshis locking_script', 'prevout_record')
                integer(record['satoshis'], 'prevout_satoshis', 1)
                integer(record['vout'], 'prevout_vout', 0, 4294967295)
                expected = {k: inp[k] for k in ('txid', 'vout', 'satoshis', 'locking_script')}
                expected['network'] = frozen['network']
                require(record == expected, 'prevout_mismatch')
            # Claim before invoking custody: a crash/exception may have produced
            # valid signed bytes even when this process never receives them.
            self.gate.begin_signing(rid, now=now)
            try:
                raw_hex = self.sign(loads(bounded_json(frozen)))
            except Exception:
                raise PolicyError('signing_failed_reservation_held') from None
            self.gate.prepare(rid, raw_hex, now=now)
            outgoing = self.gate.begin_dispatch(rid, now=now)
        except PolicyError:
            raise
        except Exception as exc:
            raise PolicyError('pre_dispatch_failed_reservation_held') from exc
        try:
            result = self.broadcast(outgoing['network'], outgoing['raw_hex'], outgoing['txid'])
            keys(result, 'accepted network txid', 'broadcast_receipt')
            require(result['accepted'] is True and result['network'] == outgoing['network']
                    and result['txid'] == outgoing['txid'], 'broadcast_not_confirmed')
        except Exception:
            # Includes explicit rejects: only independent reconciliation can know
            # whether these bytes reached another node; never refund automatically.
            return self.gate.uncertain(rid)
        return self.gate.settle(rid, outgoing['txid'])
