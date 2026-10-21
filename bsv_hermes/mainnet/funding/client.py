"""Snapshot algorithm. All values from the public provider remain observations."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import math
import re
import threading
import time

from . import BASE, MAX_MONEY, NETWORKS, PublicTarget, FundingError, _fail
from .codec import parse_transaction


@dataclass(frozen=True)
class HTTPReply:
    status: int
    body: bytes
    headers: dict = field(default_factory=dict)


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _integer(value, minimum=0, maximum=MAX_MONEY, code="PROVIDER_RESPONSE"):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(code)
    return value


def _unconfirmed_height(value):
    if value is not None and (type(value) is not int or value not in (0, -1)):
        _fail()


def _txid(value):
    if type(value) is not str or not re.fullmatch("[0-9a-f]{64}", value):
        _fail()
    return value


def _json(reply):
    content_type = reply.headers.get("content-type", "")
    if type(content_type) is not str or content_type.split(";", 1)[0].strip().lower() != "application/json":
        _fail()
    try:
        def no_duplicates(pairs):
            obj = {}
            for k, v in pairs:
                if k in obj:
                    _fail()
                obj[k] = v
            return obj
        return json.loads(reply.body.decode("utf-8"), parse_float=Decimal,
                          parse_constant=lambda _: _fail(), object_pairs_hook=no_duplicates)
    except (ValueError, UnicodeError, RecursionError):
        _fail()


@dataclass(frozen=True)
class Limits:
    request_timeout: float = 8.0
    total_timeout: float = 45.0
    max_response_bytes: int = 262144
    max_total_bytes: int = 2097152
    max_requests: int = 64
    max_utxos: int = 20

    def __post_init__(self):
        for name, maximum in (("request_timeout", 30), ("total_timeout", 120)):
            value = getattr(self, name)
            if (type(value) not in (int, float) or not math.isfinite(value)
                    or not 0.001 <= value <= maximum):
                _fail("INVALID_POLICY")
        for name, maximum in (("max_response_bytes", 1048576), ("max_total_bytes", 8388608),
                              ("max_requests", 64), ("max_utxos", 20)):
            _integer(getattr(self, name), 1, maximum, "INVALID_POLICY")


# A single process-wide gate prevents separate clients from bursting the free
# service quota. Separate operating-system processes still need caller coordination.
_PUBLIC_GATE = threading.Lock()
_PUBLIC_NEXT_REQUEST = 0.0


class FundingClient:
    def __init__(self, *, transport=None, request_interval=0.34, limits=None):
        if (type(request_interval) not in (int, float) or not math.isfinite(request_interval)
                or not 0 <= request_interval <= 2 or (transport is None and request_interval < 0.34)):
            _fail("INVALID_POLICY")
        if transport is None:
            from .transport import HttpsTransport
            transport = HttpsTransport()
            self._public = True
        else:
            self._public = False
        if not callable(transport) or (limits is not None and not isinstance(limits, Limits)):
            _fail("INVALID_POLICY")
        self.transport = transport
        self.request_interval = request_interval
        self.limits = limits or Limits()

    def funding(self, target, *, required_satoshis=1, min_confirmations=1):
        _integer(required_satoshis, 1, code="INVALID_POLICY")
        result = self.discover(target, min_confirmations=min_confirmations)
        result.update(required_satoshis=required_satoshis,
                      funded=result["eligible_satoshis"] >= required_satoshis)
        return result

    def discover(self, target, *, min_confirmations=1):
        if not isinstance(target, PublicTarget):
            _fail("INVALID_TARGET")
        _integer(min_confirmations, 0, 1000, "INVALID_POLICY")
        base = BASE + "/" + NETWORKS[target.network]
        records = []
        started = _utc()
        deadline = time.monotonic() + self.limits.total_timeout
        byte_count = 0
        next_request = 0.0

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                _fail("TIMEOUT")
            return value

        def request(path, allow_unspent=False):
            global _PUBLIC_NEXT_REQUEST
            nonlocal byte_count, next_request
            remaining()
            if len(records) >= self.limits.max_requests:
                _fail("RESOURCE_LIMIT")
            url = base + path
            acquired = False
            try:
                if self._public:
                    acquired = _PUBLIC_GATE.acquire(timeout=remaining())
                    if not acquired:
                        _fail("TIMEOUT")
                wait_until = _PUBLIC_NEXT_REQUEST if self._public else next_request
                delay = max(0, wait_until - time.monotonic())
                if delay >= remaining():
                    _fail("TIMEOUT")
                if delay:
                    time.sleep(delay)
                next_request = time.monotonic() + self.request_interval
                if self._public:
                    _PUBLIC_NEXT_REQUEST = next_request
                reply = self.transport(url, timeout=min(self.limits.request_timeout, remaining()),
                                       max_bytes=self.limits.max_response_bytes)
            except FundingError:
                raise
            except TimeoutError:
                _fail("TIMEOUT")
            except Exception:
                _fail("NETWORK_ERROR")
            finally:
                if acquired:
                    _PUBLIC_GATE.release()
            remaining()
            if (not isinstance(reply, HTTPReply) or type(reply.status) is not int
                    or type(reply.body) is not bytes or type(reply.headers) is not dict):
                _fail()
            if any(type(k) is not str or type(v) is not str for k, v in reply.headers.items()):
                _fail()
            if reply.headers.get("next-page"):
                _fail("RESOURCE_LIMIT")
            if reply.headers.get("content-encoding", "identity").lower() != "identity":
                _fail()
            byte_count += len(reply.body)
            if (len(reply.body) > self.limits.max_response_bytes
                    or byte_count > self.limits.max_total_bytes):
                _fail("RESOURCE_LIMIT")
            records.append({"url": url, "method": "GET", "status": reply.status,
                            "observed_at": _utc(), "body_sha256": hashlib.sha256(reply.body).hexdigest(),
                            "body_bytes": len(reply.body)})
            if reply.status == 429:
                _fail("RATE_LIMITED")
            if reply.status == 404 and allow_unspent:
                if (reply.body != b"Not Found" or not str(reply.headers.get("content-type", "")).startswith("text/plain")):
                    _fail()
                return reply
            if reply.status != 200:
                _fail("PROVIDER_HTTP")
            return reply

        def listing():
            data = _json(request("/address/" + target.address + "/unspent/all"))
            if (type(data) is not dict or data.get("address") != target.address
                    or data.get("script") != target.script_hash or data.get("error") != ""
                    or type(data.get("result")) is not list):
                _fail()
            if set(data) - {"address", "script", "result", "error", "next-page"}:
                _fail()
            if data.get("next-page") or len(data["result"]) > self.limits.max_utxos:
                _fail("RESOURCE_LIMIT")
            rows = []
            seen = set()
            for row in data["result"]:
                if (type(row) is not dict or set(row) - {
                        "height", "tx_pos", "tx_hash", "value", "isSpentInMempoolTx", "status", "hex"}):
                    _fail()
                if "hex" in row and row["hex"] != target.locking_script_hex:
                    _fail()
                txid = _txid(row.get("tx_hash"))
                index = _integer(row.get("tx_pos"), 0, 4294967295)
                if (txid, index) in seen:
                    _fail("CONFLICT")
                seen.add((txid, index))
                value = _integer(row.get("value"), 1)
                if type(row.get("isSpentInMempoolTx")) is not bool:
                    _fail()
                status = row.get("status")
                if status == "confirmed":
                    height = _integer(row.get("height"), 1, 2147483647)
                elif status == "unconfirmed":
                    _unconfirmed_height(row.get("height"))
                    height = 0
                else:
                    _fail()
                rows.append({"txid": txid, "vout": index, "satoshis": value,
                             "height": height, "status": status,
                             "mempool_spent": row["isSpentInMempoolTx"]})
            return sorted(rows, key=lambda r: (r["txid"], r["vout"]))

        rows = listing()
        transactions = {}
        utxos = []
        excluded = []
        for row in rows:
            txid, index = row["txid"], row["vout"]
            if txid not in transactions:
                reply = request("/tx/" + txid + "/hex")
                try:
                    raw = reply.body.decode("ascii").strip()
                except UnicodeError:
                    _fail()
                tx = parse_transaction(raw, txid)
                details = _json(request("/tx/hash/" + txid))
                if type(details) is not dict or details.get("txid") != txid:
                    _fail()
                transactions[txid] = (tx, details, raw)
            tx, details, raw = transactions[txid]
            if index >= len(tx["outputs"]):
                _fail()
            if tx["outputs"][index] != (row["satoshis"], target.locking_script_hex):
                _fail()
            if row["status"] == "confirmed":
                confirmations = _integer(details.get("confirmations"), 1, 2147483647)
                if _integer(details.get("blockheight"), 1, 2147483647) != row["height"]:
                    _fail()
                _txid(details.get("blockhash"))
            else:
                confirmations = 0
                _integer(details.get("confirmations", 0), 0, 0)
                _unconfirmed_height(details.get("blockheight"))
                if details.get("blockhash"):
                    _fail()
            reason = "mempool_spent" if row["mempool_spent"] else None
            if not reason:
                spent = request(f"/tx/{txid}/{index}/spent", allow_unspent=True)
                if spent.status == 200:
                    report = _json(spent)
                    if (type(report) is not dict or set(report) != {"txid", "vin", "status"}
                            or report["status"] not in ("confirmed", "unconfirmed")):
                        _fail()
                    _txid(report["txid"])
                    _integer(report["vin"], 0, 4294967295)
                    reason = "provider_reports_spent"
            if not reason and tx["coinbase"] and confirmations < 100:
                reason = "immature_coinbase"
            if not reason and confirmations < min_confirmations:
                reason = "below_confirmation_policy"
            output = {"txid": txid, "vout": index, "satoshis": row["satoshis"],
                      "locking_script_hex": target.locking_script_hex,
                      "height": row["height"], "confirmations": confirmations,
                      "coinbase": tx["coinbase"], "source_transaction_hex": raw,
                      "verification": "raw-txid-value-script-bound; provider-chain-and-spent-status"}
            if reason:
                output["reason"] = reason
                excluded.append(output)
            else:
                utxos.append(output)
        inputs_seen = {}
        all_outpoints = {(r["txid"], r["vout"]) for r in rows}
        for txid, (tx, _, _) in transactions.items():
            if tx["coinbase"]:
                continue
            for previous in tx["inputs"]:
                if previous in inputs_seen:
                    _fail("CONFLICT")
                inputs_seen[previous] = txid
        # A provider may include a parent and its spending child. Never return
        # the already-consumed parent as eligible, even if its flag is stale.
        consumed = all_outpoints & inputs_seen.keys()
        for output in utxos[:]:
            if (output["txid"], output["vout"]) in consumed:
                output["reason"] = "spent_by_candidate_transaction"
                excluded.append(output)
                utxos.remove(output)
        if listing() != rows:
            _fail("SNAPSHOT_CHANGED")
        remaining()
        eligible_satoshis = _integer(sum(u["satoshis"] for u in utxos))
        return {"schema": "bsv-funding-snapshot/v1", "network": target.network,
                "address": target.address, "locking_script_hex": target.locking_script_hex,
                "min_confirmations": min_confirmations, "utxos": utxos,
                "excluded": excluded, "eligible_satoshis": eligible_satoshis,
                "observation_complete": True, "consensus_verified": False,
                "provenance": {"provider": "whatsonchain", "base_url": base,
                               "started_at": started, "completed_at": _utc(),
                               "trust": "single-provider-observation-not-SPV",
                               "requests": records}}
