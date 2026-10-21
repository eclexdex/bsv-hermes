"""Single fixed-host GET in a killable stdlib worker with no inherited environment.

The outer process deadline also bounds DNS and slow trickle bodies (urllib's
socket timeout alone does not). No shell, proxy configuration, cookies, auth,
redirect following, response decompression, or arbitrary endpoint inputs.
"""
import json
import math
import re
import subprocess
import sys

from . import FundingError, _fail
from .client import HTTPReply

_WORKER = r'''
import json, socket, sys, urllib.error, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
try:
    options = json.loads(sys.stdin.buffer.read(8192))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(options["url"], method="GET", headers={
        "Accept": "application/json, text/plain", "Accept-Encoding": "identity",
        "Cache-Control": "no-cache", "User-Agent": "bsv-hermes-funding/1"})
    try:
        response = opener.open(request, timeout=options["timeout"])
    except urllib.error.HTTPError as response_error:
        response = response_error
    with response:
        headers = {k: response.headers[k] for k in (
            "content-type", "content-encoding", "date", "x-request-id", "next-page")
            if response.headers.get(k) is not None}
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise ValueError()
        lengths = response.headers.get_all("content-length", [])
        transfers = response.headers.get_all("transfer-encoding", [])
        if len(lengths) > 1 or (lengths and transfers):
            raise ValueError()
        if transfers and (len(transfers) != 1 or transfers[0].lower().strip() != "chunked"):
            raise ValueError()
        length = lengths[0] if lengths else None
        if length is not None and (not length.isdigit() or int(length) > options["max_bytes"]):
            print(json.dumps({"error": "RESOURCE_LIMIT"})); sys.exit(0)
        body = response.read(options["max_bytes"] + 1)
        if len(body) > options["max_bytes"]:
            print(json.dumps({"error": "RESOURCE_LIMIT"})); sys.exit(0)
        if length is not None and len(body) != int(length):
            raise ValueError()
        print(json.dumps({"status": response.status, "headers": headers, "body_hex": body.hex()}))
except (TimeoutError, socket.timeout):
    print(json.dumps({"error": "TIMEOUT"}))
except urllib.error.URLError as error:
    print(json.dumps({"error": "TIMEOUT" if isinstance(error.reason, TimeoutError) else "NETWORK_ERROR"}))
except Exception:
    print(json.dumps({"error": "NETWORK_ERROR"}))
'''

# Read-only routes only; not even alternate WoC APIs are addressable.
_ROUTE = re.compile(r"https://api\.whatsonchain\.com/v1/bsv/(main|test)/(?:"
                    r"address/[1-9A-HJ-NP-Za-km-z]{26,35}/unspent/all|"
                    r"tx/[0-9a-f]{64}/hex|tx/hash/[0-9a-f]{64}|"
                    r"tx/[0-9a-f]{64}/[0-9]{1,10}/spent)")


class HttpsTransport:
    def __call__(self, url, *, timeout, max_bytes):
        if type(url) is not str or _ROUTE.fullmatch(url) is None:
            _fail("INVALID_TARGET")
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 30 or type(max_bytes) is not int
                or not 1 <= max_bytes <= 1048576):
            _fail("INVALID_POLICY")
        wire = json.dumps({"url": url, "timeout": timeout, "max_bytes": max_bytes}).encode()
        try:
            completed = subprocess.run([sys.executable, "-I", "-S", "-c", _WORKER],
                                       input=wire, capture_output=True, timeout=timeout,
                                       env={}, check=False, close_fds=True)
        except subprocess.TimeoutExpired:
            _fail("TIMEOUT")
        except OSError:
            _fail("NETWORK_ERROR")
        if completed.returncode != 0 or len(completed.stdout) > max_bytes * 2 + 16384:
            _fail("NETWORK_ERROR")
        try:
            payload = json.loads(completed.stdout)
            if "error" in payload:
                code = payload["error"]
                _fail(code if code in ("TIMEOUT", "NETWORK_ERROR", "RESOURCE_LIMIT") else "NETWORK_ERROR")
            body = bytes.fromhex(payload["body_hex"])
            if len(body) > max_bytes:
                _fail("RESOURCE_LIMIT")
            return HTTPReply(payload["status"], body, payload["headers"])
        except (ValueError, TypeError, KeyError):
            _fail("NETWORK_ERROR")
