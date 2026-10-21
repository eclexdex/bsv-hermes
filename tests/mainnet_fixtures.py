"""NEVER FUND: freshly generated keys, invented ancestry, loopback-only provider."""
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
from urllib.parse import urlsplit

from bsv_hermes.mainnet.funding import PublicTarget
from bsv_hermes.mainnet.funding.client import FundingClient, HTTPReply
from bsv_hermes.mainnet.broadcast.transport import Response


def txid(raw):
    return hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()[::-1].hex()


class Provider:
    def __init__(self, public, value=10000):
        self.target = PublicTarget.from_wallet_metadata(public)
        script = bytes.fromhex(self.target.locking_script_hex)
        # Ordinary non-coinbase parent with an invented outpoint and scriptSig.
        self.raw = (b'\x01\0\0\0\x01' + b'\x13'*32 + b'\0'*4 + b'\x01\x51' + b'\xff'*4
                    + b'\x01' + value.to_bytes(8, 'little') + bytes([len(script)]) + script + b'\0'*4).hex()
        self.txid, self.value = txid(self.raw), value
        self.submitted = {}; self.posts = 0; self.gets = 0; self.ack_only = False; self.stale = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body, mime='application/json'):
                if not isinstance(body, bytes):
                    body = json.dumps(body).encode()
                self.send_response(status); self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)

            def do_GET(self):
                owner.gets += 1
                if '/address/' in self.path:
                    rows = [] if owner.stale else [{'tx_hash': owner.txid, 'tx_pos': 0, 'value': owner.value,
                         'height': 100, 'isSpentInMempoolTx': False, 'status': 'confirmed'}]
                    return self.reply(200, {'address': owner.target.address, 'script': owner.target.script_hash,
                                           'result': rows, 'error': ''})
                if self.path.endswith('/spent'):
                    return self.reply(404, b'Not Found', 'text/plain')
                parts = self.path.split('/')
                if self.path.endswith('/hex'):
                    key = parts[-2]
                    raw = owner.raw if key == owner.txid else owner.submitted.get(key)
                    return self.reply(200 if raw else 404, raw.encode() if raw else b'Not Found', 'text/plain')
                key = parts[-1]
                if key == owner.txid:
                    return self.reply(200, {'txid': key, 'confirmations': 10, 'blockheight': 100, 'blockhash': 'ab'*32})
                if key in owner.submitted:
                    return self.reply(200, {'txid': key, 'confirmations': 0})
                return self.reply(404, b'Not Found', 'text/plain')

            def do_POST(self):
                assert self.path.endswith('/tx/raw')
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                raw = data['txhex']; key = txid(raw); owner.posts += 1
                if not owner.ack_only:
                    owner.submitted[key] = raw
                self.reply(200, key.encode(), 'text/plain')

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()

    def request(self, method, url, body=None, timeout=10):
        # A trusted TEST adapter rewrites only the provider origin to loopback.
        connection = HTTPConnection('127.0.0.1', self.server.server_port, timeout=timeout)
        try:
            connection.request(method, urlsplit(url).path, body=body)
            r = connection.getresponse(); payload = r.read(1048577)
            return r.status, payload, {k.lower(): v for k, v in r.getheaders()}
        finally:
            connection.close()

    def funding(self):
        def transport(url, *, timeout, max_bytes):
            status, body, headers = self.request('GET', url, timeout=timeout)
            return HTTPReply(status, body, headers)
        return FundingClient(transport=transport, request_interval=0)

    def broadcast_transport(self):
        from bsv_hermes.mainnet.broadcast.transport import HTTPTransport
        return HTTPTransport.for_local_tests('http://127.0.0.1:' + str(self.server.server_port))

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
