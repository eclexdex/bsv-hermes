"""Bounded direct HTTP transport: no proxy, redirect, credentials or auth replay."""
import base64
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit
from .endpoints import allowed_url

MAX_RESPONSE_BYTES = 262144
MAX_REQUEST_BYTES = 200100


class TransportError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes


class HTTPTransport:
    def __init__(self, *, request_timeout=8.0, max_response_bytes=MAX_RESPONSE_BYTES):
        if type(request_timeout) not in (int, float) or not math.isfinite(request_timeout) or not 0.1 <= request_timeout <= 10:
            raise ValueError('request timeout must be between 0.1 and 10 seconds')
        if type(max_response_bytes) is not int or not 256 <= max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError('response byte limit outside policy')
        self.request_timeout = float(request_timeout)
        self.max_response_bytes = max_response_bytes
        self._local_origin = None

    @classmethod
    def for_local_tests(cls, origin, **kwargs):
        # Explicit library test seam. Never exposed through the native tools.
        if type(origin) is not str or re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}', origin) is None:
            raise ValueError('test origin must be literal IPv4 loopback with port')
        port = urlsplit(origin).port
        if not 1 <= port <= 65535:
            raise ValueError('invalid loopback port')
        result = cls(**kwargs)
        result._local_origin = origin
        return result

    def request(self, method, url, *, body=None, timeout=None):
        if not allowed_url(method, url):
            raise ValueError('endpoint not allowlisted')
        if body is not None and (type(body) is not bytes or len(body) > MAX_REQUEST_BYTES):
            raise ValueError('request body exceeds policy')
        if (method == 'GET' and body is not None) or (method == 'POST' and not body):
            raise ValueError('invalid HTTP request shape')
        timeout = self.request_timeout if timeout is None else min(self.request_timeout, timeout)
        if not math.isfinite(timeout) or timeout <= 0:
            raise TransportError('deadline')
        actual_url = url if self._local_origin is None else self._local_origin + urlsplit(url).path
        request = {'method': method, 'url': actual_url,
                   'body': None if body is None else base64.b64encode(body).decode('ascii'),
                   'timeout': timeout, 'max_bytes': self.max_response_bytes,
                   'local': self._local_origin is not None}
        try:
            # The child bounds its stdout; the parent kills/reaps a hung child.
            # -I excludes PYTHONPATH/user site code. No shell, redirects or retries.
            result = subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('_http_worker.py'))],
                                    input=json.dumps(request).encode(), stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise TransportError('timeout') from None
        except OSError:
            raise TransportError('transport_unavailable') from None
        if result.returncode or len(result.stdout) > (self.max_response_bytes * 4 // 3 + 1024):
            raise TransportError('worker_error')
        try:
            value = json.loads(result.stdout)
            if 'error' in value:
                raise TransportError(value['error'])
            response = Response(value['status'], base64.b64decode(value['body'], validate=True))
            if len(response.body) > self.max_response_bytes or type(response.status) is not int:
                raise ValueError('invalid worker response')
            return response
        except (ValueError, KeyError, TypeError):
            raise TransportError('worker_error') from None
