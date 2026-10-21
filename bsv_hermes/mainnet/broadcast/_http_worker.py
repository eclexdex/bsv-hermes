"""One bounded HTTP exchange in a killable process, including DNS and TLS.

Internal worker, not an API or CLI. Never follows redirects, uses proxies, reads
credentials, decompresses bodies, or prints raw request/error data.
"""
import base64
import http.client
import ipaddress
import json
import socket
import ssl
import sys
from urllib.parse import urlsplit

http.client._MAXLINE = 8192
http.client._MAXHEADERS = 32


def exchange(request):
    parsed = urlsplit(request['url'])
    timeout = request['timeout']
    local = request['local']
    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)
    if local:
        if parsed.scheme != 'http' or host != '127.0.0.1':
            return {'error': 'endpoint_blocked'}
    elif parsed.scheme != 'https':
        return {'error': 'endpoint_blocked'}
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses or (not local and any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses)):
        return {'error': 'endpoint_blocked'}

    def connect(address, timeout=timeout, source_address=None):
        # Connect only to the addresses checked above: no second DNS lookup.
        for family, socktype, proto, _, sockaddr in addresses:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            try:
                sock.connect(sockaddr)
                return sock
            except OSError:
                sock.close()
        raise OSError('connect failed')

    cls = http.client.HTTPConnection if local else http.client.HTTPSConnection
    kwargs = {'timeout': timeout}
    if not local:
        kwargs['context'] = ssl.create_default_context()
    connection = cls(host, port, **kwargs)
    connection._create_connection = connect
    try:
        body = base64.b64decode(request['body'], validate=True) if request['body'] is not None else None
        headers = {'Accept': 'application/json, text/plain', 'Accept-Encoding': 'identity',
                   'Connection': 'close', 'User-Agent': 'bsv-hermes-bounded-broadcast/1'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        connection.request(request['method'], parsed.path, body=body, headers=headers)
        response = connection.getresponse()
        if response.getheader('Content-Encoding', 'identity').lower() not in ('identity', ''):
            return {'error': 'encoded_response'}
        lengths = response.headers.get_all('Content-Length', [])
        if len(lengths) > 1 or (lengths and (not lengths[0].isdigit() or int(lengths[0]) > request['max_bytes'])):
            return {'error': 'response_limit'}
        if lengths and response.getheader('Transfer-Encoding'):
            return {'error': 'response_framing'}
        body = response.read(request['max_bytes'] + 1)
        if len(body) > request['max_bytes']:
            return {'error': 'response_limit'}
        if lengths and len(body) != int(lengths[0]):
            return {'error': 'response_truncated'}
        return {'status': response.status, 'body': base64.b64encode(body).decode('ascii')}
    finally:
        connection.close()


def main():
    try:
        raw = sys.stdin.buffer.read(300001)
        if len(raw) > 300000:
            result = {'error': 'request_limit'}
        else:
            result = exchange(json.loads(raw))
    except (socket.timeout, TimeoutError):
        result = {'error': 'timeout'}
    except Exception:
        result = {'error': 'transport_error'}
    sys.stdout.write(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()
