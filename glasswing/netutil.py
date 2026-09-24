from __future__ import annotations
import json
import random
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
__all__ = ['tcp_probe', 'tls_probe', 'http_probe', 'dns_query_udp', 'doh_query', 'resolve_all', 'health_check']

def tcp_probe(host: str, port: int, timeout: float=4.0) -> dict:
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {'ok': True, 'elapsed': time.time() - t0, 'error': None}
    except socket.timeout:
        return {'ok': False, 'elapsed': time.time() - t0, 'error': 'timeout'}
    except ConnectionResetError:
        return {'ok': False, 'elapsed': time.time() - t0, 'error': 'reset'}
    except OSError as exc:
        return {'ok': False, 'elapsed': time.time() - t0, 'error': type(exc).__name__}

def tls_probe(host: str, port: int=443, timeout: float=6.0, sni: str | None=None, verify: bool=False) -> dict:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or host) as ss:
                ss.version()
        return {'ok': True, 'elapsed': time.time() - t0, 'error': None}
    except socket.timeout:
        return {'ok': False, 'elapsed': time.time() - t0, 'error': 'timeout'}
    except ConnectionResetError:
        return {'ok': False, 'elapsed': time.time() - t0, 'error': 'reset'}
    except ssl.SSLError as exc:
        return {'ok': False, 'elapsed': time.time() - t0, 'error': 'ssl:' + str(exc)[:80]}
    except OSError as exc:
        return {'ok': False, 'elapsed': time.time() - t0, 'error': type(exc).__name__}

def _build_opener(proxy: str | None=None):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)

def http_probe(url: str, proxy: str | None=None, timeout: float=10.0, method: str='GET') -> dict:
    t0 = time.time()
    opener = _build_opener(proxy)
    req = urllib.request.Request(url, method=method, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) glasswing-probe/0.1', 'Accept': '*/*'})
    try:
        with opener.open(req, timeout=timeout) as resp:
            resp.read(64)
            return {'status': resp.status, 'elapsed': time.time() - t0, 'error': None}
    except urllib.error.HTTPError as exc:
        return {'status': exc.code, 'elapsed': time.time() - t0, 'error': None}
    except urllib.error.URLError as exc:
        reason = getattr(exc, 'reason', exc)
        name = type(reason).__name__ if not isinstance(reason, str) else reason
        return {'status': None, 'elapsed': time.time() - t0, 'error': str(name)[:80]}
    except Exception as exc:
        return {'status': None, 'elapsed': time.time() - t0, 'error': type(exc).__name__}

def _encode_dns_name(name: str) -> bytes:
    out = b''
    for part in name.rstrip('.').split('.'):
        if not part:
            continue
        try:
            raw = part.encode('idna')
        except Exception:
            raw = part.encode('ascii', errors='ignore')
        out += bytes([len(raw)]) + raw
    return out + b'\x00'

def _skip_dns_name(data: bytes, off: int) -> int:
    while off < len(data):
        length = data[off]
        if length == 0:
            return off + 1
        if length & 192 == 192:
            return off + 2
        off += length + 1
    return off

def _parse_dns_answers(data: bytes, tid: int) -> list[str]:
    ips: list[str] = []
    if len(data) < 12:
        return ips
    rid, _flags, qd, an, _ns, _ar = struct.unpack('>HHHHHH', data[:12])
    if rid != tid:
        return ips
    off = 12
    for _ in range(qd):
        off = _skip_dns_name(data, off) + 4
    for _ in range(an):
        off = _skip_dns_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack('>HHIH', data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4 and (off + 4 <= len(data)):
            ips.append('.'.join((str(b) for b in data[off:off + 4])))
        off += rdlen
    return ips

def dns_query_udp(host: str, server: str, timeout: float=3.0, port: int=53) -> dict:
    tid = random.randint(0, 65535)
    packet = struct.pack('>HHHHHH', tid, 256, 1, 0, 0, 0)
    packet += _encode_dns_name(host) + struct.pack('>HH', 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(2048)
        return {'ips': _parse_dns_answers(data, tid), 'error': None}
    except Exception as exc:
        return {'ips': [], 'error': type(exc).__name__}
    finally:
        sock.close()

def doh_query(host: str, doh_url: str='https://doh.pub/dns-query', timeout: float=6.0, proxy: str | None=None) -> dict:
    sep = '&' if '?' in doh_url else '?'
    url = f'{doh_url}{sep}name={urllib.parse.quote(host)}&type=A'
    req = urllib.request.Request(url, headers={'accept': 'application/dns-json'})
    try:
        with _build_opener(proxy).open(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode('utf-8', 'replace'))
        ips = [a.get('data') for a in payload.get('Answer', []) if a.get('type') == 1]
        return {'ips': [ip for ip in ips if ip], 'error': None}
    except Exception as exc:
        return {'ips': [], 'error': type(exc).__name__}

def resolve_all(host: str, servers: list[str] | None=None, timeout: float=3.0) -> dict:
    result: dict = {'system': [], 'servers': {}, 'error': None}
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        result['system'] = sorted({i[4][0] for i in infos})
    except Exception as exc:
        result['error'] = type(exc).__name__
    for srv in servers or []:
        result['servers'][srv] = dns_query_udp(host, srv, timeout=timeout)['ips']
    return result

def health_check(proxy: str, url: str='https://www.apple.com/', expect_status: int | None=None, timeout: float=8.0) -> dict:
    info = http_probe(url, proxy=proxy, timeout=timeout)
    ok = info['error'] is None and info['status'] is not None
    if ok and expect_status not in (None, 0) and (info['status'] != expect_status):
        ok = False
    info['ok'] = ok
    return info
if __name__ == '__main__':
    print('tcp 1.1.1.1:443 ->', tcp_probe('1.1.1.1', 443, timeout=3))
    print('tls www.apple.com  ->', tls_probe('www.apple.com', timeout=6))
    print('dns(223.5.5.5) www.google.com ->', dns_query_udp('www.google.com', '223.5.5.5'))
