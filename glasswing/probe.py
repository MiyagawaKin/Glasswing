from __future__ import annotations
import concurrent.futures
import time
from . import netutil
__all__ = ['probe_dns', 'probe_sni', 'probe_ports', 'probe_proxy', 'probe_all']

def probe_dns(cfg: dict, hosts: list[str] | None=None) -> dict:
    hosts = hosts or ['www.google.com', 'api.openai.com', 'www.apple.com']
    pcfg = cfg.get('probe', {})
    servers = pcfg.get('dns_servers', [])
    doh_url = pcfg.get('doh_url', 'https://doh.pub/dns-query')
    results: dict = {'hosts': {}, 'servers': servers, 'doh_url': doh_url}
    for host in hosts:
        system = netutil.resolve_all(host, servers=servers)
        doh = netutil.doh_query(host, doh_url=doh_url)
        entry = {'system': system.get('system', []), 'udp': {s: system['servers'].get(s, []) for s in servers}, 'doh': doh.get('ips', []), 'doh_error': doh.get('error')}
        udp_ips = {ip for ips in entry['udp'].values() for ip in ips}
        doh_ips = set(entry['doh'])
        entry['suspicious_udp'] = sorted((ip for ip in udp_ips if ip.startswith(('127.', '0.')) or ip == '1.1.1.1'))
        all_ips = udp_ips | set(entry['system'])
        entry['fake_ip'] = any((ip.startswith(('198.18.', '198.19.')) for ip in all_ips))
        entry['udp_vs_doh_disjoint'] = bool(udp_ips and doh_ips and (not udp_ips & doh_ips))
        results['hosts'][host] = entry
    return results

def probe_sni(cfg: dict) -> dict:
    pcfg = cfg.get('probe', {})
    blocked = pcfg.get('blocked_samples', [])
    opened = pcfg.get('open_samples', [])

    def _one(host: str) -> tuple[str, dict]:
        return (host, netutil.tls_probe(host, timeout=6.0))
    out: dict = {'blocked': {}, 'open': {}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for host, info in pool.map(_one, blocked):
            out['blocked'][host] = info
        for host, info in pool.map(_one, opened):
            out['open'][host] = info
    return out

def probe_ports(cfg: dict) -> dict:
    pcfg = cfg.get('probe', {})
    targets = pcfg.get('port_targets', [])
    ports = pcfg.get('port_list', [443])

    def _one(target: str):
        row = {}
        for port in ports:
            row[port] = netutil.tcp_probe(target, port, timeout=3.0)['ok']
        return (target, row)
    out: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for target, row in pool.map(_one, targets):
            out[target] = row
    out['_ports'] = ports
    return out

def probe_proxy(cfg: dict) -> dict:
    hcfg = cfg.get('health', {})
    url = hcfg.get('url', 'https://www.gstatic.com/generate_204')
    expect = hcfg.get('expect_status') or None
    timeout = float(hcfg.get('timeout_sec', 8))
    ports = cfg.get('ports', [])
    out: dict = {'url': url, 'expect_status': expect, 'ports': {}}
    for port in ports:
        proxy = f'http://127.0.0.1:{port}'
        listening = netutil.tcp_probe('127.0.0.1', port, timeout=2.0)['ok']
        if not listening:
            out['ports'][port] = {'listening': False, 'ok': False, 'status': None, 'elapsed': 0.0, 'error': 'not-listening'}
            continue
        info = netutil.health_check(proxy, url=url, expect_status=expect, timeout=timeout)
        out['ports'][port] = {'listening': True, 'ok': bool(info.get('ok')), 'status': info.get('status'), 'elapsed': round(info.get('elapsed', 0), 3), 'error': info.get('error')}
    return out

def check_local_env() -> list[str]:
    warnings: list[str] = []
    try:
        from . import winproxy
        state = winproxy.get_proxy()
        if state.get('enabled'):
            warnings.append('The system proxy is enabled (%s), so probe connections may be routed through the local proxy. DNS, port, and SNI results may be inaccurate. Disable the proxy and TUN before probing upstream rules.' % state.get('server'))
    except Exception:
        pass
    return warnings

def probe_all(cfg: dict) -> dict:
    started = time.time()
    env_warnings = check_local_env()
    for w in env_warnings:
        print(f'⚠️  {w}')
    result = {'started_at': time.strftime('%Y-%m-%d %H:%M:%S'), 'env_warnings': env_warnings, 'dns': probe_dns(cfg), 'sni': probe_sni(cfg), 'ports': probe_ports(cfg), 'proxy': probe_proxy(cfg)}
    result['elapsed_sec'] = round(time.time() - started, 1)
    return result
