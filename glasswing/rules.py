from __future__ import annotations
__all__ = ['infer', 'render_markdown', 'render_text']

def infer(result: dict) -> list[dict]:
    findings: list[dict] = []
    dns = result.get('dns', {})
    hijacked = []
    doh_ok = False
    for host, entry in (dns.get('hosts') or {}).items():
        if entry.get('suspicious_udp') or entry.get('udp_vs_doh_disjoint'):
            hijacked.append(host)
        if entry.get('doh'):
            doh_ok = True
    fake_ip_hosts = [h for h, e in (dns.get('hosts') or {}).items() if e.get('fake_ip')]
    if fake_ip_hosts:
        findings.append({'level': 'warn', 'title': 'Probes are affected by the local proxy (fake-ip is intercepting DNS)', 'detail': 'Results in 198.18.0.0/15 indicate that the local proxy (TUN/fake-ip) is handling DNS. DNS and port probes then reflect local proxy behavior, **not** upstream rules. Disable the proxy (or TUN and system proxy) and run the probes again for accurate results.', 'evidence': f"Affected: {', '.join(fake_ip_hosts[:3])}"})
    if hijacked:
        findings.append({'level': 'crit', 'title': 'DNS over UDP port 53 is intercepted or poisoned', 'detail': 'A custom public DNS server also returns incorrect results, so switching DNS servers will not help.', 'evidence': f"Affected samples: {', '.join(hijacked[:4])}"})
    if doh_ok:
        findings.append({'level': 'info', 'title': 'Encrypted DNS (DoH over 443) is available', 'detail': 'DoH can return valid DNS results; configure the client to use DoH or resolve domains through the proxy.', 'evidence': f"DoH service: {dns.get('doh_url')}"})
    else:
        findings.append({'level': 'warn', 'title': 'The DoH probe returned no result', 'detail': 'DoH may be blocked or the network may be temporarily unavailable; try another DoH endpoint.', 'evidence': ''})
    sni = result.get('sni', {})
    blocked_dead = [h for h, i in (sni.get('blocked') or {}).items() if not i.get('ok')]
    open_ok = [h for h, i in (sni.get('open') or {}).items() if i.get('ok')]
    open_dead = [h for h, i in (sni.get('open') or {}).items() if not i.get('ok')]
    if blocked_dead and open_ok:
        findings.append({'level': 'crit', 'title': 'Selective SNI filtering detected', 'detail': 'Blocked domains accept TCP connections but their TLS handshakes time out or reset, while ordinary overseas sites work in the same environment. This suggests domain-based SNI filtering rather than IP-wide blocking.', 'evidence': f"Unavailable: {', '.join(blocked_dead[:4])} | Reachable: {', '.join(open_ok[:3])}"})
    if open_dead:
        findings.append({'level': 'warn', 'title': 'Some control-group domains are also unavailable', 'detail': 'This may indicate broader overseas access restrictions or temporary network instability or throttling.', 'evidence': f"Unavailable: {', '.join(open_dead[:4])}"})
    ports = result.get('ports', {})
    port_list = ports.get('_ports', [])
    blocked_ports = set()
    open_ports = set()
    for target, row in ports.items():
        if str(target).startswith('_'):
            continue
        for port, ok in (row or {}).items():
            try:
                port_num = int(port)
            except (TypeError, ValueError):
                continue
            (open_ports if ok else blocked_ports).add(port_num)
    if 443 in open_ports and 80 in open_ports:
        findings.append({'level': 'info', 'title': 'No blocking detected on ports 443/80', 'detail': 'Common HTTPS/HTTP ports are available; proxy tunnel ports can be selected freely (443 recommended).', 'evidence': f'Reachable ports: {sorted(open_ports)}'})
    if 53 in blocked_ports:
        findings.append({'level': 'warn', 'title': 'Port 53 is restricted', 'detail': 'UDP/TCP port 53 is unavailable to overseas targets, consistent with DNS interception; avoid plain DNS on port 53.', 'evidence': f'Unavailable ports: {sorted(blocked_ports)}'})
    proxy = result.get('proxy', {})

    def _ports(pred) -> list[int]:
        out = []
        for key, info in (proxy.get('ports') or {}).items():
            if pred(info):
                try:
                    out.append(int(key))
                except (TypeError, ValueError):
                    pass
        return out
    good = _ports(lambda i: i.get('ok'))
    dead_not_listen = _ports(lambda i: not i.get('listening'))
    dead_data = _ports(lambda i: i.get('listening') and (not i.get('ok')))
    if dead_data:
        findings.append({'level': 'crit', 'title': 'Proxy port is listening, but the data plane is unavailable', 'detail': 'This is consistent with intermittent interference against recognized proxy traffic: TCP handshakes succeed, but payloads are dropped. Clients may show a node timeout and all proxied applications may fail.', 'evidence': f'Affected ports: {dead_data}'})
    if dead_not_listen:
        findings.append({'level': 'warn', 'title': 'System proxy points to a port with no listener', 'detail': 'This often occurs after a proxy client exits unexpectedly: a stale system proxy setting can make all websites unavailable even though direct access works. guard can clear or switch the setting.', 'evidence': f'Ports: {dead_not_listen}'})
    if good:
        findings.append({'level': 'info', 'title': f'{len(good)} channel(s) currently available', 'detail': 'guard switches automatically when a channel fails.', 'evidence': f'Available: {good}'})
    return findings
_ICON = {'info': '✅', 'warn': '⚠️', 'crit': '🚨'}

def render_text(findings: list[dict]) -> str:
    lines = []
    for f in findings:
        lines.append(f"{_ICON.get(f['level'], '·')} {f['title']}")
        if f.get('detail'):
            lines.append(f"    {f['detail']}")
        if f.get('evidence'):
            lines.append(f"    Evidence: {f['evidence']}")
        lines.append('')
    return '\n'.join(lines)

def render_markdown(findings: list[dict], title: str='Upstream Network Rule Inference Report') -> str:
    out = [f'# {title}', '']
    out.append('| Level | Finding | Details | Evidence |')
    out.append('|---|---|---|---|')
    for f in findings:
        out.append('| {icon} | **{t}** | {d} | {e} |'.format(icon=_ICON.get(f['level'], '·'), t=f['title'], d=(f.get('detail') or '').replace('|', '/'), e=(f.get('evidence') or '').replace('|', '/')))
    out.append('')
    return '\n'.join(out)
