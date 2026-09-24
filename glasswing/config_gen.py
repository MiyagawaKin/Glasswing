from __future__ import annotations
import os
import re
__all__ = ['extract_proxies_block', 'build_config', 'write_config']

def extract_proxies_block(source_text: str) -> str:
    m = re.search('^proxies:\\s*\\n(.*?)(?=^[A-Za-z][\\w-]*:|\\Z)', source_text, re.S | re.M)
    if not m:
        raise ValueError('Could not find a proxies: section in the input file')
    return m.group(1).rstrip('\n')

def _node_names(proxies_block: str) -> list[str]:
    names = []
    for line in proxies_block.splitlines():
        m = re.match('\\s*-?\\s*name:\\s*\\"?(.*?)\\"?\\s*$', line)
        if m:
            names.append(m.group(1))
    return names

def build_config(source_text: str, cfg: dict, port: int | None=None) -> str:
    gcfg = cfg.get('gen', {})
    port = int(port or gcfg.get('mixed_port', 7890))
    proxies_block = extract_proxies_block(source_text)
    names = _node_names(proxies_block)
    if not names:
        raise ValueError('No proxy names were found in the proxies section')
    direct = cfg.get('direct_domains', [])
    rules = [f'  - DOMAIN-SUFFIX,{d},DIRECT' for d in direct]
    if gcfg.get('tls_fragment', True):
        rules.insert(0, '  # TLS fragmentation enabled (supported TLS protocols only; not plain SS)')
    lines: list[str] = []
    lines.append(f'mixed-port: {port}')
    lines.append('allow-lan: false')
    lines.append(f"mode: {gcfg.get('mode', 'rule')}")
    lines.append(f"log-level: {gcfg.get('log_level', 'warning')}")
    lines.append("external-controller: ''")
    lines.append('')
    lines.append('# Use system DNS and proxy-side resolution to avoid poisoned DNS responses')
    lines.append('dns:')
    lines.append('  enable: false')
    lines.append('')
    lines.append('tun:')
    lines.append('  enable: false   # Set to true to enable TUN; run with administrator privileges')
    lines.append('')
    lines.append('proxies:')
    lines.append(proxies_block)
    lines.append('')
    lines.append('proxy-groups:')
    lines.append('  - name: PROXY')
    lines.append('    type: select')
    lines.append('    proxies:')
    for n in names:
        lines.append(f'      - "{n}"')
    lines.append('')
    lines.append('rules:')
    lines.extend(rules)
    lines.append('  - GEOSITE,cn,DIRECT      # Requires geosite.dat; it can be copied from the client directory')
    lines.append('  - MATCH,PROXY')
    lines.append('')
    return '\n'.join(lines)

def write_config(text: str, out_path: str) -> str:
    out_dir = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(text)
    return out_path
