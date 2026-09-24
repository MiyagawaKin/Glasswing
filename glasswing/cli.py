from __future__ import annotations
import argparse
import json
import os
import sys
import time
from . import config as cfgmod
from . import config_gen, guard as guardmod, probe as probemod, rules as rulesmod
from . import winproxy
__all__ = ['main']

def _parse_ports(value: str) -> list[int]:
    if not value:
        return []
    return [int(p.strip()) for p in value.split(',') if p.strip()]

def _cmd_probe(args) -> int:
    cfg = cfgmod.load(args.config)
    ports = _parse_ports(args.ports)
    if ports:
        cfg['ports'] = ports
    print('Starting probes (about 30-60 seconds)...\n')
    result = probemod.probe_all(cfg)
    print('—— DNS ——')
    for host, entry in result['dns']['hosts'].items():
        doh = ','.join(entry['doh']) or '(failed)'
        print(f'  {host}')
        print(f"    System DNS: {','.join(entry['system']) or '(none)'}")
        for srv, ips in entry['udp'].items():
            print(f"    UDP {srv}: {','.join(ips) or '(none)'}")
        print(f'    DoH: {doh}')
    print('\n—— SNI / TLS ——')
    for group, label in (('blocked', 'Expected blocked'), ('open', 'Control group')):
        print(f'  [{label}]')
        for host, info in result['sni'][group].items():
            mark = 'OK ' if info['ok'] else '✗  '
            print(f"    {mark} {host:<26} {info['error'] or ''} ({info['elapsed']:.2f}s)")
    print('\n-- Port policy --')
    for target, row in result['ports'].items():
        if target.startswith('_'):
            continue
        ok_ports = [str(p) for p, ok in row.items() if ok]
        print(f"  {target}: reachable ports {','.join(ok_ports) or '(none)'}")
    print('\n-- Local proxy channels --')
    for port, info in result['proxy']['ports'].items():
        mark = '✅' if info['ok'] else '⚠️' if info['listening'] else '❌'
        print(f"  {mark} {port}: listening={info['listening']} status={info['status']} err={info['error']} {info['elapsed']}s")
    if args.json_out:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
        with open(args.json_out, 'w', encoding='utf-8') as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        print(f'\nRaw results saved to: {args.json_out}')
    return 0

def _cmd_rules(args) -> int:
    cfg = cfgmod.load(args.config)
    print('Probing...\n')
    result = probemod.probe_all(cfg)
    findings = rulesmod.infer(result)
    print(rulesmod.render_text(findings))
    print('Tip: run `python -m glasswing report` to generate a Markdown report.')
    return 0

def _cmd_gen(args) -> int:
    cfg = cfgmod.load(args.config)
    with open(args.src, encoding='utf-8') as fh:
        text = fh.read()
    out = args.dst or cfg.get('gen', {}).get('out', 'out/config.yaml')
    built = config_gen.build_config(text, cfg, port=args.port or None)
    path = config_gen.write_config(built, out)
    print(f'✅ Generated: {path}')
    print('   Note: this file may contain node details; make sure it is covered by .gitignore.')
    return 0

def _cmd_guard(args) -> int:
    cfg = cfgmod.load(args.config)
    ports = _parse_ports(args.ports)
    try:
        return guardmod.run_guard(cfg, ports=ports or None, interval=args.interval or None, fail_threshold=args.threshold or None, dry_run=args.dry_run, once=args.once)
    except KeyboardInterrupt:
        print('\nMonitor stopped.')
        return 0

def _cmd_report(args) -> int:
    cfg = cfgmod.load(args.config)
    print('Probing...\n')
    result = probemod.probe_all(cfg)
    findings = rulesmod.infer(result)
    md = rulesmod.render_markdown(findings)
    md += '\n## Raw probe data\n\n```json\n'
    md += json.dumps(result, ensure_ascii=False, indent=2)
    md += '\n```\n'
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as fh:
        fh.write(md)
    print(f'✅ Report generated: {args.out}')
    return 0

def _cmd_proxy(args) -> int:
    if args.set:
        ok = winproxy.set_proxy(args.set, enable=True)
        print(f"Set system proxy to {args.set}: {('success' if ok else 'failed (not Windows or insufficient permissions)')}")
    elif args.off:
        ok = winproxy.disable_proxy()
        print(f"Disable system proxy: {('success' if ok else 'failed (not Windows or insufficient permissions)')}")
    else:
        info = winproxy.get_proxy()
        print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0

def main(argv: list[str] | None=None) -> int:
    parser = argparse.ArgumentParser(prog='glasswing', description='Campus network diagnostics and connection recovery')
    parser.add_argument('--version', action='version', version='glasswing 0.1.0')
    sub = parser.add_subparsers(dest='cmd')
    p = sub.add_parser('probe', help='Run all probes')
    p.add_argument('--config', default='config.yaml')
    p.add_argument('--json', dest='json_out', default='')
    p.add_argument('--ports', default='')
    p.set_defaults(func=_cmd_probe)
    p = sub.add_parser('rules', help='Infer upstream network rules')
    p.add_argument('--config', default='config.yaml')
    p.set_defaults(func=_cmd_rules)
    p = sub.add_parser('gen-config', help='Generate a proxy configuration with routing rules')
    p.add_argument('-i', '--in', dest='src', required=True)
    p.add_argument('-o', '--out', dest='dst', default='')
    p.add_argument('--port', type=int, default=0)
    p.add_argument('--config', default='config.yaml')
    p.set_defaults(func=_cmd_gen)
    p = sub.add_parser('guard', help='Monitor channels and switch automatically')
    p.add_argument('--config', default='config.yaml')
    p.add_argument('--ports', default='')
    p.add_argument('--interval', type=int, default=0)
    p.add_argument('--threshold', type=int, default=0)
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--once', action='store_true')
    p.set_defaults(func=_cmd_guard)
    p = sub.add_parser('report', help='Generate a Markdown report')
    p.add_argument('--config', default='config.yaml')
    p.add_argument('--out', default='out/report.md')
    p.set_defaults(func=_cmd_report)
    p = sub.add_parser('proxy', help='View, set, or disable the system proxy')
    p.add_argument('--set', default='')
    p.add_argument('--off', action='store_true')
    p.set_defaults(func=_cmd_proxy)
    args = parser.parse_args(argv)
    if not getattr(args, 'func', None):
        parser.print_help()
        return 1
    return args.func(args)
if __name__ == '__main__':
    sys.exit(main())
