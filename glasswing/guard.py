from __future__ import annotations
import time
from datetime import datetime
from . import netutil, winproxy
__all__ = ['find_available', 'run_guard']

def _log(msg: str, level: str='info') -> None:
    stamp = datetime.now().strftime('%H:%M:%S')
    icon = {'info': '  ', 'ok': '✅', 'warn': '⚠️ ', 'err': '❌'}.get(level, '  ')
    print(f'[{stamp}] {icon}{msg}', flush=True)

def find_available(ports: list[int], url: str, expect: int | None, timeout: float, skip: set[int] | None=None) -> int | None:
    skip = skip or set()
    for port in ports:
        if port in skip:
            continue
        if not netutil.tcp_probe('127.0.0.1', port, timeout=2.0)['ok']:
            continue
        info = netutil.health_check(f'http://127.0.0.1:{port}', url=url, expect_status=expect, timeout=timeout)
        if info.get('ok'):
            return port
    return None

def run_guard(cfg: dict, ports: list[int] | None=None, interval: int | None=None, fail_threshold: int | None=None, dry_run: bool=False, once: bool=False) -> int:
    hcfg = cfg.get('health', {})
    url = hcfg.get('url', 'https://www.gstatic.com/generate_204')
    expect = hcfg.get('expect_status') or None
    timeout = float(hcfg.get('timeout_sec', 8))
    interval = int(interval or hcfg.get('interval_sec', 10))
    threshold = int(fail_threshold or hcfg.get('fail_threshold', 2))
    ports = ports or cfg.get('ports', [7890])
    _log(f'guard started | ports={ports} | target={url} | interval={interval}s | threshold={threshold}')
    if dry_run:
        _log('Dry-run mode: the system proxy will not be changed', 'warn')
    misses = 0
    last_state: tuple | None = None
    while True:
        current = winproxy.get_proxy() if winproxy.is_windows() else {'enabled': False, 'port': None}
        cur_port = current.get('port')
        healthy = False
        reason = ''
        if cur_port is None:
            reason = 'System proxy is disabled or does not point to a local port'
        elif not netutil.tcp_probe('127.0.0.1', cur_port, timeout=2.0)['ok']:
            reason = f'No process is listening on port {cur_port} (dead proxy)'
        else:
            info = netutil.health_check(f'http://127.0.0.1:{cur_port}', url=url, expect_status=expect, timeout=timeout)
            if info.get('ok'):
                healthy = True
            else:
                reason = f"Port {cur_port} is listening, but its data plane is unavailable (status={info.get('status')} err={info.get('error')})"
        state = (healthy, cur_port, reason if not healthy else '')
        if state != last_state:
            if healthy:
                _log(f'Channel {cur_port} is healthy', 'ok')
            else:
                _log(reason, 'warn')
            last_state = state
        if healthy:
            misses = 0
        else:
            misses += 1
            _log(f'Failure count {misses}/{threshold}')
            if misses >= threshold:
                target = find_available(ports, url, expect, timeout, skip={cur_port} if cur_port else set())
                if target is None:
                    _log('All candidate ports are unavailable; a different node is required', 'err')
                elif dry_run:
                    _log(f'[dry-run] Would switch to port {target}', 'warn')
                else:
                    ok = winproxy.set_proxy(f'127.0.0.1:{target}', enable=True)
                    _log(f"Switched to port {target} (system proxy update: {('success' if ok else 'failed')})", 'ok' if ok else 'err')
                misses = 0
                last_state = None
        if once:
            return 0
        time.sleep(interval)
if __name__ == '__main__':
    from . import config as _config
    run_guard(_config.load())
