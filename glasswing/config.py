from __future__ import annotations
import copy
import os
DEFAULTS: dict = {'ports': [7890, 7891, 7892], 'health': {'url': 'https://www.apple.com/', 'expect_status': 0, 'timeout_sec': 8, 'fail_threshold': 2, 'interval_sec': 10}, 'probe': {'blocked_samples': ['www.google.com', 'chatgpt.com', 'api.openai.com', 'archiveofourown.org', 'www.dlsite.com', 'www.pixiv.net', 'www.reddit.com'], 'open_samples': ['www.apple.com', 'www.bing.com', 'www.python.org', 'www.qq.com'], 'port_targets': ['104.18.32.7', '20.205.243.166'], 'port_list': [22, 25, 53, 80, 443, 8080, 8443, 2053, 2096], 'dns_servers': ['223.5.5.5', '119.29.29.29'], 'doh_url': 'https://doh.pub/dns-query'}, 'direct_domains': ['chaoxing.com', 'chaoxing.com.cn', 'chaoxing.cn', 'xuexitong.com', 'cnki.net', 'edu.cn', 'qq.com', 'baidu.com', 'taobao.com', 'bilibili.com'], 'gen': {'mixed_port': 7890, 'mode': 'rule', 'log_level': 'warning', 'tls_fragment': True, 'out': 'out/config.yaml'}, 'log_level': 'INFO'}

def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out

def load(path: str | None='config.yaml') -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    ports_env = os.environ.get('CNG_PORTS')
    if ports_env:
        try:
            cfg['ports'] = [int(p.strip()) for p in ports_env.split(',') if p.strip()]
        except ValueError:
            pass
    url_env = os.environ.get('CNG_HEALTH_URL')
    if url_env:
        cfg['health']['url'] = url_env
    doh_env = os.environ.get('CNG_DOH_URL')
    if doh_env:
        cfg['probe']['doh_url'] = doh_env
    lvl_env = os.environ.get('CNG_LOG_LEVEL')
    if lvl_env:
        cfg['log_level'] = lvl_env
    if not path or not os.path.exists(path):
        return cfg
    try:
        import yaml
        with open(path, encoding='utf-8') as fh:
            data = yaml.safe_load(fh) or {}
        if isinstance(data, dict):
            cfg = _deep_merge(cfg, data)
    except ImportError:
        cfg['_warn'] = 'PyYAML is not installed; config.yaml was ignored (pip install PyYAML)'
    except Exception as exc:
        cfg['_warn'] = f'Could not parse config.yaml: {exc}'
    return cfg
