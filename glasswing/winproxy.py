from __future__ import annotations
import re
import sys
KEY_PATH = 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
__all__ = ['is_windows', 'get_proxy', 'set_proxy', 'disable_proxy', 'refresh', 'parse_server']

def is_windows() -> bool:
    return sys.platform.startswith('win')

def parse_server(server: str) -> tuple[str, int | None]:
    m = re.match('^\\s*(?:(?P<host>[^:]+):)?(?P<port>\\d+)\\s*$', server or '')
    if not m:
        return (server or '', None)
    return (m.group('host') or '127.0.0.1', int(m.group('port')))

def _open_key(write: bool=False):
    import winreg
    return winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_PATH, 0, winreg.KEY_READ | (winreg.KEY_WRITE if write else 0))

def get_proxy() -> dict:
    if not is_windows():
        return {'enabled': False, 'server': '', 'host': '', 'port': None}
    try:
        import winreg
        with _open_key() as key:
            try:
                enabled, _ = winreg.QueryValueEx(key, 'ProxyEnable')
            except FileNotFoundError:
                enabled = 0
            try:
                server, _ = winreg.QueryValueEx(key, 'ProxyServer')
            except FileNotFoundError:
                server = ''
        host, port = parse_server(server)
        return {'enabled': bool(enabled), 'server': server, 'host': host, 'port': port}
    except Exception:
        return {'enabled': False, 'server': '', 'host': '', 'port': None}

def set_proxy(server: str='127.0.0.1:7890', enable: bool=True) -> bool:
    if not is_windows():
        return False
    try:
        import winreg
        with _open_key(write=True) as key:
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, server)
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1 if enable else 0)
        refresh()
        return True
    except Exception:
        return False

def disable_proxy() -> bool:
    if not is_windows():
        return False
    try:
        import winreg
        with _open_key(write=True) as key:
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
        refresh()
        return True
    except Exception:
        return False

def refresh() -> None:
    if not is_windows():
        return
    try:
        import ctypes
        wininet = ctypes.windll.wininet
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass
if __name__ == '__main__':
    print('Current system proxy:', get_proxy())
