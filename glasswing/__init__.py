import sys as _sys
for _name in ('stdout', 'stderr'):
    _stream = getattr(_sys, _name, None)
    if _stream is not None and hasattr(_stream, 'reconfigure'):
        try:
            _stream.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
__version__ = '0.1.0'
__all__ = ['__version__']
