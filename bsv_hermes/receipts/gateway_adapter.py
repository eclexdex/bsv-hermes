"""Inactive gateway handler. Parent/operator must arm explicitly for EACH run.
No installation, discovery, filesystem I/O, or consent inferred at import time.
"""
from .recorder import Recorder

_recorder = None

def arm(path, *, consent, session_id, events, fields=(), **bounds):
    global _recorder
    if _recorder is not None and not _recorder.closed:
        raise RuntimeError('previous run still armed')
    _recorder = Recorder(path, consent=consent, session_id=session_id,
                         events=events, fields=fields, **bounds)
    return _recorder

def disarm():
    if _recorder is not None:
        _recorder.close()

def handle(event_type, context):
    if _recorder is not None:
        return _recorder.handle(event_type, context)
    return None
