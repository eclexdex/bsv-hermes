"""Opt-in, metadata-only lifecycle recorder. No Hermes dependency or installation."""
import hashlib
import json
import os
import threading
import time
import uuid

EVENTS = frozenset({'agent:start', 'agent:step', 'agent:end'})
FIELDS = frozenset({'iteration'})
DOMAIN = b'hermes-recorder/v1\0'

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

class Recorder:
    def __init__(self, path, *, consent, session_id, events, fields=(),
                 max_events=1000, max_bytes=262144, max_seconds=300, clock=time.monotonic):
        if consent is not True:
            raise ValueError('explicit per-run consent required')
        if type(session_id) is not str or not session_id or len(session_id) > 256:
            raise ValueError('explicit session binding required')
        self.events, self.fields = frozenset(events), frozenset(fields)
        if not self.events or not self.events <= EVENTS or not self.fields <= FIELDS:
            raise ValueError('scope not allowlisted')
        for value, cap in ((max_events,10000), (max_bytes,1048576), (max_seconds,3600)):
            if type(value) is not int or not 1 <= value <= cap:
                raise ValueError('invalid bound')
        self.session_id = session_id  # in memory only; never serialized or hashed
        self.clock, self.deadline = clock, clock() + max_seconds
        self.max_events, self.max_bytes = max_events, max_bytes
        self.count, self.size, self.previous = 0, 0, '0' * 64
        self.closed, self.reason = False, None
        self.lock = threading.Lock()
        self.run_id = uuid.uuid4().hex  # not supplied by event payload
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)

    def handle(self, event_type, context):
        # Never enumerate context, serialize raw data, hash excluded content, or log exceptions.
        with self.lock:
            if self.closed:
                return None
            if self.clock() >= self.deadline:
                self._close('time_limit')
                return None
            if type(event_type) is not str or event_type not in self.events or type(context) is not dict:
                return None
            if context.get('session_id') != self.session_id:
                return None
            safe = {}
            iteration = context.get('iteration') if 'iteration' in self.fields else None
            if type(iteration) is int and 0 <= iteration <= 10000:
                safe['iteration'] = iteration
            body = {'version':'hermes-recorder/v1', 'run_id':self.run_id, 'index':self.count,
                    'event':event_type, 'fields':safe, 'previous':self.previous,
                    'source':'unsigned_host_callback_unverified'}
            digest = hashlib.sha256(DOMAIN + canonical(body)).hexdigest()
            line = canonical(dict(body, event_digest=digest)) + b'\n'
            if self.count >= self.max_events or self.size + len(line) > self.max_bytes:
                self._close('size_or_event_limit')
                return None
            try:
                view = memoryview(line)
                while view:
                    n = os.write(self.fd, view)
                    if n <= 0:
                        raise OSError('write failure')
                    view = view[n:]
            except OSError:
                self._close('io_error')
                return None
            self.previous = digest
            self.count += 1
            self.size += len(line)
            if event_type == 'agent:end':
                self._close('run_end')
            elif self.count >= self.max_events:
                self._close('event_limit')
        return None

    def _close(self, reason):
        if not self.closed:
            os.close(self.fd)
            self.closed, self.reason = True, reason
            self.session_id = None

    def close(self):
        with self.lock:
            self._close('operator_stop')

    def result(self):
        return {'version':'hermes-recorder-result/v1', 'events_recorded':self.count,
                'bytes_recorded':self.size, 'closed':self.closed, 'stop_reason':self.reason,
                'artifact':'unchecked', 'chain':'unchecked', 'signature':'missing',
                'batch':'missing', 'inclusion':'missing',
                'execution_truth':'unverified_source', 'complete_trace':False}

def wrapper(recorder, event_type, context):
    """Explicit fallback, not automatic host integration."""
    return recorder.handle(event_type, context)
