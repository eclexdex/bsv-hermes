import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from bsv_hermes.receipts.recorder import Recorder, canonical, DOMAIN

ROOT = Path(__file__).parent

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.path = Path(self.tmp.name)/'events.jsonl'
        self.r = None
    def tearDown(self):
        if self.r: self.r.close()
        self.tmp.cleanup()
    def make(self, **kw):
        args = dict(consent=True, session_id='synthetic-session', events=['agent:start','agent:step','agent:end'])
        args.update(kw)
        self.r = Recorder(self.path, **args)
        return self.r
    def test_no_consent_no_file(self):
        for consent in (False, None, 1, 'yes'):
            with self.assertRaises(ValueError): self.make(consent=consent)
        self.assertFalse(self.path.exists())
    def test_scopes(self):
        for kw in ({'fields':['prompt']}, {'events':['command:*']}, {'max_events':True}, {'max_seconds':0}):
            with self.assertRaises(ValueError): self.make(**kw)
        self.assertFalse(self.path.exists())
    def test_redact_before_digest(self):
        r=self.make(fields=['iteration'])
        for i,event in enumerate(['agent:start','agent:step','agent:end']):
            r.handle(event, {'session_id':'synthetic-session','iteration':i,'message':'CANARY_PROMPT',
                             'response':'CANARY_OUTPUT','tool_input':{'password':'CANARY_SECRET'},
                             'tool_names':['CANARY_TOOL'],'cwd':'CANARY_PATH','api_key':'CANARY_KEY'})
        raw=self.path.read_bytes()
        self.assertNotIn(b'CANARY',raw)
        self.assertNotIn(b'synthetic-session',raw)
        previous='0'*64
        for line in raw.splitlines():
            row=json.loads(line); digest=row.pop('event_digest')
            self.assertEqual(previous,row['previous'])
            self.assertEqual(digest,hashlib.sha256(DOMAIN+canonical(row)).hexdigest())
            previous=digest
        self.assertEqual(r.reason,'run_end')
    def test_cross_session_unknown_event_and_closed(self):
        r=self.make()
        r.handle('agent:start',{'session_id':'other'})
        r.handle('command:reset',{'session_id':'synthetic-session'})
        self.assertEqual(r.count,0)
        r.handle('agent:end',{'session_id':'synthetic-session'})
        r.handle('agent:step',{'session_id':'synthetic-session'})
        self.assertEqual(r.count,1)
    def test_bounds(self):
        r=self.make(max_events=1)
        r.handle('agent:step',{'session_id':'synthetic-session'})
        self.assertTrue(r.closed)
        self.assertLessEqual(self.path.stat().st_size,262144)
    def test_time(self):
        now=[0]
        r=self.make(max_seconds=1,clock=lambda:now[0])
        now[0]=1
        r.handle('agent:step',{'session_id':'synthetic-session'})
        self.assertEqual(r.reason,'time_limit'); self.assertEqual(r.count,0)
    def test_size(self):
        r=self.make(max_bytes=1)
        r.handle('agent:step',{'session_id':'synthetic-session'})
        self.assertEqual(self.path.stat().st_size,0);self.assertTrue(r.closed)
    def test_iteration_type(self):
        r=self.make(fields=['iteration'])
        for value in (True,'CANARY',{},-1,10001):
            r.handle('agent:step',{'session_id':'synthetic-session','iteration':value})
        self.assertTrue(all(json.loads(x)['fields']=={} for x in self.path.read_text().splitlines()))
    def test_adapter_opt_in(self):
        from bsv_hermes.receipts import gateway_adapter as adapter
        adapter.disarm()
        adapter.handle('agent:start',{'session_id':'synthetic-session'})
        self.assertFalse(self.path.exists())
        self.r=adapter.arm(self.path,consent=True,session_id='synthetic-session',events=['agent:end'])
        with self.assertRaises(RuntimeError):
            adapter.arm(self.path,consent=True,session_id='synthetic-session',events=['agent:end'])
        adapter.handle('agent:end',{'session_id':'synthetic-session','message':'CANARY'})
        self.assertTrue(self.r.closed)
        self.assertNotIn('CANARY',self.path.read_text())

    def test_symlink_refused(self):
        target=Path(self.tmp.name)/'target'
        target.write_text('keep')
        self.path.symlink_to(target)
        with self.assertRaises(FileExistsError): self.make()
        self.assertEqual(target.read_text(),'keep')

    def test_no_overwrite(self):
        self.path.write_text('keep')
        with self.assertRaises(FileExistsError): self.make()
        self.assertEqual(self.path.read_text(),'keep')

if __name__=='__main__': unittest.main(verbosity=2)
