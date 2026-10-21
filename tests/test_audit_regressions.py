"""Independent regressions for confirmed low audit findings. Synthetic/offline."""
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class AuditRegressions(unittest.TestCase):
    def test_closing_other_journal_preserves_sqlite_process_lock(self):
        from bsv_hermes.mainnet.broadcast.journal import Journal
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'journal.sqlite'
            first, second = Journal(path), Journal(path)
            try:
                with first._connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    second.close()
                    code="import sqlite3,sys;db=sqlite3.connect(sys.argv[1],timeout=0.1)\ntry:\n db.execute('BEGIN IMMEDIATE');print('unlocked')\nexcept sqlite3.OperationalError:\n print('locked')"
                    p=subprocess.run([sys.executable,'-I','-c',code,str(path)],capture_output=True,text=True,timeout=3)
                    self.assertEqual(p.stdout.strip(),'locked',p.stderr)
            finally:
                first.close();second.close()

    def test_funding_worker_rejects_ambiguous_truncated_raw_http(self):
        from bsv_hermes.mainnet.funding.transport import _WORKER
        prelude = '''import io,http.client,urllib.request
class Sock:
 def makefile(self,*a,**k): return io.BytesIO(bytes.fromhex(WIRE))
class Opener:
 def open(self,*a,**k):
  r=http.client.HTTPResponse(Sock());r.begin();return r
urllib.request.build_opener=lambda *a,**k:Opener()
'''
        cases = [
            (b'Content-Length: 2\r\n', b'[]', False),
            (b'Transfer-Encoding: chunked\r\n', b'2\r\n[]\r\n0\r\n\r\n', False),
            (b'Content-Length: 50\r\n', b'[]', True),
            (b'Content-Length: 2\r\nContent-Length: 50\r\n', b'[]', True),
            (b'Content-Length: 2\r\nContent-Length: 2\r\n', b'[]', True),
            (b'Content-Length: 2\r\nTransfer-Encoding: chunked\r\n', b'2\r\n[]\r\n0\r\n\r\n', True),
        ]
        for headers, body, reject in cases:
            with self.subTest(headers=headers):
                wire = b'HTTP/1.1 200 OK\r\n'+headers+b'\r\n'+body
                code = 'WIRE='+repr(wire.hex())+'\n'+prelude+'\n'+_WORKER
                p = subprocess.run([sys.executable,'-I','-S','-c',code],input=json.dumps({'url':'https://api.whatsonchain.com/v1/bsv/main/tx/'+'00'*32+'/hex','timeout':1,'max_bytes':100}).encode(),capture_output=True,env={},timeout=3)
                result = json.loads(p.stdout)
                if reject: self.assertEqual(result.get('error'),'NETWORK_ERROR')
                else: self.assertEqual(result['body_hex'], '5b5d')

    def test_component_provenance_accepts_arbitrary_ancestor(self):
        with tempfile.TemporaryDirectory(prefix='toolkit-recon-') as d:
            dest=Path(d)
            shutil.copytree(ROOT/'bsv_hermes', dest/'bsv_hermes', ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            p=subprocess.run([sys.executable, str(ROOT/'tests/test_mainnet_components.py')],capture_output=True,text=True,cwd=dest)
            # Explicit unittest runner, not executing a module lacking unittest.main.
            code="import sys,unittest;sys.path.insert(0,'.');sys.path.insert(1,"+repr(str(ROOT/'tests'))+");import test_mainnet_components; r=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromModule(test_mainnet_components));sys.exit(not r.wasSuccessful())"
            p=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,cwd=dest)
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)

    def test_legacy_float_bytes_preserved_and_documented(self):
        from bsv_hermes.kits.identity.core import canonical
        self.assertEqual(canonical({'x':1.5}), b'{"x":1.5}')
        self.assertIn('finite floats', canonical.__doc__)
        with self.assertRaises(ValueError): canonical({'x':float('nan')})

    def test_readme_images_and_dashboard_scope(self):
        text=(ROOT/'README.md').read_text()
        self.assertNotIn('v0.2.0 plugin',text)
        urls=re.findall(r'!\[[^\]]*\]\(([^)]+)\)',text)
        self.assertTrue(urls)
        self.assertTrue(all(x.startswith('https://raw.githubusercontent.com/eclexdex/bsv-hermes/') for x in urls),urls)

    def test_live_broadcast_journal_does_not_reopen_substituted_db(self):
        from bsv_hermes.mainnet.broadcast.journal import Journal, JournalError
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); path=root/'journal.sqlite'; other=root/'other.sqlite'
            journal=Journal(path); target=Journal(other)
            self.assertTrue(journal.claim('mainnet','11'*32,'fixture'))
            path.rename(root/'saved.sqlite'); path.symlink_to(other)
            with self.assertRaises(JournalError): journal.get('mainnet','11'*32)
            self.assertIsNone(target.get('mainnet','11'*32))
        # A live Journal must retain a pinned SQLite connection, not reopen a path.
        with tempfile.TemporaryDirectory() as d:
            journal=Journal(Path(d)/'journal.sqlite')
            with patch('bsv_hermes.mainnet.broadcast.journal.sqlite3.connect', side_effect=AssertionError('reopen forbidden')):
                self.assertIsNone(journal.get('mainnet','22'*32))
