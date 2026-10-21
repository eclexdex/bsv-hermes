import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]


class ReleaseGuardTests(unittest.TestCase):
    def module(self):
        path=ROOT/'scripts/receipt_release_check.py'
        self.assertTrue(path.is_file(), 'receipt release acceptance missing')
        spec=importlib.util.spec_from_file_location('receipt_release_check',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_private_inventory_and_archive_links_rejected(self):
        m=self.module()
        self.assertEqual(m.inventory([('bsv_hermes/receipts/__init__.py',b'')]), [])
        self.assertTrue(m.inventory([('wallet.json',b'{}')]))
        canary = b'password=' + b'"' + b'SYNTHETIC_CANARY_NOT_REAL_SECRET' + b'"'
        self.assertTrue(m.inventory([('source.py',canary)]))
        self.assertTrue(m.inventory([('../escape',b'')]))
        self.assertTrue(m.inventory([('source.py',b'/' + b'Users' + b'/synthetic/private')]))
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'bad.whl'
            with zipfile.ZipFile(path,'w') as z:
                member=zipfile.ZipInfo('link');member.create_system=3;member.external_attr=0o120777<<16
                z.writestr(member,'target')
            with self.assertRaises(ValueError):m.archive_entries(path)
