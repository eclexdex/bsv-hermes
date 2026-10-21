import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_receipt_integration import request


class ReceiptCLI(unittest.TestCase):
    def run_cli(self, *args):
        p = subprocess.run([sys.executable, '-m', 'bsv_hermes.receipts', *map(str, args)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        return p

    def test_create_verify_view_offline_and_refuse_overwrite(self):
        self.assertIsNotNone(importlib.util.find_spec('bsv_hermes.receipts.__main__'), 'receipt CLI missing')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            req, bundle, report, view = [root/n for n in ('request.json', 'bundle.json', 'report.json', 'view.html')]
            req.write_text(json.dumps(request()))
            self.run_cli('create', req, '--output', bundle)
            self.assertEqual(json.loads(bundle.read_text())['version'], 'hermes-receipt/v1')
            p = self.run_cli('verify', bundle, '--output', report)
            actual = json.loads(report.read_text())
            self.assertEqual(actual['results']['chain']['status'], 'match')
            self.assertEqual(actual['results']['artifact']['status'], 'unchecked')
            self.run_cli('view', report, '--output', view)
            html = view.read_text()
            self.assertIn('Content-Security-Policy', html)
            self.assertIn('bsv-hermes/receipt-report/v2', html)
            self.assertNotIn('https://cdn', html)
            p = subprocess.run([sys.executable, '-m', 'bsv_hermes.receipts', 'create', str(req), '--output', str(bundle)], capture_output=True)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(bundle.stat().st_mode & 0o777, 0o600)
            symlink = root/'alias'; symlink.symlink_to(bundle)
            p = subprocess.run([sys.executable, '-m', 'bsv_hermes.receipts', 'verify', str(symlink)], capture_output=True)
            self.assertEqual(p.returncode, 2)
