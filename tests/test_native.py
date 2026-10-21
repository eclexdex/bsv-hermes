import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class NativeHarnessTests(unittest.TestCase):
    def test_native_smoke_harness_exists(self):
        self.assertTrue((ROOT / 'scripts' / 'native_smoke.py').is_file(), 'native smoke harness missing')

    @unittest.skipUnless(importlib.util.find_spec('hermes_cli'), 'Hermes host dependencies unavailable; run native_smoke.py with host Python')
    def test_real_native_registration_and_invocation(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'native_smoke.py'), str(ROOT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(len(receipt['registered_tools']), 6)
        self.assertEqual(len(receipt['registered_skills']), 3)
        self.assertEqual(len(receipt['optional']['registered_tools']), 19)
        self.assertTrue(receipt['optional']['config_readback'])
        self.assertEqual(receipt['dispatch_api'], 'registry.dispatch')
        self.assertTrue(all(item['ok'] for item in receipt['handler_results'].values()))
