import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_mainnet_workflow import sdk_ready


class MainnetCLI(unittest.TestCase):
    def run_cli(self, *args, input=None):
        return subprocess.run([sys.executable, '-B', '-m', 'bsv_hermes.mainnet', *args],
                              input=input, capture_output=True, text=True, timeout=20)

    def test_doctor_requires_no_wallet_path_and_no_keys(self):
        result = self.run_cli('doctor')
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)['result']
        self.assertFalse(value['wallet_opened'])
        self.assertFalse(value['ready_for_mainnet'])
        self.assertEqual(value['sdk_expected'], '2.4.0')

    @unittest.skipUnless(sdk_ready(), 'isolated mainnet extra required')
    def test_cli_initializes_only_with_explicit_create_and_cap(self):
        with tempfile.TemporaryDirectory(prefix='bsv-cli-test-') as temp:
            root, authority = str(Path(temp)/'runtime'), str(Path(temp)/'operator')
            args = ('init', '--directory', root, '--authority-directory', authority,
                    '--total-cap-sat', '300', '--max-fee-sat', '150', '--fee-rate-sat-kb', '500')
            denied = self.run_cli(*args)
            self.assertNotEqual(denied.returncode, 0)
            self.assertFalse(Path(root).exists())
            result = self.run_cli(*args, '--create-dedicated-wallet')
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            address = self.run_cli('address', '--directory', root)
            self.assertEqual(json.loads(result.stdout)['result'], json.loads(address.stdout)['result'])
            self.assertNotIn('private_key', address.stdout)
            again = self.run_cli(*args, '--create-dedicated-wallet')
            self.assertNotEqual(again.returncode, 0)

    def test_argument_errors_never_echo_supplied_values(self):
        result = self.run_cli('--unknown', 'PRIVATE-CANARY')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('PRIVATE-CANARY', result.stdout+result.stderr)
