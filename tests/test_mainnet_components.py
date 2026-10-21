import importlib
import unittest


class MainnetComponents(unittest.TestCase):
    def test_selected_components_are_bundled_not_research_path_imports(self):
        names = ('wallet', 'funding', 'builder', 'signer', 'broadcast', 'publish', 'spend_policy')
        for name in names:
            with self.subTest(name=name):
                module = importlib.import_module('bsv_hermes.mainnet.' + name)
                self.assertIn('bsv_hermes/mainnet/', module.__file__)
                self.assertNotIn('toolkit-recon', module.__file__)
