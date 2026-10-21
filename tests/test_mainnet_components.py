import importlib
import unittest
from pathlib import Path
import bsv_hermes.mainnet


class MainnetComponents(unittest.TestCase):
    def test_selected_components_are_bundled_not_research_path_imports(self):
        names = ('wallet', 'funding', 'builder', 'signer', 'broadcast', 'publish', 'spend_policy')
        for name in names:
            with self.subTest(name=name):
                module = importlib.import_module('bsv_hermes.mainnet.' + name)
                expected = Path(bsv_hermes.mainnet.__file__).resolve().parent
                self.assertTrue(Path(module.__file__).resolve().is_relative_to(expected))
