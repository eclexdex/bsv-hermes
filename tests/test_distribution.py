import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class DistributionTests(unittest.TestCase):
    def test_native_directory_entry_and_manifest(self):
        entry = ROOT / '__init__.py'
        self.assertTrue(entry.is_file(), 'native directory entry missing')
        spec = importlib.util.spec_from_file_location('native_bsv_fixture', entry, submodule_search_locations=[str(ROOT)])
        module = importlib.util.module_from_spec(spec)
        import sys
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.assertTrue(callable(module.register))
        text = (ROOT / 'plugin.yaml').read_text()
        self.assertIn('name: bsv-hermes', text)
        for name in ('bsv_capabilities', 'bsv_inspect_script', 'bsv_inspect_transaction', 'bsv_plan_commitment'):
            self.assertIn(name, text)

    def test_package_and_workflow_inventory(self):
        self.assertTrue((ROOT / 'pyproject.toml').is_file(), 'build metadata missing')
        for name in ('inspect-evidence', 'plan-commitment', 'audit-workproducts'):
            text = (ROOT / 'bsv_hermes' / 'skills' / name / 'SKILL.md').read_text()
            self.assertTrue(text.startswith('---\n'))
            for section in ('## When to Use', '## Procedure', '## Pitfalls', '## Verification'):
                self.assertIn(section, text)

    def test_manifest_generator_and_canonical_inventory(self):
        self.assertTrue((ROOT/'scripts/update_manifest.py').is_file(), 'canonical manifest generator missing')
        import hashlib, json, subprocess, sys, tempfile, shutil
        with tempfile.TemporaryDirectory() as temp:
            source=pathlib.Path(temp)/'source'
            shutil.copytree(ROOT,source,ignore=shutil.ignore_patterns('local-verification','build','dist','.git','*.egg-info','__pycache__'))
            result=subprocess.run([sys.executable,'-B',str(source/'scripts/update_manifest.py')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            raw=(source/'SOURCE-MANIFEST.json').read_bytes(); data=json.loads(raw)
            self.assertEqual(raw,(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n').encode())
            self.assertNotIn('SOURCE-MANIFEST.json',data['files'])
            self.assertIn('scripts/install_local.py',data['files'])
            self.assertIn('bsv_hermes/kits/assurance/core.py',data['files'])
            for name,digest in data['files'].items():
                self.assertEqual(hashlib.sha256((source/name).read_bytes()).hexdigest(),digest)
                self.assertNotIn('local-verification',name)
            self.assertEqual(sum(n.endswith('plugin.yaml') for n in data['files']),1)
            self.assertEqual(sum(n.endswith('/SKILL.md') for n in data['files']),3)

    def test_import_is_offline_and_skills_have_metadata(self):
        import subprocess, sys
        result=subprocess.run([sys.executable,'-B','-c',
            "import socket; socket.socket.connect=lambda *a,**k: (_ for _ in ()).throw(AssertionError('network')); socket.create_connection=socket.socket.connect; import bsv_hermes.adapter"],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        for name in ('inspect-evidence','plan-commitment','audit-workproducts'):
            text=(ROOT/'bsv_hermes/skills'/name/'SKILL.md').read_text()
            desc=next(line.split(': ',1)[1] for line in text.splitlines() if line.startswith('description:'))
            self.assertLessEqual(len(desc),60); self.assertTrue(desc.endswith('.'))
            self.assertIn('license: Pending operator decision',text)
            self.assertNotIn('/Users/',text)
