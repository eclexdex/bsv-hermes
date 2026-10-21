import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/'scripts/install_local.py'

class InstallerTests(unittest.TestCase):
    def run_install(self, source, profile, *args):
        return subprocess.run([sys.executable,'-B',str(SCRIPT),'--source',str(source),'--profile',str(profile),*args],capture_output=True,text=True)

    def fixture(self, temp):
        source=Path(temp).resolve()/'source'; profile=Path(temp).resolve()/'profile'
        source.mkdir(); profile.mkdir()
        for name in ('plugin.yaml','__init__.py','bsv_hermes/__init__.py'):
            dest=source/name; dest.parent.mkdir(parents=True,exist_ok=True); dest.write_text('fixture\n')
        self.manifest(source)
        return source,profile

    def manifest(self, source):
        import hashlib
        files={str(p.relative_to(source)).replace('\\','/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file() and p.name!='SOURCE-MANIFEST.json'}
        (source/'SOURCE-MANIFEST.json').write_text(json.dumps({'format':'bsv-hermes-source/v1','files':files},sort_keys=True,separators=(',',':'))+'\n')

    def test_installer_exists_and_requires_explicit_target(self):
        self.assertTrue(SCRIPT.is_file(), 'reviewed local installer missing')
        result=subprocess.run([sys.executable,str(SCRIPT)],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('--profile',result.stderr)

    def test_default_dryrun_install_readback_no_config_mutation_collision(self):
        self.assertTrue(SCRIPT.is_file(), 'reviewed local installer missing')
        with tempfile.TemporaryDirectory() as t:
            source,profile=self.fixture(t)
            (profile/'config.yaml').write_text('sentinel: do-not-change\n')
            before=(profile/'config.yaml').read_bytes()
            dry=self.run_install(source,profile)
            self.assertEqual(dry.returncode,0,dry.stdout+dry.stderr)
            self.assertEqual(json.loads(dry.stdout)['mode'],'dry-run')
            self.assertFalse((profile/'plugins').exists())
            installed=self.run_install(source,profile,'--install')
            self.assertEqual(installed.returncode,0,installed.stdout+installed.stderr)
            dest=profile/'plugins'/'bsv-hermes'
            self.assertEqual((dest/'__init__.py').read_bytes(),(source/'__init__.py').read_bytes())
            self.assertEqual((profile/'config.yaml').read_bytes(),before)
            self.assertFalse(json.loads(installed.stdout)['enabled'])
            self.assertNotEqual(self.run_install(source,profile,'--install').returncode,0)

    def test_tamper_traversal_symlink_hardlink_and_target_links_rejected(self):
        self.assertTrue(SCRIPT.is_file(), 'reviewed local installer missing')
        import os
        for attack in ('tamper','traversal','source-link','hardlink','target-link'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as t:
                source,profile=self.fixture(t)
                leaf=source/'__init__.py'
                if attack=='tamper': leaf.write_text('changed')
                elif attack=='traversal':
                    data=json.loads((source/'SOURCE-MANIFEST.json').read_text()); data['files']['../escape']='0'*64
                    (source/'SOURCE-MANIFEST.json').write_text(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n')
                elif attack in ('source-link','hardlink'):
                    outside=Path(t)/'outside'; shutil.copyfile(leaf,outside); leaf.unlink()
                    if attack=='source-link': leaf.symlink_to(outside)
                    else: os.link(outside,leaf)
                else:
                    outside=Path(t)/'outside'; outside.mkdir(); (profile/'plugins').symlink_to(outside,target_is_directory=True)
                result=self.run_install(source,profile,'--install')
                self.assertNotEqual(result.returncode,0,result.stdout)
                self.assertFalse((profile/'plugins'/'bsv-hermes').exists())
