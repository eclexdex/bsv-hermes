"""Offline receipt release acceptance, derived from the receipt-wave release lane.

Snapshot only exact manifest-listed ordinary files; never copy research/venvs.
Build prerequisites must already exist. No package-index, live config or funds.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import zipfile


def digest(raw): return hashlib.sha256(raw).hexdigest()


def safe_name(name):
    p=PurePosixPath(name)
    return bool(p.parts) and not p.is_absolute() and '..' not in p.parts and '\\' not in name and ':' not in name and str(p)==name


def inventory(entries):
    findings=[]
    for name,data in entries:
        if not safe_name(name): findings.append({'file':name,'rule':'unsafe-path'})
        if any(x.lower() in {'.env','.git','.hermes','wallet.json','authority.json','state.db','soul.md','memory.md','sessions','local-verification','__pycache__'} for x in PurePosixPath(name).parts):
            findings.append({'file':name,'rule':'private-name'})
        private_path = b'(?:/' + b'Users/[^/\\s]+/|/' + b'home/[^/\\s]+/|[A-Z]:\\\\Users\\\\)'
        if re.search(private_path,data):
            findings.append({'file':name,'rule':'absolute-private-path'})
        patterns=[rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',rb'(?i)(?:api_key|access_token|password)\s*[:=]\s*[\"\'][A-Za-z0-9_/-]{24,}']
        if any(re.search(p,data) for p in patterns): findings.append({'file':name,'rule':'secret-pattern'})
    return findings


def archive_entries(path):
    entries=[];names=set();size=0
    def add(name,data):
        nonlocal size
        if not safe_name(name) or name in names: raise ValueError('archive path/duplicate')
        names.add(name);size+=len(data)
        if len(names)>2000 or size>64*1024*1024: raise ValueError('archive budget')
        entries.append((name,data))
    if path.suffix=='.whl':
        with zipfile.ZipFile(path) as z:
            for member in z.infolist():
                if stat.S_ISLNK(member.external_attr>>16): raise ValueError('archive link')
                if member.is_dir():continue
                if member.file_size>8*1024*1024: raise ValueError('member budget')
                add(member.filename,z.read(member))
    else:
        with tarfile.open(path) as t:
            for member in t:
                if member.isdir():continue
                if not member.isfile() or member.size>8*1024*1024:raise ValueError('archive link/type/size')
                add(member.name,t.extractfile(member).read())
    return entries


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--hermes-python');p.add_argument('--hermes-source');p.add_argument('--sdk-python');p.add_argument('--browser-python')
    args=p.parse_args();source=args.source.resolve();out=args.out.resolve()
    # Pin the already available build-package roots before isolating HOME. On
    # macOS, changing HOME otherwise silently falls back to ancient system tools.
    build_env={'PYTHONPATH':os.pathsep.join(sorted({str(importlib.metadata.distribution(x).locate_file('')) for x in ('setuptools','wheel')}))}
    out.mkdir(parents=True,exist_ok=False)
    tmp=out/'tmp';tmp.mkdir()
    env=dict(os.environ,SOURCE_DATE_EPOCH='1700000000',PYTHONHASHSEED='0',PYTHONDONTWRITEBYTECODE='1',PIP_NO_INDEX='1',PIP_DISABLE_PIP_VERSION_CHECK='1',TMPDIR=str(tmp))
    env.pop('PYTHONPATH',None);env['HOME']=str(out/'isolated-home');env['HERMES_HOME']=str(out/'isolated-home/hermes')
    Path(env['HOME']).mkdir()
    report={'format':'bsv-hermes-receipt-release/v1','commands':[],'source_hashes':{},'archives':{},
            'skips':['Funded canary/public POST/live hooks/operator-key signing NOT EXECUTED.',
                     'Selected-chain validation and authenticated execution are not implemented.',
                     'Source/secret inventory is heuristic; license selection remains pending.',
                     'sdist gzip/tar byte reproducibility not asserted; rebuilt wheel equality is tested.']}
    def run(argv,cwd,extra=None):
        argv=list(map(str,argv));e=dict(env);e.update(extra or {})
        proc=subprocess.run(argv,cwd=cwd,env=e,capture_output=True,text=True,timeout=180)
        log=out/('command-%03d.log'%len(report['commands']));log.write_text(proc.stdout+'\n--- STDERR ---\n'+proc.stderr)
        report['commands'].append({'argv':argv,'cwd':str(cwd),'exitcode':proc.returncode,'log':str(log),'log_sha256':digest(log.read_bytes()),'extra_env':extra or {}})
        if proc.returncode:raise RuntimeError('command failed: '+str(argv))
        return proc.stdout
    try:
        versions=run([sys.executable,'-c',"import importlib.metadata as m,json;v={x:m.version(x) for x in ('setuptools','wheel')};assert int(v['setuptools'].split('.')[0])>=77;print(json.dumps(v))"],out,build_env)
        report['build_versions']=json.loads(versions)
        manifest=(source/'SOURCE-MANIFEST.json').read_bytes();files=json.loads(manifest)['files']
        report['manifest_sha256']=digest(manifest)
        stage=out/'snapshot';stage.mkdir()
        for name,expected in dict(files,**{'SOURCE-MANIFEST.json':digest(manifest)}).items():
            if not safe_name(name):raise ValueError('source path')
            src=source/name
            if src.is_symlink() or not src.is_file():raise ValueError('source not ordinary')
            data=src.read_bytes()
            if digest(data)!=expected:raise ValueError('source hash drift: '+name)
            dest=stage/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
            report['source_hashes'][name]=expected
        findings=inventory([(n,(stage/n).read_bytes()) for n in report['source_hashes']])
        report['source_scan']=findings
        if findings:raise ValueError('source scan findings')
        run([sys.executable,'scripts/update_manifest.py','--check'],stage)
        run([sys.executable,'-c',"import setuptools.build_meta as b;b.build_wheel('dist');b.build_sdist('dist')"],stage,build_env)
        artifacts=sorted((stage/'dist').iterdir())
        for artifact in artifacts:
            if not artifact.name.startswith('bsv_hermes-'):raise ValueError('unexpected distribution identity')
            entries=archive_entries(artifact);findings=inventory(entries)
            report['archives'][artifact.name]={'sha256':digest(artifact.read_bytes()),'inventory':{n:digest(d) for n,d in entries},'findings':findings}
            if findings:raise ValueError('archive privacy scan')
        wheel=next(x for x in artifacts if x.suffix=='.whl');sdist=next(x for x in artifacts if x.name.endswith('.tar.gz'))
        original=digest(wheel.read_bytes())
        run([sys.executable,'-c',"import setuptools.build_meta as b;b.build_wheel('dist')"],stage,build_env)
        report['wheel_repeat_identical']=digest(wheel.read_bytes())==original
        unpack=out/'extracted';unpack.mkdir()
        for name,data in archive_entries(sdist):
            dest=unpack/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
        extracted=next(unpack.iterdir());report['extracted_source']=str(extracted)
        run([sys.executable,'scripts/update_manifest.py','--check'],extracted)
        run([sys.executable,'-c',"import setuptools.build_meta as b;b.build_wheel('dist')"],extracted,build_env)
        rebuilt=next((extracted/'dist').glob('*.whl'));report['sdist_wheel_identical']=digest(rebuilt.read_bytes())==original
        if not report['wheel_repeat_identical'] or not report['sdist_wheel_identical']:raise ValueError('nonreproducible wheel')
        report['installed']={}
        for label,artifact in [('wheel',wheel),('sdist-wheel',rebuilt)]:
            venv=out/('clean-'+label);run([sys.executable,'-m','venv',venv],out);python=venv/'bin/python'
            run([python,'-m','pip','install','--no-index','--no-deps',artifact],out)
            probe="""import importlib.util,json,pathlib,sys
from bsv_hermes.receipts import evidence,verifier,viewer
assert importlib.util.find_spec('cryptography') is None
assert importlib.util.find_spec('bsv') is None
assert importlib.util.find_spec('hermes_cli') is None
assert 'site-packages' in verifier.__file__
assert not any(x.startswith(('hermes_cli','bsv_hermes.mainnet','cryptography')) for x in sys.modules)
fixture=pathlib.Path(sys.argv[1]);b=json.loads((fixture/'contract/golden.json').read_text());r=evidence.verify(b)
assert r['results']['chain']['status']=='match'
assert r['results']['artifact']['status']=='unchecked'
assert r['results']['signature']['status']=='missing'
assert r['results']['inclusion']['selected_chain']['status']=='unchecked'
v={'adapter':evidence.ADAPTER,'bundle':b,'signature':{'version':1,'domain':'bsv-hermes/receipt-signature/v1','algorithm':'Ed25519','public_key_sha256':verifier.digest(bytes(32)),'bundle_sha256':verifier.digest(verifier.contract_canonical(b)),'issued_at':100,'expires_at':200,'nonce':'00'*16,'signature':'A'*86+'=='}}
r=evidence.verify(v,trusted_key='00'*32,now=150)
assert r['results']['signature']['status']=='unchecked',r
pathlib.Path('installed-viewer.html').write_text(viewer.generate({'source_label':'SYNTHETIC installed-wheel receipt','bundle':b,'report':r}))
print(json.dumps({'import':verifier.__file__,'report':r},sort_keys=True))
"""
            cwd=out/('probe-'+label);cwd.mkdir()
            probe_result=json.loads(run([python,'-I','-c',probe,extracted/'tests/receipt_vectors'],cwd))
            report['installed'][label]=probe_result
            run([python,'-I','-m','bsv_hermes.receipts','create',extracted/'examples/receipt-request.json','--output',cwd/'bundle.json'],cwd)
            run([venv/'bin/bsv-receipt-verify',cwd/'bundle.json','--artifact','instruction='+str(extracted/'examples/receipt-instruction.txt'),'--artifact','output='+str(extracted/'examples/receipt-output.txt'),'--output',cwd/'report.json'],cwd)
            assert json.loads((cwd/'report.json').read_text())['results']['artifact']['status']=='match'
            run([venv/'bin/bsv-receipt','view',cwd/'report.json','--output',cwd/'cli-viewer.html'],cwd)
            suite="import sys,unittest;sys.path.insert(0,sys.argv[1]);s=unittest.defaultTestLoader.discover(sys.argv[1],pattern='test_receipt_*.py');r=unittest.TextTestRunner(verbosity=2).run(s);sys.exit(not r.wasSuccessful())"
            run([python,'-I','-c',suite,extracted/'tests'],cwd)
        profile=out/'isolated-profile';profile.mkdir()
        run([sys.executable,'scripts/install_local.py','--profile',profile,'--install'],extracted)
        if args.hermes_python and args.hermes_source:
            hostenv={'PYTHONPATH':str(Path(args.hermes_source).resolve())}
            for script in ('native_smoke.py','receipt_host_smoke.py'):
                run([args.hermes_python,extracted/'scripts'/script,extracted],out,hostenv)
            if args.sdk_python:
                run([args.hermes_python,extracted/'scripts/mainnet_smoke.py',extracted,'--sdk-python',args.sdk_python],out,hostenv)
            else:report['skips'].append('Extracted mainnet native SDK smoke not requested.')
        else:report['skips'].append('Extracted actual Hermes discovery/dispatch/hooks not requested.')
        if args.browser_python:
            run([args.browser_python,extracted/'scripts/receipt_browser_smoke.py','--out',out/'browser','--html',out/'probe-wheel/installed-viewer.html'],out,build_env)
        else:report['skips'].append('Browser smoke not requested.')
        report['result']='acceptance-completed-not-license-or-funding-approval';code=0
    except Exception as ex:
        report['result']='blocked';report['error']=str(ex);code=1
    (out/'RESULTS.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'result':report['result'],'report':str(out/'RESULTS.json'),'error':report.get('error')}))
    return code

if __name__=='__main__':raise SystemExit(main())
