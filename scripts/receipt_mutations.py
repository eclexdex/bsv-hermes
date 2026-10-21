"""Reset-between-mutants production receipt audit. Only synthetic temporary copies.

No changes to the source under test. Calls the lane10-derived blackbox harness.
A process failure is NOT counted as an assertion kill.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
MUTANTS=[
 ('artifact-always-match','verifier.py',"'match' if len(data) == artifact['size'] and digest(data) == artifact['sha256'] else 'mismatch'","'match'"),
 ('chain-always-match','verifier.py',"'match' if linked else 'mismatch'","'match'"),
 ('batch-always-match','batch.py',"return step == len(siblings) and commitment(node, count, proof['network']) == hex32(expected_commitment)","return True"),
 ('signature-always-match','signature.py',"    if sidecar is None:","    return result('match', 'mutation')\n    if sidecar is None:"),
 ('provider-is-inclusion','evidence.py',"        status = 'missing' if 'raw_tx_hex' not in sidecar else 'mismatch' if any(type(x) is dict and x.get('status') == 'mismatch' for x in details.values()) else 'unchecked'","        status = 'match'"),
 ('aggregate-green','evidence.py',"return {'report_format': REPORT, 'adapter': ADAPTER,","return {'verified': True, 'report_format': REPORT, 'adapter': ADAPTER,"),
]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    report={'runs':[],'source':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'bsv_hermes/receipts').glob('*.py')}}
    for label,file,old,new in [('pristine',None,None,None)]+MUTANTS:
        with tempfile.TemporaryDirectory(prefix='receipt-mutation-') as temp:
            root=Path(temp);package=root/'bsv_hermes';package.mkdir()
            shutil.copyfile(ROOT/'bsv_hermes/__init__.py',package/'__init__.py')
            shutil.copytree(ROOT/'bsv_hermes/receipts',package/'receipts',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            if file:
                path=package/'receipts'/file;text=path.read_text()
                assert text.count(old)==1,(label,'invalid mutation match count')
                path.write_text(text.replace(old,new))
            result=root/'report.json'
            cmd=[sys.executable,str(ROOT/'scripts/receipt_adversarial.py'),'--output',str(result),'--command',sys.executable,str(ROOT/'scripts/receipt_test_adapter.py'),str(root)]
            proc=subprocess.run(cmd,cwd=root,capture_output=True,text=True,timeout=120)
            data=json.loads(result.read_text())
            # Verify each child's module paths/hashes, including parser-rejection cases.
            for case in data['findings']:
                for path,digest in case.get('dimensions',{}).get('implementation',{}).items():
                    assert Path(path).is_relative_to(root) and hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
            failures=[x for x in data['findings'] if not x['passed']]
            invalid=[x for x in failures if 'error' in x or 'exit_code' in x.get('differences',{})]
            outcome='pristine-pass' if label=='pristine' and proc.returncode==0 else 'assertion-kill' if label!='pristine' and failures and not invalid else 'invalid-or-survived'
            report['runs'].append({'label':label,'outcome':outcome,'cases':data['cases'],'passed':data['passed'],'failed_cases':[x['id'] for x in failures], 'command':cmd,'exitcode':proc.returncode,'import_paths_hashes_verified':True,
                'mutation_file':file,'mutated_sha256':hashlib.sha256((package/'receipts'/file).read_bytes()).hexdigest() if file else None})
    report['killed']=sum(x['outcome']=='assertion-kill' for x in report['runs'])
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return int(report['runs'][0]['outcome']!='pristine-pass' or report['killed']!=len(MUTANTS))

if __name__=='__main__':raise SystemExit(main())
