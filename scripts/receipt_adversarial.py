"""Run immutable vectors against an explicit JSONL verifier adapter (no shell)."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE=Path(__file__).parent

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--command', nargs=argparse.REMAINDER, default=[sys.executable,str(HERE/'receipt_test_adapter.py')])
    p.add_argument('--output',type=Path)
    args=p.parse_args()
    raw=(HERE.parent/'tests/receipt_vectors/adversarial-production.json').read_bytes()
    pinned=(HERE.parent/'tests/receipt_vectors/adversarial-production.sha256').read_text().strip()
    if hashlib.sha256(raw).hexdigest()!=pinned:
        raise SystemExit('immutable vectors hash mismatch')
    cases=json.loads(raw)['cases']; findings=[]
    for case in cases:
        try:
            # File-backed stdout bounds memory; adapter is explicitly caller-trusted code.
            import tempfile
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                process=subprocess.run(args.command,input=json.dumps(case['request']).encode()+b'\n',stdout=out,stderr=err,timeout=3)
                if out.tell()>65536: raise ValueError('adapter stdout limit')
                out.seek(0); actual=json.loads(out.read())
                differences={k:{'expected':v,'actual':actual.get(k)} for k,v in case['expected'].items() if actual.get(k)!=v}
                if 'verified' in actual: differences['verified']='forbidden aggregate verdict'
                if process.returncode: differences['exit_code']=process.returncode
            findings.append({'id':case['id'],'passed':not differences,'dimensions':actual,'differences':differences})
        except (ValueError,TypeError,AttributeError,subprocess.TimeoutExpired,OSError) as e:
            findings.append({'id':case['id'],'passed':False,'error':str(e)})
    report={'adapter_command':args.command,'fixture_sha256':pinned,'cases':len(cases),'passed':sum(f['passed'] for f in findings),'findings':findings,'scope':'production-format semantic translation of lane10; independent lane01 literal bytes; no authenticated execution or archive-import claim'}
    text=json.dumps(report,indent=2)+'\n'
    if args.output: args.output.write_text(text)
    else: print(text,end='')
    return int(report['passed']!=report['cases'])
if __name__=='__main__': sys.exit(main())
