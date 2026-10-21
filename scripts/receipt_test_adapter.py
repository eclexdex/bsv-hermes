"""Trusted test adapter only. Explicit synthetic bytes, never bundle-named paths."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile

source=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parents[1]
sys.path.insert(0,str(source))
from bsv_hermes.receipts import evidence, verifier
assert Path(verifier.__file__).resolve().is_relative_to(source)


def main():
    request=json.loads(sys.stdin.buffer.read(4*1024*1024))
    result={k:'missing' for k in ('artifact','chain','signature','batch','inclusion','publication')}
    result.update(parse='mismatch',source='unverified')
    try:
        bundle=verifier.strict_load(request['bundle'].encode())
        with tempfile.TemporaryDirectory(prefix='receipt-vector-') as temp:
            grants={}
            for i,(name,hexdata) in enumerate(request.get('artifacts_hex',{}).items()):
                path=Path(temp)/str(i);path.write_bytes(bytes.fromhex(hexdata));grants[name]=path
            trust={k:request[k] for k in ('batch_commitment','trusted_key','now') if k in request}
            report=evidence.verify(bundle,grants,**trust)
            result.update({k:v['status'] for k,v in report['results'].items()})
            result['parse']='match'
            # Forbidden aggregate verdicts must survive normalization, not be hidden.
            if 'verified' in report: result['verified']=report['verified']
    except (ValueError,TypeError,KeyError,RecursionError):
        pass
    result['implementation']={str(Path(m.__file__).resolve()):hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in (evidence,verifier)}
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
