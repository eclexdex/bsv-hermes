"""Create the canonical shipping-file hash inventory; not an authenticity signature."""
import argparse
import hashlib
import json
from pathlib import Path
from install_local import read_regular

ROOT_FILES = ('__init__.py','plugin.yaml','pyproject.toml','MANIFEST.in','.gitignore',
              'README.md','SECURITY.md','CONTRIBUTING.md','LICENSE-POLICY.md','PROVENANCE.md','THIRD_PARTY.md')
DIRECTORIES = ('bsv_hermes','scripts','tests','docs','examples','.github')
SUFFIXES = {'.py','.md','.json','.yaml','.yml','.toml','.png','.txt'}


def create(root):
    paths=[root/name for name in ROOT_FILES if (root/name).is_file()]
    for directory in DIRECTORIES:
        paths.extend(p for p in (root/directory).rglob('*') if p.is_file() and p.suffix in SUFFIXES and '__pycache__' not in p.parts)
    files={p.relative_to(root).as_posix():hashlib.sha256(read_regular(p)).hexdigest() for p in sorted(paths)}
    return (json.dumps({'format':'bsv-hermes-source/v1','files':files},sort_keys=True,separators=(',',':'))+'\n').encode()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='Check only, never rewrite')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]; path=root/'SOURCE-MANIFEST.json'; raw=create(root)
    if args.check:
        if not path.is_file() or path.read_bytes()!=raw: raise SystemExit('Manifest does not match shipping files')
    else:
        if path.is_symlink() or (path.exists() and path.stat().st_nlink!=1): raise SystemExit('Unsafe manifest target')
        path.write_bytes(raw)
    print(json.dumps({'files':len(json.loads(raw)['files']),'manifest_sha256':hashlib.sha256(raw).hexdigest(),'self_included':False}))


if __name__=='__main__': main()
