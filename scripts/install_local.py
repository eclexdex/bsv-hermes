"""Offline explicit directory installer. Dry-run by default; never enables plugins."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat

MANIFEST = 'SOURCE-MANIFEST.json'
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024


def checked_path(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('An absolute path without traversal is required')
    for parent in reversed((path,*path.parents)):
        try: mode=parent.lstat().st_mode
        except FileNotFoundError: continue
        if stat.S_ISLNK(mode): raise ValueError('Symlink paths are not allowed')
    return path


def read_regular(path):
    checked_path(path)
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_FILE:
        raise ValueError('Only bounded single-link regular source files are allowed')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino) or opened.st_nlink!=1 or not stat.S_ISREG(opened.st_mode):
            raise ValueError('Source changed while opening')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(MAX_FILE+1)
        after=os.fstat(fd)
        if len(raw)>MAX_FILE or (after.st_size,after.st_mtime_ns,after.st_nlink)!=(opened.st_size,opened.st_mtime_ns,1):
            raise ValueError('Source changed while reading')
        return raw
    finally: os.close(fd)


def no_duplicates(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('Duplicate manifest key')
        result[key]=value
    return result


def source_payload(source):
    source=checked_path(source)
    raw=read_regular(source/MANIFEST)
    data=json.loads(raw,object_pairs_hook=no_duplicates)
    canonical=(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n').encode()
    if raw!=canonical or type(data) is not dict or set(data)!={'format','files'} or data['format']!='bsv-hermes-source/v1':
        raise ValueError('Invalid canonical source manifest')
    files=data['files']
    if type(files) is not dict or not 3<=len(files)<=256: raise ValueError('Invalid inventory')
    if not {'plugin.yaml','__init__.py','bsv_hermes/__init__.py'}<=set(files): raise ValueError('Native root missing')
    payload={}; total=len(raw)
    for name,digest in files.items():
        p=PurePosixPath(name)
        if not name or '\\' in name or p.is_absolute() or any(x in ('','.','..') for x in name.split('/')) or name==MANIFEST:
            raise ValueError('Invalid inventory path')
        if type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None: raise ValueError('Invalid hash')
        content=read_regular(source.joinpath(*p.parts)); total+=len(content)
        if total>MAX_TOTAL or hashlib.sha256(content).hexdigest()!=digest: raise ValueError('Source integrity check failed')
        payload[name]=content
    payload[MANIFEST]=raw
    return payload,hashlib.sha256(raw).hexdigest()


def install(source, profile, apply=False):
    profile=checked_path(profile)
    if not profile.is_dir(): raise ValueError('Explicit existing profile directory required')
    parent=checked_path(profile/'plugins')
    target=checked_path(parent/'bsv-hermes')
    if target.exists(): raise ValueError('Target exists; refusing overwrite or upgrade')
    if parent.exists() and not parent.is_dir(): raise ValueError('Plugin parent is not a directory')
    payload,manifest_hash=source_payload(source)
    if apply:
        parent.mkdir(mode=0o700,exist_ok=True)
        checked_path(parent)
        target.mkdir(mode=0o700)  # Exclusive: collision is always an error.
        try:
            for name,raw in payload.items():
                destination=target.joinpath(*PurePosixPath(name).parts)
                destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                checked_path(destination)
                with destination.open('xb') as stream: stream.write(raw)
            # Read back the exact installed target before reporting success.
            copied,copied_hash=source_payload(target)
            if copied_hash!=manifest_hash or copied!=payload: raise ValueError('Installed readback mismatch')
        except BaseException:
            # Only the newly created target is ours; never delete existing profiles/config.
            if not target.is_symlink(): shutil.rmtree(target)
            raise
    return {'ok':True,'mode':'installed' if apply else 'dry-run','target':str(target),
            'files':len(payload),'source_manifest_sha256':manifest_hash,'enabled':False,
            'next':'Set HERMES_HOME to the explicit profile, then run: hermes plugins enable bsv-hermes; restart Hermes or /reset.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1],help='Reviewed native source root (defaults to this extracted source)')
    parser.add_argument('--profile',type=Path,required=True,help='Explicit existing absolute Hermes profile directory')
    parser.add_argument('--install',action='store_true',help='Actually copy; otherwise verify and dry-run only')
    args=parser.parse_args()
    try: result=install(args.source,args.profile,args.install)
    except (ValueError,OSError,UnicodeError,RecursionError):
        print(json.dumps({'ok':False,'error':'Install rejected: check manifest integrity, absolute paths, regular files and target collisions.'}))
        return 1
    print(json.dumps(result,sort_keys=True)); return 0


if __name__=='__main__': raise SystemExit(main())
