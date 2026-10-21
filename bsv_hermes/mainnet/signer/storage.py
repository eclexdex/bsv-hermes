"""POSIX descriptor-relative private storage; never discover a default wallet.

Threat model: root and the current uid are trusted. No protection against those
principals replacing files/ancestors, filesystem ACL overrides or reading memory.
"""
from contextlib import contextmanager
import json
import os
import re
import stat


class StorageError(Exception):
    pass


class AlreadyConsumed(StorageError):
    pass


def consume(directory, approval_id, digest):
    if re.fullmatch('[0-9a-f]{64}', approval_id) is None or re.fullmatch('[0-9a-f]{64}', digest) is None:
        raise StorageError()
    with private_directory(directory) as parent:
        fd = None
        try:
            fd = os.open(approval_id, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
            # Creation is the irrevocable consumption point. Even a short write,
            # fsync failure or crash burns this approval, never grants a retry.
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write((digest + '\n').encode('ascii'))
                stream.flush()
            os.fsync(fd)
            os.fsync(parent)
        except FileExistsError:
            raise AlreadyConsumed() from None
        except OSError:
            raise StorageError() from None
        finally:
            if fd is not None:
                os.close(fd)


def path_parts(path):
    if (type(path) is not str or not 1 < len(path) <= 4096 or not path.startswith('/')
            or '\0' in path or any(p in ('', '.', '..') for p in path.split('/')[1:])):
        raise StorageError()
    return path.split('/')[1:]


def _check_directory(fd, private=False):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise StorageError()
    if private:
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise StorageError()
    elif info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise StorageError()


@contextmanager
def private_directory(path):
    parts = path_parts(path)
    if os.name != 'posix' or not all(hasattr(os, n) for n in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC')):
        raise StorageError()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
    fd = None
    try:
        fd = os.open('/', flags)
        _check_directory(fd)
        for i, part in enumerate(parts):
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            _check_directory(fd, private=(i == len(parts) - 1))
        yield fd
    except OSError:
        raise StorageError() from None
    finally:
        if fd is not None:
            os.close(fd)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise StorageError()
            result[key] = value
        return result

    def constant(_):
        raise StorageError()

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def read_private_json(path, limit=4096):
    parts = path_parts(path)
    parent = '/' + '/'.join(parts[:-1])
    fd = None
    try:
        with private_directory(parent) as directory:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= limit):
                raise StorageError()
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise StorageError()
            return strict_json(raw)
    except Exception:
        raise StorageError() from None
    finally:
        if fd is not None:
            os.close(fd)
