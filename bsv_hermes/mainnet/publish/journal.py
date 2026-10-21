"""Private atomic checkpoints and cross-process reservations on one POSIX host.

An advisory flock covers each workflow call, including bounded adapter calls.
Checkpoints are fsync'd before submission. No reservation expires automatically.
Use one operator-controlled directory for every publisher of the same wallet.
"""
import contextlib
import fcntl
import json
import os
import secrets
import stat
from pathlib import Path
from .errors import PublishError

MAX_JOURNAL_BYTES = 32 * 1024 * 1024


def _unique_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def _directory(path):
    """Open every existing ancestor without following symlinks."""
    path = Path(path).absolute()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise PublishError('journal_directory_not_private')
        return fd
    except BaseException:
        os.close(fd)
        raise


class Session:
    def __init__(self, directory_fd):
        self.fd = directory_fd
        try:
            file_fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        except FileNotFoundError:
            self.data = {'version': 1, 'workflows': {}, 'reservations': {}}
            return
        try:
            st = os.fstat(file_fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_JOURNAL_BYTES or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
                raise PublishError('journal_corrupt')
            with os.fdopen(file_fd, 'rb') as stream:
                file_fd = None
                self.data = json.loads(stream.read(MAX_JOURNAL_BYTES + 1), object_pairs_hook=_unique_keys)
            if type(self.data) is not dict or set(self.data) != {'version', 'workflows', 'reservations'} or type(self.data['version']) is not int or self.data['version'] != 1 or type(self.data['workflows']) is not dict or type(self.data['reservations']) is not dict:
                raise PublishError('journal_corrupt')
        except (ValueError, TypeError, UnicodeError):
            raise PublishError('journal_corrupt') from None
        finally:
            if file_fd is not None:
                os.close(file_fd)

    def save(self):
        payload = json.dumps(self.data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        if len(payload) > MAX_JOURNAL_BYTES:
            raise PublishError('journal_full')
        name = '.checkpoint-' + secrets.token_hex(12)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, 'state.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(name, dir_fd=self.fd)
            except FileNotFoundError:
                pass


class Journal:
    def __init__(self, directory):
        # Directory provisioning belongs to the host, not model-supplied paths.
        self.directory = str(Path(directory).absolute())

    @contextlib.contextmanager
    def session(self):
        directory_fd = _directory(self.directory)
        lock_fd = None
        try:
            lock_fd = os.open('.publish.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            st = os.fstat(lock_fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
                raise PublishError('journal_lock_invalid')
            # Do not hang a Hermes call behind a slow adapter in another process.
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PublishError('workflow_busy') from None
            yield Session(directory_fd)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(directory_fd)
