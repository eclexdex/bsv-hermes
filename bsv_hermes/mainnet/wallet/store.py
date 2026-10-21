"""Owner-controlled, immutable-network P2PKH wallet storage.

Only this module handles private material. No wallet discovery, import, seed
phrases, automatic funding, transaction signing or network requests.
"""
from contextlib import contextmanager
from functools import wraps
import hashlib
import importlib.metadata
import json
import os
import secrets
import stat

FORMAT = 'bsv-hermes-local-wallet/v1'
SDK_VERSION = '2.4.0'
FILE_NAME = 'wallet.json'
MAX_DOCUMENT = 4096

ERRORS = {
    'invalid_input': 'Input rejected by wallet contract.',
    'wallet_exists': 'A wallet already exists; it will not be overwritten.',
    'wallet_missing': 'No dedicated wallet exists at the configured location.',
    'unsafe_storage': 'Wallet storage ownership, permissions or path safety check failed.',
    'wallet_corrupt': 'Wallet data failed integrity validation; no private details are returned.',
    'network_mismatch': 'The requested network does not match this wallet.',
    'wallet_mismatch': 'The expected wallet identifier does not match this wallet.',
    'sdk_unavailable': 'The pinned BSV SDK with native libsecp256k1 is required.',
    'storage_error': 'The wallet operation failed; inspect the private local store without sharing its contents.',
}


class WalletError(Exception):
    """Fixed public error; never accepts a private underlying message."""
    def __init__(self, code):
        self.code = code if code in ERRORS else 'storage_error'
        super().__init__(ERRORS[self.code])


def _safe(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except WalletError:
            raise
        except Exception:
            raise WalletError('storage_error') from None
    return call


def _network(value):
    if type(value) is not str or value not in ('mainnet', 'testnet'):
        raise WalletError('invalid_input')
    return value


def _sdk():
    try:
        if importlib.metadata.version('bsv-sdk') != SDK_VERSION:
            raise RuntimeError()
        from bsv import PrivateKey, Network
        from bsv.native import native_status
        status = native_status()
        if status.get('available') is not True or status.get('backend') != 'libsecp256k1':
            raise RuntimeError()
        return PrivateKey, Network
    except Exception:
        raise WalletError('sdk_unavailable') from None


def _public(key, network):
    public_key = key.public_key().hex(compressed=True)
    wallet_id = hashlib.sha256(
        b'bsv-hermes-wallet/v1\0' + network.encode('ascii') + b'\0' + bytes.fromhex(public_key)
    ).hexdigest()
    return {'wallet_id': wallet_id, 'network': network, 'address': key.address(compressed=True),
            'public_key_hex': public_key, 'address_type': 'p2pkh', 'compressed': True}


def _directory_check(fd, private=False):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise WalletError('unsafe_storage')
    if private:
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise WalletError('unsafe_storage')
    elif info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise WalletError('unsafe_storage')


class WalletStore:
    """Construct only with an explicit operator-owned absolute directory.

    The constructor is side-effect-free; no defaults or profile/environment reads.
    Current uid and root are trusted. Symlinks, permissive files, hardlinks and
    nonlocal/untrusted writable ancestors are outside the accepted contract.
    """
    def __init__(self, directory):
        if (type(directory) is not str or not 1 < len(directory) <= 4096
                or not directory.startswith('/') or '\x00' in directory
                or any(p in ('', '.', '..') for p in directory.split('/')[1:])):
            raise WalletError('invalid_input')
        self._parts = tuple(directory.split('/')[1:])

    @contextmanager
    def _directory(self, create=False):
        # Hold each opened descriptor before descending; never check then follow
        # an ancestor by pathname. Parent renames cannot redirect leaf access.
        if os.name != 'posix' or not all(hasattr(os, n) for n in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC')):
            raise WalletError('unsafe_storage')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = None
        try:
            fd = os.open('/', flags)
            _directory_check(fd)
            for i, part in enumerate(self._parts):
                final = i == len(self._parts) - 1
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError:
                    if not (create and final):
                        raise WalletError('wallet_missing') from None
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass  # Concurrent creator: re-open and verify.
                    child = os.open(part, flags, dir_fd=fd)
                    os.fsync(fd)
                os.close(fd)
                fd = child
                _directory_check(fd, private=final)
            yield fd
        except WalletError:
            raise
        except OSError:
            raise WalletError('unsafe_storage') from None
        finally:
            if fd is not None:
                os.close(fd)

    @_safe
    def create(self, network='mainnet'):
        network = _network(network)
        PrivateKey, Network = _sdk()
        with self._directory(create=True) as directory:
            try:
                os.stat(FILE_NAME, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise WalletError('wallet_exists')
            key = PrivateKey(network=Network.MAINNET if network == 'mainnet' else Network.TESTNET)
            public = _public(key, network)
            document = {'format': FORMAT, **public, 'private_key_wif': key.wif(compressed=True)}
            payload = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
            temporary = '.creating-' + secrets.token_hex(16)
            file_fd = None
            created = False
            try:
                file_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  0o600, dir_fd=directory)
                created = True
                os.fchmod(file_fd, 0o600)
                with os.fdopen(file_fd, 'wb', closefd=False) as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(file_fd)
                # Atomic publication without replacement: readers never see a
                # partially-written wallet; racing creators cannot clobber it.
                try:
                    os.link(temporary, FILE_NAME, src_dir_fd=directory,
                            dst_dir_fd=directory, follow_symlinks=False)
                except FileExistsError:
                    raise WalletError('wallet_exists') from None
            finally:
                if file_fd is not None:
                    os.close(file_fd)
                if created:
                    os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
            _, verified = self._read(directory)
            if verified != public:
                raise WalletError('wallet_corrupt')
            return verified

    def _read(self, directory):
        """Local-only private read. Never return its first result to a tool."""
        file_fd = None
        try:
            try:
                file_fd = os.open(FILE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                  dir_fd=directory)
            except FileNotFoundError:
                raise WalletError('wallet_missing') from None
            except OSError:
                raise WalletError('unsafe_storage') from None
            before = os.fstat(file_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
                raise WalletError('unsafe_storage')
            if not 0 < before.st_size <= MAX_DOCUMENT:
                raise WalletError('wallet_corrupt')
            chunks, size = [], 0
            while size <= MAX_DOCUMENT:
                chunk = os.read(file_fd, MAX_DOCUMENT + 1 - size)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            after = os.fstat(file_fd)
            if (size != before.st_size or size > MAX_DOCUMENT
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise WalletError('wallet_corrupt')
            data = b''.join(chunks)
        finally:
            if file_fd is not None:
                os.close(file_fd)
        PrivateKey, Network = _sdk()
        try:
            def unique(pairs):
                result = {}
                for name, value in pairs:
                    if name in result:
                        raise ValueError()
                    result[name] = value
                return result
            document = json.loads(data, object_pairs_hook=unique)
            names = {'format', 'network', 'wallet_id', 'address', 'public_key_hex',
                     'address_type', 'compressed', 'private_key_wif'}
            if type(document) is not dict or set(document) != names:
                raise ValueError()
            if any(type(document[n]) is not str for n in names - {'compressed'}):
                raise ValueError()
            if document['format'] != FORMAT or document['compressed'] is not True:
                raise ValueError()
            if document['network'] not in ('mainnet', 'testnet') or len(document['private_key_wif']) != 52:
                raise ValueError()
            key = PrivateKey(document['private_key_wif'])
            if key.network != Network(document['network']) or key.compressed is not True:
                raise ValueError()
            if key.wif(compressed=True) != document['private_key_wif']:
                raise ValueError()
            public = _public(key, document['network'])
            if any(type(document[n]) is not type(v) or document[n] != v for n, v in public.items()):
                raise ValueError()
            return key, public
        except Exception:
            raise WalletError('wallet_corrupt') from None

    @_safe
    def address(self, expected_network=None):
        if expected_network is not None:
            _network(expected_network)
        with self._directory() as directory:
            _, public = self._read(directory)
        if expected_network is not None and expected_network != public['network']:
            raise WalletError('network_mismatch')
        return public

    @_safe
    def network(self):
        public = self.address()
        return {'network': public['network'], 'mutable': False, 'wallet_id': public['wallet_id']}

    @contextmanager
    def signing_key(self, *, expected_network, expected_wallet_id):
        """Privileged in-process seam, NEVER a native handler or authorization.

        The transaction coordinator must enforce human intent, limits and approval
        BEFORE entering. The yielded object implements the pinned SDK PrivateKey
        interface, with redacted repr and no pickle. Never log/export/retain it.
        Python cannot guarantee zeroization; handle invalidation is best-effort.
        """
        handle = None
        try:
            _network(expected_network)
            if (type(expected_wallet_id) is not str or len(expected_wallet_id) != 64
                    or any(c not in '0123456789abcdef' for c in expected_wallet_id)):
                raise WalletError('invalid_input')
            with self._directory() as directory:
                key, public = self._read(directory)
            if public['network'] != expected_network:
                raise WalletError('network_mismatch')
            if public['wallet_id'] != expected_wallet_id:
                raise WalletError('wallet_mismatch')
            PrivateKey, _ = _sdk()
            class LocalSigningKey(PrivateKey):
                def __repr__(self):
                    return '<LocalBSVSigningKey redacted>'
                __str__ = __repr__

                def __reduce_ex__(self, protocol):
                    raise TypeError('Local signing keys cannot be serialized')
            handle = LocalSigningKey(key.serialize(), network=key.network)
            del key
            yield handle
        except WalletError:
            raise
        except Exception:
            raise WalletError('storage_error') from None
        finally:
            if handle is not None:
                # Invalidates this handle; does not promise secure erasure of
                # immutable bytes or SDK/interpreter copies.
                handle._secret = b'\x00' * 32
