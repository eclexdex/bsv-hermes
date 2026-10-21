"""One bounded request, no administration or dynamic factories in the protocol."""
import json
from pathlib import Path
import re
import sys

# Supports the extracted native directory plugin and a normal installed wheel.
# This path is fixed by this shipped resource, never by the request/environment.
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bsv_hermes import boundary
from bsv_hermes.mainnet.native import OPERATIONS, schema, error
from bsv_hermes.mainnet.runtime import Runtime, MainnetError
from bsv_hermes.mainnet.funding import FundingError
from bsv_hermes.mainnet.wallet import WalletError
from bsv_hermes.mainnet.signer import SignerError
from bsv_hermes.mainnet.spend_policy import PolicyError
from bsv_hermes.mainnet.signer.storage import strict_json


def safe_error(exc):
    code = 'mainnet_operation_failed'
    if isinstance(exc, (MainnetError, FundingError, WalletError, SignerError)):
        code = exc.code
    elif isinstance(exc, PolicyError):
        code = str(exc)
    if type(code) is not str or re.fullmatch('[a-zA-Z0-9_]{1,64}', code) is None:
        code = 'mainnet_operation_failed'
    return error(code)


def dispatch(directory, request, runtime_factory=Runtime):
    try:
        boundary.budget(request)
        if type(request) is not dict or set(request) != {'tool', 'arguments'} or request['tool'] not in OPERATIONS:
            return error('invalid_input')
        name, arguments = request['tool'], request['arguments']
        boundary.validate(arguments, schema(name)['parameters'])
    except (ValueError, TypeError, KeyError, RecursionError):
        return error('invalid_input')
    try:
        runtime = runtime_factory(directory)
        value = getattr(runtime, OPERATIONS[name][0])(**arguments)
        return {'ok': True, 'result': value}
    except Exception as exc:
        return safe_error(exc)


def main(runtime_factory=Runtime):
    try:
        raw = sys.stdin.buffer.read(32769)
        if len(raw) > 32768 or len(sys.argv) != 2:
            raise ValueError()
        result = dispatch(sys.argv[1], strict_json(raw), runtime_factory)
    except Exception:
        result = error('invalid_input')
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()
