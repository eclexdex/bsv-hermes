"""Read-only, public BSV funding observations. No custody or broadcast API."""
from dataclasses import dataclass
import hashlib
import re

MAX_MONEY = 2_100_000_000_000_000
BASE = "https://api.whatsonchain.com/v1/bsv"
NETWORKS = {"mainnet": "main", "testnet": "test"}
MESSAGES = {
    "INVALID_TARGET": "Expected a valid public BSV P2PKH address for the selected network.",
    "INVALID_POLICY": "Funding policy is outside the supported bounds.",
    "PROVIDER_RESPONSE": "Provider returned an invalid or inconsistent response.",
    "PROVIDER_HTTP": "Public provider request failed.",
    "RATE_LIMITED": "Public provider rate limit reached; retry later.",
    "TIMEOUT": "Public provider request exceeded the time budget.",
    "NETWORK_ERROR": "Public provider was not reachable over verified HTTPS.",
    "RESOURCE_LIMIT": "Funding discovery exceeded its bounded resource policy.",
    "SNAPSHOT_CHANGED": "UTXO observations changed during discovery; obtain a new snapshot.",
    "CONFLICT": "Provider returned conflicting transaction or outpoint observations.",
}


class FundingError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(MESSAGES[code])


def _fail(code="PROVIDER_RESPONSE"):
    raise FundingError(code) from None


def _sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


@dataclass(frozen=True)
class PublicTarget:
    network: str
    address: str
    locking_script_hex: str = ""

    def __post_init__(self):
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        if (type(self.network) is not str or self.network not in NETWORKS
                or type(self.address) is not str or not 26 <= len(self.address) <= 35
                or any(c not in alphabet for c in self.address)):
            _fail("INVALID_TARGET")
        number = 0
        for char in self.address:
            number = number * 58 + alphabet.index(char)
        decoded = b"\0" * (len(self.address) - len(self.address.lstrip("1")))
        decoded += number.to_bytes((number.bit_length() + 7) // 8, "big")
        version = 0 if self.network == "mainnet" else 111
        if (len(decoded) != 25 or decoded[0] != version
                or _sha256d(decoded[:21])[:4] != decoded[21:]):
            _fail("INVALID_TARGET")
        script = "76a914" + decoded[1:21].hex() + "88ac"
        if self.locking_script_hex not in ("", script):
            _fail("INVALID_TARGET")
        object.__setattr__(self, "locking_script_hex", script)

    @classmethod
    def from_wallet_metadata(cls, public):
        allowed = {"wallet_id", "network", "address", "public_key_hex", "address_type", "compressed"}
        if type(public) is not dict or set(public) != allowed:
            _fail("INVALID_TARGET")
        if public["address_type"] != "p2pkh" or public["compressed"] is not True:
            _fail("INVALID_TARGET")
        key = public["public_key_hex"]
        if type(key) is not str or re.fullmatch(r"0[23][0-9a-f]{64}", key) is None:
            _fail("INVALID_TARGET")
        target = cls(public["network"], public["address"])
        key_bytes = bytes.fromhex(key)
        key_hash = hashlib.new("ripemd160", hashlib.sha256(key_bytes).digest()).hexdigest()
        if target.locking_script_hex != "76a914" + key_hash + "88ac":
            _fail("INVALID_TARGET")
        wallet_id = hashlib.sha256(b"bsv-hermes-wallet/v1\0" + target.network.encode("ascii")
                                  + b"\0" + key_bytes).hexdigest()
        if public["wallet_id"] != wallet_id:
            _fail("INVALID_TARGET")
        return target

    @property
    def script_hash(self):
        # WoC uses the reversed SHA256 digest, as its published fixture shows.
        return hashlib.sha256(bytes.fromhex(self.locking_script_hex)).digest()[::-1].hex()


from .client import FundingClient, HTTPReply, Limits  # noqa: E402

__all__ = ["PublicTarget", "FundingClient", "FundingError", "HTTPReply", "Limits"]
