"""v1 synchronous ports. Adapters must enforce their own authority boundaries.

All hex is lowercase. All amounts are integer satoshis, never float/bool.
No port is permitted to sign and broadcast as a combined operation.
"""
from dataclasses import dataclass
from typing import Protocol, Tuple


@dataclass(frozen=True)
class Prevout:
    txid: str
    vout: int
    satoshis: int
    locking_script_hex: str

    @property
    def outpoint(self):
        return '%s:%s' % (self.txid, self.vout)


@dataclass(frozen=True)
class FundingRequest:
    workflow_id: str
    network: str
    commitment_script_hex: str
    wallet_ref: str
    key_ref: str
    max_spend_sats: int
    excluded_outpoints: Tuple[str, ...]


@dataclass(frozen=True)
class FundingSelection:
    network: str
    inputs: Tuple[Prevout, ...]
    change_script_hex: str
    fee_sats: int


@dataclass(frozen=True)
class BuildRequest:
    workflow_id: str
    network: str
    commitment_script_hex: str
    inputs: Tuple[Prevout, ...]
    change_script_hex: str
    fee_sats: int


@dataclass(frozen=True)
class SignRequest:
    workflow_id: str
    network: str
    unsigned_tx_hex: str
    inputs: Tuple[Prevout, ...]
    key_ref: str
    max_spend_sats: int
    intent_digest: str


@dataclass(frozen=True)
class AuthorizationRequest:
    stage: str
    workflow_id: str
    network: str
    approval_ref: str
    wallet_ref: str
    key_ref: str
    max_spend_sats: int
    intent_digest: str
    transaction_hex: str
    inputs: Tuple[Prevout, ...]
    fee_sats: int


@dataclass(frozen=True)
class SubmissionRequest:
    workflow_id: str
    network: str
    signed_tx_hex: str
    txid: str
    # Same signed transaction always has the same idempotency key.
    idempotency_key: str


@dataclass(frozen=True)
class SubmissionResult:
    network: str
    txid: str
    status: str  # accepted | already_known | rejected | unknown


@dataclass(frozen=True)
class LookupResult:
    network: str
    txid: str
    status: str  # mempool | confirmed | absent | unknown


class Authorization(Protocol):
    def authorize(self, request: AuthorizationRequest) -> bool: ...


class Funding(Protocol):
    def select(self, request: FundingRequest) -> FundingSelection: ...


class Builder(Protocol):
    def build(self, request: BuildRequest) -> str: ...


class LocalSigner(Protocol):
    local: bool
    def sign(self, request: SignRequest) -> str: ...


class Broadcaster(Protocol):
    def submit(self, request: SubmissionRequest) -> SubmissionResult: ...
    def lookup(self, txid: str) -> LookupResult: ...


@dataclass(frozen=True)
class Ports:
    authorization: Authorization
    funding: Funding
    builder: Builder
    signer: LocalSigner
    broadcaster: Broadcaster
