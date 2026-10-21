"""Dedicated local BSV single-key wallet; no key export or network clients."""
from .store import WalletError, WalletStore

__all__ = ['WalletError', 'WalletStore']
