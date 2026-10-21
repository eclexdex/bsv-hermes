"""Fixed public BSV endpoints. No user-configurable hosts or cross-provider failover."""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Endpoint:
    provider: str
    network: str
    protocol: str
    base: str

    @property
    def submit_url(self):
        return self.base + ('/tx/raw' if self.protocol == 'woc' else '/tx')

    def status_url(self, txid):
        return self.base + ('/tx/hash/' if self.protocol == 'woc' else '/tx/') + txid

    def raw_url(self, txid):
        if self.protocol != 'woc':
            raise ValueError('provider has no supported raw readback')
        return self.base + '/tx/' + txid + '/hex'

    @property
    def policy_url(self):
        return self.base + ('/chain/info' if self.protocol == 'woc' else '/policy')


PROVIDERS = ('whatsonchain', 'gorillapool-arc', 'arcade-us', 'arcade-eu',
             'arcade-ap', 'gorillapool-arcade')


def endpoint(provider, network):
    if type(provider) is not str or provider not in PROVIDERS or network not in ('main', 'test'):
        raise ValueError('unsupported provider or network')
    if provider == 'whatsonchain':
        return Endpoint(provider, network, 'woc', 'https://api.whatsonchain.com/v1/bsv/' + network)
    if provider == 'gorillapool-arc':
        host = 'arc.gorillapool.io' if network == 'main' else 'testnet.arc.gorillapool.io'
        return Endpoint(provider, network, 'arc', 'https://' + host + '/v1')
    if network != 'main':
        raise ValueError('listed Arcade public endpoints are mainnet only')
    host = {'arcade-us': 'arcade-us-1.bsvblockchain.tech',
            'arcade-eu': 'arcade-eu-1.bsvblockchain.tech',
            'arcade-ap': 'arcade-ap-1.bsvblockchain.tech',
            'gorillapool-arcade': 'arcade.gorillapool.io'}[provider]
    return Endpoint(provider, network, 'arcade', 'https://' + host)


def allowed_url(method, url):
    if type(url) is not str or method not in ('GET', 'POST'):
        return False
    for provider in PROVIDERS:
        for network in ('main', 'test'):
            try:
                ep = endpoint(provider, network)
            except ValueError:
                continue
            if method == 'POST' and url == ep.submit_url:
                return True
            if method == 'GET':
                if url == ep.policy_url:
                    return True
                pattern = re.escape(ep.status_url('')) + r'[0-9a-f]{64}'
                if re.fullmatch(pattern, url):
                    return True
                if ep.protocol == 'woc' and re.fullmatch(re.escape(ep.base) + r'/tx/[0-9a-f]{64}/hex', url):
                    return True
    return False
