from typing import List
from cryptography import x509

from assert_certificate import dnsname


def assert_www(certificate: x509.Certificate):
    """
    each DNSname has its www counterpart, or a star counterpart
    """
    _assert_www(dnsname(certificate))


def _assert_www(names: List[str]):
    naked = set()
    www = set()
    for name in names:
        if name.startswith('www.'):
            www.add(name[4:])
        elif name.startswith('*.'):
            www.add(name[2:])
        elif len(name.split('.')) > 2:
            continue
        else:
            naked.add(name)
    assert www == naked
