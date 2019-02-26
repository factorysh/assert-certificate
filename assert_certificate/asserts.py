from cryptography import x509

from assert_certificate import dnsname


def assert_www(certificate: x509.Certificate):
    """
    each DNSname has its www counterpart, or a star counterpart
    """
    naked = set()
    www = set()
    for name in dnsname(certificate):
        if name.startswith('www.'):
            www.add(name[4:])
        elif name.startswith('*.'):
            www.add(name[2:])
        else:
            naked.add(name)
    assert www == naked
