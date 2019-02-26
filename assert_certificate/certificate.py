from typing import Dict, List, Iterable, Generator, Any
import io
from collections import OrderedDict

from cryptography import x509
from cryptography.hazmat.backends import default_backend


def read_all_pem(data: Iterable[bytes]) -> Generator[bytes, None, None]:
    """
    data is something readable, like open(path, 'rb')
    yield on bytes per certificate
    """
    buff = io.BytesIO()
    cert = False
    for line in data:
        if line.startswith(b'-----BEGIN CERTIFICATE-----'):
            cert = True
        if cert:
            buff.write(line)
        if line.startswith(b'-----END CERTIFICATE-----'):
            cert = False
            buff.seek(0)
            yield buff.read()
            buff = io.BytesIO()


def load_pem_all_certificates(path: str) -> Dict[x509.Name, x509.Certificate]:
    """
    Read all pem certificate at path
    Return a dict subject => certificate
    """
    p = dict()
    for pem in read_all_pem(open(path, 'rb')):
        c = x509.load_pem_x509_certificate(pem, default_backend())
        p[c.subject] = c
    return p


def load_pem_last_certificate(path: str) -> x509.Certificate:
    all = sort_certs(load_pem_all_certificates(path))
    return list(all.values())[-1]


def sort_certs(certs: Dict[x509.Name, x509.Certificate]) -> \
    Dict[x509.Name, x509.Certificate]:
    unsorted = list(certs.keys()).copy()
    keys = [unsorted.pop()]
    while len(keys) < len(certs):
        something_happened = False
        for k in unsorted:
            v = certs[k]
            first, last = certs[keys[0]], certs[keys[-1]]
            if v.issuer == last.subject:
                keys.append(k)
                something_happened = True
            elif v.subject == first.issuer:
                keys.insert(0, k)
                something_happened = True
            if something_happened:
                unsorted.remove(k)
                break
        assert something_happened, "Chain is broken"
    return OrderedDict((k, certs[k]) for k in keys)

