import io
from collections import OrderedDict
from typing import Dict, List, Iterable, Generator, Any

import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from assert_certificate.certificate import (read_all_pem,
                                            load_pem_all_certificates)


def trusted_ca() -> Dict[x509.Name, x509.Certificate]:
    "Return indexed trusted certificates"
    return load_pem_all_certificates(certifi.where())


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


def verify_chain(ca: Dict[x509.Name, x509.Certificate],
                 certs: Dict[x509.Name, x509.Certificate]):
    ca = ca.copy()
    if not isinstance(certs, OrderedDict):
        certs = sort_certs(certs)
    for cert in certs.values():
        verify(ca[cert.issuer], cert)
        ca[cert.subject] = cert


def verify(issuer: x509.Certificate, cert: x509.Certificate):
    """
    Verify certificate with its issuer
    """
    h = cert.signature_hash_algorithm
    issuer.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        h
    )

