import io

import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def read_all_pem(data):
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


def load_pem_all_certificates(path):
    """
    Read all pem certificate at path
    Return a dict subject => certificate
    """
    p = dict()
    for pem in read_all_pem(open(path, 'rb')):
        c = x509.load_pem_x509_certificate(pem, default_backend())
        p[c.subject] = c
    return p


def trusted_ca():
    "Return indexed trusted certificates"
    return load_pem_all_certificates(certifi.where())


def verify_chain(ca, certs):
    ca = ca.copy()
    certs_keys = list(certs.keys())
    while len(certs_keys) > 0:
        something_happened = False
        for cert_key in certs_keys:
            if cert_key in ca: # Aldreay trusted
                certs_keys.remove(cert_key)
                something_happened = True
                break
            cert = certs[cert_key]
            if cert.issuer in ca:
                verify(ca[cert.issuer], cert)
                ca[cert_key] = cert
                certs_keys.remove(cert_key)
                something_happened = True
                break
        if not something_happened:
            raise InvalidSignature()


def verify(issuer, cert):
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

