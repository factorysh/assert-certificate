import io

import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def load_pem_all_certificates(path):
    p = dict()
    buff = io.BytesIO()
    cert = False
    for line in open(path, 'rb'):
        if line.startswith(b'-----BEGIN CERTIFICATE-----'):
            cert = True
        if cert:
            buff.write(line)
        if line.startswith(b'-----END CERTIFICATE-----'):
            cert = False
            buff.seek(0)
            c = x509.load_pem_x509_certificate(buff.read(), default_backend())
            buff = io.BytesIO()
            p[c.subject] = c
    return p


def trusted_ca():
    "Pool of CA"
    return load_pem_all_certificates(certifi.where())


def verify_chain(ca, certs):
    ca = ca.copy()
    certs_keys = list(certs.keys())
    for a in range(len(certs)):
        for cert_key in certs_keys:
            print(cert_key)
            if cert_key in ca: # Aldreay trusted
                print('already trusted')
                certs_keys.remove(cert_key)
                break
            cert = certs[cert_key]
            print('issuer', cert.issuer)
            if cert.issuer in ca:
                verify(ca[cert.issuer], cert)
                print('verified', cert)
                ca[cert_key] = cert
                certs_keys.remove(cert_key)
                break
            print('unknown issuer', cert.issuer, cert)
        if len(certs_keys) == 0:
            return True
    return False


def verify(ca, cert):
    h = cert.signature_hash_algorithm
    ca.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        h
    )

