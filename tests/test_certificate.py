import pytest

from assert_certificate.pool import (load_pem_all_certificates, trusted_ca,
                                     verify_chain, sort_certs)


@pytest.fixture
def certificate():
    return open('wwwgooglecom.crt', 'rb').read()


def test_certificate(certificate):
    ca = trusted_ca()
    google = load_pem_all_certificates('wwwgooglecom.crt')
    verify_chain(ca, google)


def test_sort(certificate):
    google = sort_certs(load_pem_all_certificates('wwwgooglecom.crt'))
    assert list(google.values())[0].subject.rdns[0].rfc4514_string() == \
        'OU=GlobalSign Root CA - R2'
