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
    google = load_pem_all_certificates('wwwgooglecom.crt')
    print(sort_certs(google))
