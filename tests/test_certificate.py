import pytest

from assert_certificate import parse_certificate


@pytest.fixture
def certificate():
    return open('wwwgooglecom.crt', 'rb').read()


def test_certificate(certificate):
    c = parse_certificate(certificate)
    print(c)
