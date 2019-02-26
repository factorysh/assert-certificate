import pytest
from assert_certificate.asserts import _assert_www


def test_assert():
    _assert_www(['pim.example.com'])
    _assert_www(['www.example.com', 'example.com'])
    with pytest.raises(AssertionError):
        _assert_www(['*.example.com'])
    with pytest.raises(AssertionError):
        _assert_www(['example.com'])
    _assert_www(['example.com', '*.example.com'])
