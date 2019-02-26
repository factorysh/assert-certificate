from typing import List

from cryptography.x509.oid import NameOID
from cryptography import x509


def subject_common_name(certificate: x509.Certificate) -> str:
    return certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME)[0].value


def dnsname(certificate: x509.Certificate) -> List[str]:
    return certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
