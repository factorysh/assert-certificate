from x5092json import x509parser


def parse_certificate(data):
    certificate = x509parser.READERS['PEM'](data)
    return x509parser.parse(certificate)


def get(certificate, key1, key2):
    for a in certificate[key1]:
        if a['oid']['name'] == key2:
            return a['value']
    return None


def subject_common_name(certificate):
    return get(certificate, 'subject', 'commonName')


def dnsname(certificate):
    altnames = get(certificate, 'extensions', 'subjectAltName')
    if altnames is None:
        return None
    return [ n['dnsname_value'] for n in altnames]
