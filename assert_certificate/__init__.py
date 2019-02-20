from x5092json import x509parser


def parse_certificate(data):
    certificate = x509parser.READERS['PEM'](data)
    return x509parser.parse(certificate)


def subject_common_name(certificate):
    for s in certificate['subject']:
        if s['oid']['name'] == 'commonName':
            return s['value']
    return None
