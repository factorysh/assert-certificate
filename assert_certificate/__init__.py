from x5092json import x509parser


def parse_certificate(data):
    certificate = x509parser.READERS['PEM'](data)
    return x509parser.parse(certificate)
