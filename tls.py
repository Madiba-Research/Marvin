import ipaddress
import os
import logging
import OpenSSL
from cryptography import x509
from cryptography.x509 import ExtendedKeyUsageOID
from cryptography.x509 import NameOID
import datetime
import mitmproxy
from mitmproxy import ctx
from mitmproxy.certs import Cert

from cryptography.hazmat.primitives import hashes

# CA_EXPIRY = datetime.timedelta(days=10 * 365)
# CERT_EXPIRY = datetime.timedelta(days=365)



def monkey_dummy_cert(privkey, cacert, commonname, sans,organization):
    CERT_TYPE = os.environ['CERT_TYPE']
    # 1 = normal
    # 2 = self sign
    # 3 = expired
    # 4 = domain mismatched
    
    builder = x509.CertificateBuilder()
    # builder._version = x509.Version.v1
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
    )
    builder = builder.public_key(cacert.public_key())

    
    if CERT_TYPE == "3":
        builder = builder.not_valid_before(datetime.datetime.fromisoformat('2011-11-01'))
        builder = builder.not_valid_after(datetime.datetime.fromisoformat('2011-11-04'))
    else:
        now = datetime.datetime.now()
        builder = builder.not_valid_before(now - datetime.timedelta(days=20))
        builder = builder.not_valid_after(now + datetime.timedelta(days=2))
    
    subject = []
    is_valid_commonname = commonname is not None and len(commonname) < 64
    if is_valid_commonname:
        assert commonname is not None
        subject.append(x509.NameAttribute(NameOID.COMMON_NAME, commonname))
    if organization is not None:
        assert organization is not None
        subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if CERT_TYPE == "2":
        builder = builder.issuer_name(x509.Name(subject))
    else:
        builder = builder.issuer_name(cacert.subject)
        
    builder = builder.subject_name(x509.Name(subject))
    builder = builder.serial_number(x509.random_serial_number())

    ss: list[x509.GeneralName] = []
    for x in sans:
        try:
            ip = ipaddress.ip_address(x)
        except ValueError:
            ss.append(x509.DNSName(x))
        else:
            ss.append(x509.IPAddress(ip))
    # RFC 5280 §4.2.1.6: subjectAltName is critical if subject is empty.
    builder = builder.add_extension(
        x509.SubjectAlternativeName(ss), critical=not is_valid_commonname
    )
    cert = builder.sign(private_key=privkey, algorithm=hashes.SHA256())  # type: ignore

    logging.info("ssss")
    return Cert(cert)

def client_connected(layer):
    mitmproxy.certs.dummy_cert = monkey_dummy_cert

# addons = [CheckSSLPinning()]

