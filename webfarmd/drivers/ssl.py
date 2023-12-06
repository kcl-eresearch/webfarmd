#
# Webfarmd
#
# Author: Skylar Kelty
#

import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


class SSLDriver:
    @staticmethod
    def self_sign_ssl(ssl_name):
        """
        Generate a self signed cert.
        """
        one_day = datetime.timedelta(1, 0, 0)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ssl_name)])
        )
        builder = builder.issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ssl_name)])
        )
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(
            datetime.datetime.today() + (one_day * 365 * 5)
        )
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(ssl_name), x509.DNSName("*.%s" % ssl_name)]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )

        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        cert = certificate.public_bytes(serialization.Encoding.PEM)
        privatekey = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return ("", cert.decode("ascii"), privatekey.decode("ascii"))
