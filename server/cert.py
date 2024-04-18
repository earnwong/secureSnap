from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, BestAvailableEncryption, NoEncryption
import datetime


def generate_keys_and_certificate():
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Claremont"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureSnap"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureSnap"),
    ])
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # The certificate will be valid for 1 year
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("mycompany.com")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Save the private key to a file
    with open("server/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))

    # Save the certificate to a file
    with open("server/certificate.pem", "wb") as f:
        f.write(certificate.public_bytes(Encoding.PEM))

    print("Keys and certificate generated and saved to disk.")

if __name__ == "__main__":
    generate_keys_and_certificate()
