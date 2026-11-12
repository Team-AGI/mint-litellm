"""시험용 자체 서명 인증서를 만든다. 이름은 tls-front 하나만 담고, 같은 파일이 신뢰 기준(CA)도 된다."""

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out = Path(sys.argv[1])
if (out / "tls.crt").exists() and (out / "tls.key").exists():
    sys.exit(0)  # 이미 만든 인증서를 쓰고 있는 문과 신뢰 기준이 어긋나지 않게 한다
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls-front")])
now = datetime.datetime.now(datetime.UTC)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=5))
    .not_valid_after(now + datetime.timedelta(days=2))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("tls-front")]), critical=False)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    .sign(key, hashes.SHA256())
)
out.mkdir(parents=True, exist_ok=True)
(out / "tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(out / "tls.key").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
(out / "tls.key").chmod(0o644)
