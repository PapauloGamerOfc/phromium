#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Independent certificate-scheme negotiation fixtures; not a path validator."""
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.x509.oid import NameOID


def main(args):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "scheme fixture")])
    subject = x25519.X25519PrivateKey.generate().public_key()
    issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(subject).serial_number(1).not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(False, None), True))
    fixtures = []
    for index, digest in enumerate((hashes.SHA256(), hashes.SHA384(), hashes.SHA512())):
        pss = padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size)
        fixtures.append((builder.sign(issuer, digest, rsa_padding=pss), 0x0804 + index))
        fixtures.append((builder.sign(issuer, digest), (0x0401, 0x0501, 0x0601)[index]))
        bad_salt = padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size - 1)
        fixtures.append((builder.sign(issuer, digest, rsa_padding=bad_salt), 0))
        bad_mgf = padding.PSS(mgf=padding.MGF1(hashes.SHA384() if index == 0 else hashes.SHA256()), salt_length=digest.digest_size)
        fixtures.append((builder.sign(issuer, digest, rsa_padding=bad_mgf), 0))
        curve = (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1())[index]
        fixtures.append((builder.sign(ec.generate_private_key(curve), digest), (0x0403, 0x0503, 0x0603)[index]))
    fixtures.append((builder.sign(ed25519.Ed25519PrivateKey.generate(), None), 0x0807))
    codes = (0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0807, 0xfe00, 0xfe01)
    checks = 0
    with tempfile.TemporaryDirectory(prefix="httpps-cert-alg-") as directory:
        certificate = Path(directory) / "leaf.der"
        for cert, expected in fixtures:
            certificate.write_bytes(cert.public_bytes(serialization.Encoding.DER))
            for offered in codes:
                result = subprocess.run([str(args.native.resolve()), "--certificate-algorithms", f"{offered:04x}", str(certificate)], capture_output=True)
                assert (result.returncode == 0) == (offered == expected), (expected, offered, result.stderr)
                checks += 1
    print(f"{checks} native certificate negotiation checks passed: SHA2 RSA-PSS parameters, PKCS1, ECDSA, Ed25519 and role separation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    main(parser.parse_args())
