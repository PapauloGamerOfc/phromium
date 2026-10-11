#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Exercise the compiled C++ engine against the independent Python server.

Usage: python interop_test.py --native path/to/httpps_native_test[.exe]
         --server-source path/to/tls20-server
All listeners and generated credentials are temporary and loopback-only.
"""

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from tls20_server.config import Config, Endpoint
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.server import start_server

    native = str(args.native.resolve())
    checks = 0

    async def run(*arguments, success=True):
        nonlocal checks
        process = await asyncio.create_subprocess_exec(
            native, *map(str, arguments), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        try:
            output, error = await asyncio.wait_for(process.communicate(), 15)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        assert (process.returncode == 0) == success, (arguments, process.returncode, error)
        checks += 1
        return output

    with tempfile.TemporaryDirectory(prefix="httpps-native-") as temporary:
        folder = Path(temporary)
        credentials, ca = generate_lab_credentials("localhost")
        _, wrong_ca = generate_lab_credentials("localhost")
        root = folder / "root.der"
        wrong_root = folder / "wrong-root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        wrong_root.write_bytes(wrong_ca.public_bytes(serialization.Encoding.DER))
        leaf = folder / "leaf.der"
        leaf.write_bytes(credentials.chain_der[0])
        await run()
        await run("--verify", "localhost", root, leaf)
        await run("--verify", "wrong.invalid", root, leaf, success=False)
        await run("--verify", "localhost", wrong_root, leaf, success=False)
        await run("--verify", "localhost", root, leaf, leaf, success=False)
        mutation = folder / "mutated.der"
        for offset in (0, 1, 5, 12, 32, 100, len(credentials.chain_der[0]) - 1):
            data = bytearray(credentials.chain_der[0])
            data[offset] ^= 1
            mutation.write_bytes(data)
            await run("--verify", "localhost", root, mutation, success=False)
        mutation.write_bytes(credentials.chain_der[0] + b"\x00")
        await run("--verify", "localhost", root, mutation, success=False)

        # Second mandatory issuer algorithm, including negative leaf profiles.
        p256 = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Native test CA")])
        issuer = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                  .public_key(p256.public_key()).serial_number(1)
                  .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                  .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                  .sign(p256, hashes.SHA256()))
        root_p256 = folder / "p256-root.der"
        root_p256.write_bytes(issuer.public_bytes(serialization.Encoding.DER))
        static = x25519.X25519PrivateKey.generate()
        for kind in ("valid", "expired", "signature-usage", "missing-eku", "policy"):
            builder = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                       .public_key(static.public_key()).serial_number(2)
                       .not_valid_before(now - timedelta(days=2))
                       .not_valid_after(now + timedelta(days=-1 if kind == "expired" else 1))
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                       .add_extension(x509.KeyUsage(kind == "signature-usage", False, False, False, True, False, False, False, False), True)
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False))
            if kind != "missing-eku":
                builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            if kind == "policy":
                builder = builder.add_extension(x509.NameConstraints([x509.DNSName("localhost")], None), False)
            cert = builder.sign(p256, hashes.SHA256())
            mutation.write_bytes(cert.public_bytes(serialization.Encoding.DER))
            await run("--verify", "localhost", root_p256, mutation, success=kind == "valid")

        # Match the reference validator's constrained certificate profile, not
        # just the generic X.509 library's default acceptance policy.
        from tls20_server.errors import ProtocolError
        from tls20_server.pki import _children, _element, validate_chain

        def profile_leaf(*, subject=ca_name, san="localhost", critical_san=False,
                         aki=None):
            builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                       .public_key(static.public_key()).serial_number(2)
                       .not_valid_before(now - timedelta(days=1))
                       .not_valid_after(now + timedelta(days=1))
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                       .add_extension(x509.KeyUsage(False, False, False, False, True,
                                                    False, False, False, False), True)
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical_san)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False))
            if aki is not None:
                builder = builder.add_extension(aki, False)
            return builder.sign(p256, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

        async def profile_check(der, hostname="localhost", *, success=False,
                                root_cert=issuer):
            root_p256.write_bytes(root_cert.public_bytes(serialization.Encoding.DER))
            mutation.write_bytes(der)
            try:
                validate_chain([der], [root_cert], hostname, "lab-offline")
                reference_ok = True
            except ProtocolError:
                reference_ok = False
            assert reference_ok == success, "unexpected reference PKI result"
            await run("--verify", hostname, root_p256, mutation, success=success)

        await profile_check(profile_leaf(), success=True)
        await profile_check(profile_leaf(subject=x509.Name([])))
        await profile_check(profile_leaf(subject=x509.Name([]), critical_san=True), success=True)
        await profile_check(profile_leaf(san="*.example.com"), "www.example.com", success=True)
        await profile_check(profile_leaf(san="*.example.com"), "xn--bcher-kva.example.com")
        await profile_check(profile_leaf(san="xn--bcher-kva.example.com"),
                            "xn--bcher-kva.example.com", success=True)
        await profile_check(profile_leaf(aki=x509.AuthorityKeyIdentifier(
            None, [x509.DirectoryName(ca_name)], issuer.serial_number)))
        await profile_check(profile_leaf(aki=x509.AuthorityKeyIdentifier(b"missing issuer SKI", None, None)))

        ski = x509.SubjectKeyIdentifier.from_public_key(p256.public_key())
        root_with_ski = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                         .public_key(p256.public_key()).serial_number(3)
                         .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                         .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                         .add_extension(x509.KeyUsage(False, False, False, False, False,
                                                      True, True, False, False), True)
                         .add_extension(ski, False).sign(p256, hashes.SHA256()))
        await profile_check(profile_leaf(aki=x509.AuthorityKeyIdentifier(ski.digest, None, None)),
                            success=True, root_cert=root_with_ski)
        await profile_check(profile_leaf(aki=x509.AuthorityKeyIdentifier(b"wrong", None, None)),
                            root_cert=root_with_ski)

        def tlv(tag, content):
            size = len(content)
            length = (bytes([size]) if size < 128 else
                      bytes([128 + (size.bit_length() + 7) // 8]) +
                      size.to_bytes((size.bit_length() + 7) // 8, "big"))
            return bytes([tag]) + length + content

        # CertificateBuilder prevents invalid serials. Rebuild and correctly
        # re-sign the TBSCertificate so rejection cannot be blamed on a bad sig.
        source = profile_leaf()
        outer = _children(_element(source)[1])
        tbs_parts = _children(outer[0][1])
        for serial_bytes, valid in ((b"\x00", False), (b"\x80", False),
                                    (b"\x00\x80" + b"\x00" * 19, False),
                                    (b"\x7f" + b"\xff" * 19, True)):
            updated = list(entry[2] for entry in tbs_parts)
            updated[1] = tlv(2, serial_bytes)
            tbs = tlv(0x30, b"".join(updated))
            signature = p256.sign(tbs, ec.ECDSA(hashes.SHA256()))
            await profile_check(tlv(0x30, tbs + outer[1][2] + tlv(3, b"\x00" + signature)),
                                success=valid)

        # A nonzero unused-bit count is outside TBSCertificate. Preserve every
        # signed octet and signature octet while changing only that count.
        for _ in range(128):
            source = profile_leaf()
            outer = _children(_element(source)[1])
            if outer[2][1][-1] & 1 == 0:
                altered = tlv(0x30, outer[0][2] + outer[1][2] +
                              tlv(3, b"\x01" + outer[2][1][1:]))
                await profile_check(altered)
                break
        else:
            raise AssertionError("could not create octet-alignment fixture")

        hits = 0
        early_hits = 0
        body = b"native HTTPPS interop\n" * 2048
        async def backend(reader, writer):
            nonlocal hits, early_hits
            try:
                request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                assert request.startswith(b"GET / HTTP/1.1\r\n")
                hits += 1
                early_hits += b"\r\nEarly-Data: 1\r\n" in request
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        http = await asyncio.start_server(backend, "127.0.0.1", 0)
        port = http.sockets[0].getsockname()[1]
        proxy = await start_server(Config(listen=Endpoint("127.0.0.1", 0),
                                         upstream=Endpoint("127.0.0.1", port),
                                         upstream_early_data_aware=True,
                                         early_data_paths=("/",)), credentials)
        secure_port = proxy.server.sockets[0].getsockname()[1]
        try:
            responses = await asyncio.gather(*(
                run("--get", "localhost", secure_port, root) for _ in range(8)))
            assert all(response.endswith(body) for response in responses)
            assert hits == 8
            await run("--get", "localhost", secure_port, wrong_root, success=False)
            await run("--get", "wrong.invalid", secure_port, root, success=False)
            assert hits == 8, "backend opened before native client authentication"
            response = await run("--get-external", "localhost", secure_port, root)
            assert response.endswith(body)
            assert hits == 9
            await run("--get-external", "localhost", secure_port, wrong_root, success=False)
            await run("--get-external", "wrong.invalid", secure_port, root, success=False)
            assert hits == 9, "external rejection must prevent application traffic"
            response = await run("--get-resume", "localhost", secure_port, root)
            assert response.count(body) == 3
            assert hits == 12 and early_hits == 1, (hits, early_hits)
        finally:
            await proxy.close()
            http.close()
            await http.wait_closed()
    print(f"{checks} native checks passed, including eight concurrent encrypted HTTP exchanges")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
