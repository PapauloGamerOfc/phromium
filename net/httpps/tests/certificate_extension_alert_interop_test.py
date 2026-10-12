#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""CertificateEntry offer/context alerts after decompression and cache expansion."""
import argparse
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from interop_runtime import run, start_process


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from tls20_server import credential_cache, handshake, messages as m
    from tls20_server.errors import PeerClosed
    from tls20_server.pki import Credentials
    from tls20_server.transparency import _der, precertificate_tbs

    now = datetime.now(timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), x25519.X25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CE alert fixture")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=7))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
          .sign(ca_key, hashes.SHA256()))
    leaf_builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.KeyUsage(False, False, False, False, True, False, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False))
    plain_leaf = leaf_builder.sign(ca_key, hashes.SHA256())
    log_key = ec.generate_private_key(ec.SECP256R1())
    timestamp = int(now.timestamp() * 1000).to_bytes(8, "big")
    issuer_spki = ca_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    entry = b"\x01\x01" + timestamp + m._vec(hashlib.sha256(issuer_spki).digest(), 1)
    entry += m._vec(plain_leaf.tbs_certificate_bytes, 3) + b"\0\0"
    sct = b"\x01\x03" + m._vec(bytes.fromhex("2b06010401"), 1) + timestamp + b"\0\0"
    sct += m._vec(log_key.sign(entry, ec.ECDSA(hashes.SHA256())), 2)
    leaf = leaf_builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.101.75"),
        _der(4, m._vec(m._vec(sct, 2), 2))), False).sign(ca_key, hashes.SHA256())
    assert precertificate_tbs(leaf, version=2) == plain_leaf.tbs_certificate_bytes
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    credentials = Credentials([leaf_der], key)
    response = (ocsp.OCSPResponseBuilder().add_response(leaf, ca, hashes.SHA256(), ocsp.OCSPCertStatus.GOOD,
                now-timedelta(minutes=1), now+timedelta(hours=1), None, None)
                .responder_id(ocsp.OCSPResponderEncoding.HASH, ca).sign(ca_key, hashes.SHA256()))
    status = b"\x01" + m._vec(response.public_bytes(serialization.Encoding.DER), 3)
    cases = [("valid", b"", "none", 0),
             ("offered-ocsp", m.extension(5, status), "ocsp", 0),
             ("truncated", b"\xfa\xfa\x00", "none", 50),
             # Well-framed repetitions violate the extension invariant before
             # offer processing, including compressed/cached reconstructions.
             ("duplicate", m.extension(0xfafa, b"") * 2, "none", 47)]
    cases += [(f"ocsp-size-{index}", m.extension(5, value), "ocsp", 50)
              for index, value in enumerate((b"", b"\x01", b"\x01\0\0", b"\x01\0\0\0",
                                             b"\x01\0\0\x02\0", b"\x01\0\0\x01\0\0"))]
    cases += [("ocsp-invalid-enum", m.extension(5, b"\x02\0\0\x01\0"), "ocsp", 47)]
    cases += [(f"sct-size-{index}", m.extension(18, value), "sct", 50)
              for index, value in enumerate((b"", b"\0", b"\0\0", b"\0\x01\0", b"\0\x02\0\0",
                                             b"\0\x03\0\x02\x01", b"\0\x03\0\x01\x01\0"))]
    # Optional TLS evidence may be empty or unknown; the real signed embedded
    # SCT, never these bytes, must satisfy the configured one-log policy.
    cases += [("ct-empty", m.extension(52, b""), "ct", 0),
              ("ct-unknown", m.extension(52, b"\0\x04\0\x02\xff\xff"), "ct", 0)]
    cases += [(f"ct-size-{index}", m.extension(52, value), "ct", 50) for index, value in enumerate(
        (b"\0", b"\0\0", b"\0\x02\0\0", b"\0\x03\0\x01\xff",
         b"\0\x04\0\x03\xff\xff", b"\0\x04\0\x02\xff\xff\0"))]
    cases += [(f"unoffered-{code}", m.extension(code, status if code == 5 else b""), "none", 10 if code == 34 else 110)
              for code in (0xfafa, 5, 18, 34, 52, 59)]
    cases += [(f"misplaced-{code}", m.extension(code, b""), "none", 47)
              for code in (0, 1, 2, 3, 4, 10, 13, 15, 16, 17, 19, 20, 21, 25, 27, 28,
                           29, 30, 31, 32, 33, 41, 42, 43, 44, 45, 47, 48, 49, 50, 51,
                           55, 56, 58, 0xff02, 0xff03, 0xff04)]
    checks = 0
    original, parse = handshake._credential_frame, m.parse_client_hello
    with tempfile.TemporaryDirectory(prefix="httpps-ce-alert-") as folder:
        root, certificate, log = Path(folder)/"root.der", Path(folder)/"leaf.der", Path(folder)/"log.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        certificate.write_bytes(leaf_der)
        log.write_bytes(log_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        for algorithm in (0, 1, 2, 3):
            for cached in (False, True):
                for label, block, offered, expected in cases:
                    name = (algorithm, cached, label)
                    errors, requests, hellos, generated, handlers, cleanup_errors = [], [], [], [], set(), []
                    completed = asyncio.Event()

                    def parse_hello(*a, **kw):
                        hello = parse(*a, **kw)
                        hellos.append(hello)
                        assert (5 in hello.extensions) == (offered in ("ocsp", "ct"))
                        assert (18 in hello.extensions) == (offered == "sct")
                        assert (52 in hello.extensions) == (offered == "ct")
                        assert (25 in hello.extensions) == cached
                        assert (27 in hello.extensions) == bool(algorithm)
                        assert not set((0xfafa, 34, 59)).intersection(hello.extensions)
                        return hello

                    def credential_frame(*a, **kw):
                        frame = original(*a, **kw)
                        assert kw.get("cached", False) == cached
                        assert frame[0] == (25 if algorithm else 253 if cached else 11)
                        generated.append(frame)
                        # Preserve credential bytes and the selected encoding;
                        # only replace the current CertificateEntry metadata.
                        body = (credential_cache.cached_certificate_body([leaf_der], [block]) if cached else
                                b"\x00" + m._vec(m._vec(leaf_der, 3) + m._vec(block, 2), 3))
                        if algorithm:
                            body = credential_cache.compress_certificate(body, algorithm)
                        return m.frame(frame[0], body)

                    async def peer(reader, writer):
                        task = asyncio.current_task()
                        handlers.add(task)
                        channel = None
                        try:
                            async with asyncio.timeout(8):
                                channel = await handshake.server_handshake(reader, writer, credentials, "localhost")
                                request = await channel.recv()
                                assert request.startswith(b"GET / HTTP/1.1\r\n"), request
                                requests.append(request)
                                await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                                await channel.close()
                        except Exception as error:
                            errors.append(error)
                        finally:
                            if channel is not None: channel.abort()
                            writer.close()
                            try:
                                await asyncio.wait_for(writer.wait_closed(), 2)
                            except TimeoutError as error:
                                cleanup_errors.append(error)
                                writer.transport.abort()
                            except OSError:
                                pass
                            finally:
                                handlers.discard(task)
                                completed.set()

                    listener = await asyncio.start_server(peer, "127.0.0.1", 0)
                    process = None
                    try:
                        with patch.object(handshake, "_credential_frame", credential_frame), patch.object(m, "parse_client_hello", parse_hello):
                            command = [str(args.native.resolve()), "--certificate-alert", "localhost",
                                str(listener.sockets[0].getsockname()[1]), str(root), str(certificate), str(algorithm),
                                str(int(cached)), offered, str(expected)]
                            if offered == "ct": command.append(str(log))
                            process = await start_process(*command,
                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                            stdout, stderr = await asyncio.wait_for(process.communicate(), 12)
                            await asyncio.wait_for(completed.wait(), 10)
                            if handlers: await asyncio.wait_for(asyncio.gather(*handlers), 10)
                        assert not cleanup_errors, (name, cleanup_errors)
                        assert process.returncode == 0 and len(hellos) == len(generated) == 1, (name, stdout, stderr, errors)
                        if not expected:
                            assert not errors and len(requests) == 1 and stdout.endswith(b"\r\n\r\nOK"), (name, errors, stdout)
                        else:
                            assert f"fatal alert {expected} generated".encode() in stdout, (name, stdout)
                            assert not requests and len(errors) == 1 and isinstance(errors[0], PeerClosed), (name, errors)
                            assert errors[0].alert == expected, (name, errors)
                        checks += 1
                    finally:
                        if process is not None and process.returncode is None:
                            process.kill()
                            await process.wait()
                        listener.close()
                        for task in tuple(handlers): task.cancel()
                        if handlers: await asyncio.wait_for(asyncio.gather(*tuple(handlers), return_exceptions=True), 4)
                        await listener.wait_closed()
                print("PASS CertificateEntry matrix", algorithm, "cached", cached, flush=True)
    print(f"{checks} CertificateEntry alert cases passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    run(main(parser.parse_args()))
