#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Independent scripted-peer wire tests for the compiled TLS 2.0 client.

Tests run on loopback with newly generated credentials. They cover record and
message fragmentation, coalescing, authenticated transcript boundaries, replay,
early data, malformed keys and fail-closed application EOF.
"""

import argparse
import asyncio
import itertools
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from tls20_server import crypto as c, messages as m
    from tls20_server.errors import ProtocolError
    from tls20_server.handshake import Wire
    from tls20_server.lab import generate_lab_credentials

    native = str(args.native.resolve())
    credentials, ca = generate_lab_credentials("localhost")
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    positives = {"coalesced", "fragmented", "fragmented-hello", "empty-records",
                 "hrr-p256", "hrr-cookie", "ccs", "padded-record",
                 "legacy-record-version", "client-auth-decline"}
    after_auth = {"unclean-eof", "tampered-application", "replayed-application"}
    cases = list(sorted(positives | after_auth)) + [
        "hello-residue", "finished-residue", "duplicate-extensions", "bad-proof",
        "bad-finished", "wrong-alpn", "early-application", "zero-share",
        "echoed-share", "wrong-version", "oversized-record", "replayed-handshake",
        "hrr-repeated", "hrr-offered-group", "hrr-old-version", "hrr-empty-cookie",
        "client-auth-context", "client-auth-missing-share", "client-auth-short-share",
        "client-auth-duplicate-share", "client-auth-signature-algorithms", "client-auth-mac-scheme",
    ]
    with tempfile.TemporaryDirectory(prefix="httpps-wire-") as temporary:
        root = Path(temporary) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        leaf = Path(temporary) / "leaf.der"
        leaf.write_bytes(credentials.chain_der[0])
        mutation = await asyncio.create_subprocess_exec(
            native, "--cert-mutations", "localhost", str(root), str(leaf),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        output, errors = await mutation.communicate()
        assert mutation.returncode == 0, errors
        print(output.decode().strip())
        modes = ("--get-grease-once",) if args.grease else ("--get", "--get-external")
        for mode, kind in itertools.product(modes, cases):
            requests = []
            finished_seen = []
            handler_errors = []
            finished_handler = asyncio.Event()

            async def peer(reader, writer):
                try:
                    async with asyncio.timeout(5):
                        assert await reader.readexactly(len(c.PREFACE)) == c.PREFACE
                        wire = Wire(reader, writer)
                        ch = await wire.receive_frame(1, boundary=True)
                        hello = m.parse_client_hello(ch[4:])
                        prefix = c.PREFACE
                        def plain(fragment):
                            version = b"\x00\x00" if kind == "legacy-record-version" else b"\x03\x03"
                            return b"\x16" + version + len(fragment).to_bytes(2, "big") + fragment
                        if kind.startswith("hrr-"):
                            cookie_only = kind in ("hrr-cookie", "hrr-empty-cookie")
                            retry = m.server_hello(b"", bytes(32),
                                                   group=29 if kind == "hrr-offered-group" else 23,
                                                   retry=True)
                            if cookie_only:
                                cookie = b"opaque retry cookie" if kind == "hrr-cookie" else b""
                                extension = m.extension(43, b"\x04\x00") + m.extension(
                                    44, len(cookie).to_bytes(2, "big") + cookie)
                                retry = m.frame(2, retry[4:42] + len(extension).to_bytes(2, "big") + extension)
                            if kind == "hrr-old-version":
                                retry = retry.replace(b"\x00\x2b\x00\x02\x04\x00",
                                                      b"\x00\x2b\x00\x02\x03\x04")
                            writer.write(plain(retry))
                            await writer.drain()
                            prefix += b"\xfe\x00\x00\x20" + c.digest(ch) + retry
                            ch = await wire.receive_frame(1, boundary=True)
                            second = m.parse_client_hello(ch[4:])
                            assert second.A == hello.A and second.group == (29 if cookie_only else 23)
                            if cookie_only:
                                assert second.B == hello.B and 44 in second.extensions
                            if kind == "hrr-repeated":
                                writer.write(plain(retry))
                                await writer.drain()
                                await reader.read()
                                return
                            hello = second
                        ephemeral, public = c.traffic_key(hello.group)
                        if kind == "zero-share":
                            public = bytes(32)
                        if kind == "echoed-share":
                            public = hello.A
                        sh = m.server_hello(public, bytes(range(32)), group=hello.group)
                        if kind == "wrong-version":
                            sh = sh[:5] + b"\x02" + sh[6:]
                        if kind == "oversized-record":
                            writer.write(b"\x16\x03\x03\xff\xff")
                            await writer.drain()
                            return
                        if kind == "fragmented-hello":
                            for byte in sh:
                                writer.write(plain(bytes([byte])))
                        else:
                            writer.write(plain(sh + (b"\x00" if kind == "hello-residue" else b"")))
                        if kind == "ccs":
                            writer.write(b"\x14\x03\x03\x00\x01\x01")
                        if kind == "legacy-record-version":
                            writer.write(b"\x14\x00\x00\x00\x01\x01")
                        transcript = prefix + ch + sh
                        root_secret = c.handshake_secret(c.traffic_dh(ephemeral, hello.group, hello.B))
                        chs = c.label_expand(root_secret, "c hs traffic", c.digest(transcript), 32)
                        shs = c.label_expand(root_secret, "s hs traffic", c.digest(transcript), 32)
                        sender, receiver = c.RecordState(shs, "seal"), c.RecordState(chs, "open")
                        ee = m.encrypted_extensions(b"wrong" if kind == "wrong-alpn" else b"http/1.1")
                        cr = b""
                        if kind.startswith("client-auth-"):
                            verifier = c.public_bytes(X25519PrivateKey.generate().public_key())
                            algorithms = b"\xfe\x01" if kind == "client-auth-mac-scheme" else b"\x08\x07"
                            ext = m.extension(50, b"\x00\x02" + algorithms)
                            if kind != "client-auth-missing-share":
                                ext += m.extension(0xff03, verifier[:-1] if kind == "client-auth-short-share" else verifier)
                            if kind == "client-auth-duplicate-share":
                                ext += m.extension(0xff03, verifier)
                            if kind == "client-auth-signature-algorithms":
                                ext += m.extension(13, b"\x00\x02\x08\x07")
                            context = b"\x01x" if kind == "client-auth-context" else b"\x00"
                            cr = m.frame(13, context + len(ext).to_bytes(2, "big") + ext)
                        cert = m.certificate(credentials.chain_der)
                        transcript += ee + cr + cert
                        auth_root = c.extract(c.label_expand(root_secret, "auth salt", c.digest(transcript), 32),
                                              c.dh(credentials.private_key, hello.A))
                        proof = c.server_proof(auth_root, transcript)
                        if kind == "bad-proof":
                            proof = bytes([proof[0] ^ 1]) + proof[1:]
                        cv = m.certificate_verify(proof)
                        transcript += cv
                        sf_value = c.finished(shs, transcript)
                        if kind == "bad-finished":
                            sf_value = bytes([sf_value[0] ^ 1]) + sf_value[1:]
                        sf = m.frame(20, sf_value)
                        flight = ee + cr + cert + cv + sf
                        transcript += sf
                        app_root = c.master_secret(root_secret)
                        client_app = c.label_expand(app_root, "c ap traffic", c.digest(transcript), 32)
                        server_app = c.label_expand(app_root, "s ap traffic", c.digest(transcript), 32)
                        if kind == "finished-residue":
                            flight += b"\x00"
                        if kind == "duplicate-extensions":
                            flight = ee + flight
                        if kind == "early-application":
                            writer.write(sender.seal(b"not authenticated", 23))
                        elif kind == "fragmented":
                            for byte in flight:
                                writer.write(sender.seal(bytes([byte]), 22))
                        elif kind == "replayed-handshake":
                            encrypted = sender.seal(ee, 22)
                            writer.write(encrypted + encrypted)
                        else:
                            writer.write(sender.seal(flight, 22))
                        await writer.drain()
                        if kind == "client-auth-decline":
                            declined = await wire.receive_frame(11, receiver)
                            assert declined == m.frame(11, bytes(4))
                            transcript += declined
                        cf = await wire.receive_frame(20, receiver, boundary=True)
                        assert cf[4:] == c.finished(chs, transcript)
                        finished_seen.append(True)
                        transcript += cf
                        sender = c.RecordState(server_app, "seal")
                        receiver = c.RecordState(client_app, "open")
                        request, message_type = await wire.read_record(receiver)
                        assert message_type == 23 and request.startswith(b"GET / HTTP/1.1\r\n")
                        requests.append(request)
                        if kind == "empty-records":
                            for _ in range(64):
                                writer.write(sender.seal(b"", 23))
                        encrypted = sender.seal(response, 23, padding=150 if kind == "padded-record" else 0)
                        if kind == "tampered-application":
                            encrypted = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
                        writer.write(encrypted)
                        if kind == "replayed-application":
                            writer.write(encrypted)
                        if kind != "unclean-eof":
                            writer.write(sender.seal(b"\x01\x00", 21))
                        await writer.drain()
                except (ProtocolError, ConnectionError, asyncio.IncompleteReadError) as error:
                    if kind in positives:
                        handler_errors.append(f"unexpected peer disconnect: {error}")
                except BaseException as error:
                    handler_errors.append(repr(error))
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass
                    finished_handler.set()

            listener = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                port = listener.sockets[0].getsockname()[1]
                process = await asyncio.create_subprocess_exec(
                    native, mode, "localhost", str(port), str(root),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 10)
                except BaseException:
                    process.kill()
                    await process.wait()
                    raise
                await asyncio.wait_for(finished_handler.wait(), 6)
                assert (process.returncode == 0) == (kind in positives), (mode, kind, output, error, handler_errors)
                assert not handler_errors, (kind, handler_errors)
                if kind in positives:
                    assert output == response, kind
                    assert len(requests) == 1, kind
                elif kind not in after_auth:
                    assert not requests and not finished_seen, kind
            finally:
                listener.close()
                await listener.wait_closed()
        print(f"{len(cases) * len(modes)} native wire cases passed ({', '.join(modes)})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--grease", action="store_true", help="Exercise GREASE and record-fragmented padded ClientHello, including HRR")
    asyncio.run(main(parser.parse_args()))
