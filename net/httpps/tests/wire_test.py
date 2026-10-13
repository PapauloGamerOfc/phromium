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
                 "legacy-record-version", "client-auth-decline", "client-auth-unknown",
                 "user-canceled-plain", "user-canceled-handshake", "user-canceled-application",
                 "groups-hint"}
    after_auth = {"unclean-eof", "tampered-application", "replayed-application"}
    cases = list(sorted(positives | after_auth)) + [
        "hello-residue", "finished-residue", "duplicate-extensions", "bad-proof",
        "bad-finished", "wrong-alpn", "early-application", "zero-share",
        "echoed-share", "wrong-version", "wrong-selected-version", "oversized-record", "replayed-handshake",
        "hrr-repeated", "hrr-offered-group", "hrr-old-version", "hrr-wrong-legacy-version", "hrr-empty-cookie",
        "client-auth-context", "client-auth-missing-share", "client-auth-short-share",
        "client-auth-duplicate-share", "client-auth-signature-algorithms", "client-auth-mac-scheme",
    ]
    cases += [f"client-auth-misplaced-{code}" for code in
              (0, 1, 10, 15, 16, 17, 19, 20, 21, 25, 28, 29, 30, 31, 32,
               33, 41, 42, 43, 44, 45, 49, 51, 55, 56, 58, 59, 0xff02)]
    expected_alerts = {"wrong-version": 70, "wrong-selected-version": 47,
                       "hrr-wrong-legacy-version": 70, "hrr-old-version": 47}
    # Algorithm selection is semantic (47), nested framing or a proof with the
    # wrong negotiated hash length is syntax (50), and a bad MAC is crypto (51).
    proof_alerts = {"cv-opposite-role": 47, "cv-unknown-algorithm": 47,
                    "cv-short-proof": 50, "cv-other-hash-proof": 50,
                    "cv-empty-proof": 50, "cv-declared-short": 50,
                    "cv-truncated-algorithm": 50, "bad-proof": 51}
    cases += [case for case in proof_alerts if case not in cases]
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
            observed_alerts = []
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
                        async def check_version_alert():
                            alert = await reader.readexactly(7)
                            assert alert == bytes([21, 3, 3, 0, 2, 2, expected_alerts[kind]]), alert
                            observed_alerts.append(alert[-1])
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
                            if kind == "hrr-wrong-legacy-version":
                                retry = retry[:4] + b"\x03\x04" + retry[6:]
                            writer.write(plain(retry))
                            await writer.drain()
                            if kind in expected_alerts:
                                await check_version_alert()
                                return
                            prefix += b"\xfe\x00\x00\x20" + c.digest(ch) + retry
                            ch = await wire.receive_frame(1, boundary=True)
                            second = m.parse_client_hello(ch[4:])
                            assert second.A == hello.A and second.group == (29 if cookie_only else 23)
                            if cookie_only:
                                assert second.B == hello.B and 44 in second.extensions
                            if kind == "hrr-repeated":
                                writer.write(plain(retry))
                                await writer.drain()
                                alert = await reader.readexactly(7)
                                assert alert == bytes([21, 3, 3, 0, 2, 2, 10]), alert
                                observed_alerts.append(10)
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
                        if kind == "wrong-selected-version":
                            sh = sh.replace(b"\x00\x2b\x00\x02\x04\x00",
                                            b"\x00\x2b\x00\x02\x03\x04")
                        if kind == "oversized-record":
                            writer.write(b"\x16\x03\x03\xff\xff")
                            await writer.drain()
                            return
                        if kind == "user-canceled-plain":
                            writer.write(b"\x15\x03\x03\x00\x02\x01\x5a")
                        if kind == "fragmented-hello":
                            for byte in sh:
                                writer.write(plain(bytes([byte])))
                        else:
                            writer.write(plain(sh + (b"\x00" if kind == "hello-residue" else b"")))
                        if kind in expected_alerts:
                            await writer.drain()
                            await check_version_alert()
                            return
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
                        if kind == "groups-hint":
                            value = ee[6:] + m.extension(10, b"\x00\x04\x00\x1d\x00\x17")
                            ee = m.frame(8, len(value).to_bytes(2, "big") + value)
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
                            if kind.startswith("client-auth-misplaced-"):
                                ext += m.extension(int(kind.rsplit("-", 1)[1]), b"")
                            if kind == "client-auth-unknown":
                                ext += m.extension(0xbeef, b"opaque future offer")
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
                        if kind.startswith("cv-"):
                            body = cv[4:]
                            if kind == "cv-opposite-role":
                                body = b"\xfe\x01" + body[2:]
                            elif kind == "cv-unknown-algorithm":
                                body = b"\x08\x07" + body[2:]
                            elif kind == "cv-declared-short":
                                body = body[:2] + b"\x00\x1f" + proof
                            elif kind == "cv-truncated-algorithm":
                                body = b"\xfe"
                            else:
                                changed = (proof[:-1] if kind == "cv-short-proof" else
                                           proof + bytes(16) if kind == "cv-other-hash-proof" else b"")
                                body = body[:2] + len(changed).to_bytes(2, "big") + changed
                            # Deliberately bypass the server's now-strict frame
                            # builder: the client must diagnose these wire bytes.
                            cv = b"\x0f" + len(body).to_bytes(3, "big") + body
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
                        if kind in proof_alerts:
                            # Finish external certificate validation in its own
                            # record, then reject CV with no later unread flight
                            # that could turn close into a reset hiding the alert.
                            writer.write(sender.seal(ee + cr + cert, 22))
                            writer.write(sender.seal(cv, 22))
                        elif kind == "early-application":
                            writer.write(sender.seal(b"not authenticated", 23))
                        elif kind == "fragmented":
                            for byte in flight:
                                writer.write(sender.seal(bytes([byte]), 22))
                        elif kind == "replayed-handshake":
                            encrypted = sender.seal(ee, 22)
                            writer.write(encrypted + encrypted)
                        else:
                            if kind == "user-canceled-handshake":
                                writer.write(sender.seal(b"\x01\x5a", 21))
                            writer.write(sender.seal(flight, 22))
                        await writer.drain()
                        if kind in proof_alerts:
                            alert, content_type = await wire.read_record(receiver)
                            assert content_type == 21 and alert == bytes((2, proof_alerts[kind])), (kind, content_type, alert)
                            observed_alerts.append(alert[1])
                            return
                        if kind in ("client-auth-decline", "client-auth-unknown"):
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
                        if kind == "user-canceled-application":
                            writer.write(sender.seal(b"\x01\x5a", 21))
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
                if kind in expected_alerts:
                    assert observed_alerts == [expected_alerts[kind]], (kind, observed_alerts)
                if kind in proof_alerts:
                    assert observed_alerts == [proof_alerts[kind]], (kind, observed_alerts)
                if kind == "hrr-repeated":
                    assert observed_alerts == [10], (kind, observed_alerts)
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
