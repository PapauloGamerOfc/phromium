#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Native wire checked against tls20-spec helpers, not the Python server engine.

Three real connections cover fresh server MAC authentication, PSK resumption
with P-256 HelloRetryRequest and its binder, and an accepted 0-RTT request.
The only tls20-server import generates temporary certificates; wire codecs,
transcript construction, KDF, exporter, AES-GCM and state transitions below
do not use the server's implementation. This is not a security proof.
"""

import argparse
import asyncio
import hashlib
import hmac
import os
from pathlib import Path
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def vec(data, width=2):
    return len(data).to_bytes(width, "big") + data


def frame(kind, body):
    return bytes([kind]) + vec(body, 3)


def extension(kind, data):
    return kind.to_bytes(2, "big") + vec(data)


def ext_values(hello):
    data, result = hello[47:], {}
    while data:
        kind, length = int.from_bytes(data[:2], "big"), int.from_bytes(data[2:4], "big")
        assert length <= len(data) - 4 and kind not in result
        result[kind], data = data[4:4 + length], data[4 + length:]
    assert 13 not in result and result[43] == b"\x02\x04\x00"
    assert 50 in result and len(result[0xff02]) == 32
    return result


async def main(args):
    sys.path.insert(0, str(args.spec_source.resolve() / "tools"))
    import tls20_components as spec
    sys.path.insert(0, str(args.server_source.resolve()))
    from tls20_server.lab import generate_lab_credentials

    H = lambda data: hashlib.sha256(data).digest()
    X = lambda salt, ikm: spec.hkdf_extract("sha256", salt, ikm)
    L = lambda key, label, context=b"", length=32: spec.expand_label("sha256", key, label, context, length)
    D = lambda key, label: spec.derive_empty_secret("sha256", key, label)
    F = lambda key, transcript: hmac.digest(L(key, b"finished"), H(transcript), "sha256")

    class Cipher:
        def __init__(self, secret):
            self.secret, self.sequence = secret, 0
            self.aead = AESGCM(L(secret, b"key", length=16))
            self.iv = L(secret, b"iv", length=12)

        def nonce(self):
            nonce = (int.from_bytes(self.iv, "big") ^ self.sequence).to_bytes(12, "big")
            self.sequence += 1
            return nonce

        def seal(self, data, kind):
            header = b"\x17\x03\x03" + (len(data) + 17).to_bytes(2, "big")
            return header + self.aead.encrypt(self.nonce(), data + bytes([kind]), header)

        def open(self, record):
            plaintext = self.aead.decrypt(self.nonce(), record[5:], record[:5]).rstrip(b"\x00")
            assert plaintext
            return plaintext[-1], plaintext[:-1]

    async def record(reader):
        header = await reader.readexactly(5)
        assert header[1:3] == b"\x03\x03"
        return header + await reader.readexactly(int.from_bytes(header[3:5], "big"))

    def plain(message):
        return b"\x16\x03\x03" + vec(message)

    credentials, ca = generate_lab_credentials("localhost")
    tickets, observations, errors, handlers = {}, [], [], set()
    retry_random = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

    async def peer(reader, writer):
        task = asyncio.current_task()
        handlers.add(task)
        number = len(observations)
        observations.append(None)
        try:
            async with asyncio.timeout(8):
                assert await reader.readexactly(18) == spec.BOOTSTRAP
                first = (await record(reader))[5:]
                hello, fields = first, ext_values(first)
                psk = bytes(32)
                if number:
                    identity_length = int.from_bytes(fields[41][2:4], "big")
                    identity = fields[41][4:4 + identity_length]
                    psk = tickets[identity]
                    binder_key = D(X(bytes(32), psk), b"res binder")
                    digest = spec.binder_transcript_hash("sha256", hello[:-35])
                    assert hello[-32:] == hmac.digest(L(binder_key, b"finished"), digest, "sha256")
                prefix = spec.BOOTSTRAP
                if number == 1:
                    hrr_ext = extension(43, b"\x04\x00") + extension(51, b"\x00\x17")
                    retry = frame(2, b"\x03\x03" + retry_random + b"\x00\x13\x01\x00" + vec(hrr_ext))
                    writer.write(plain(retry))
                    await writer.drain()
                    hello = (await record(reader))[5:]
                    second = ext_values(hello)
                    assert second[0xff02] == fields[0xff02] and second[51][2:4] == b"\x00\x17"
                    fields = second
                    digest = spec.binder_transcript_hash("sha256", hello[:-35],
                        selected_hash="sha256", client_hello1=first, hello_retry_request=retry)
                    assert hello[-32:] == hmac.digest(L(binder_key, b"finished"), digest, "sha256")
                    prefix += spec.message_hash("sha256", first) + retry
                    assert H(prefix + hello) == spec.retry_transcript_hash(
                        "sha256", "sha256", first, retry, [hello])
                    key = ec.generate_private_key(ec.SECP256R1())
                    public = key.public_key().public_bytes(serialization.Encoding.X962,
                                                           serialization.PublicFormat.UncompressedPoint)
                    shared = key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(
                        ec.SECP256R1(), fields[51][6:]))
                    group = b"\x00\x17"
                else:
                    key = x25519.X25519PrivateKey.generate()
                    public = key.public_key().public_bytes_raw()
                    shared = key.exchange(x25519.X25519PublicKey.from_public_bytes(fields[51][6:]))
                    group = b"\x00\x1d"
                sh_ext = extension(43, b"\x04\x00") + extension(51, group + vec(public))
                if number:
                    sh_ext += extension(41, b"\x00\x00")
                sh = frame(2, b"\x03\x03" + os.urandom(32) + b"\x00\x13\x01\x00" + vec(sh_ext))
                transcript = prefix + hello + sh
                early = X(bytes(32), psk)
                handshake = X(D(early, b"derived"), shared)
                chs, shs = L(handshake, b"c hs traffic", H(transcript)), L(handshake, b"s hs traffic", H(transcript))
                sender, receiver = Cipher(shs), Cipher(chs)
                accepted = number == 2
                ee = extension(0, b"") + extension(16, vec(vec(b"http/1.1", 1)))
                if accepted:
                    assert fields[42] == b""
                    ee += extension(42, b"")
                flight = frame(8, vec(ee))
                transcript += flight
                if not number:
                    entries = b"".join(vec(cert, 3) + b"\x00\x00" for cert in credentials.chain_der)
                    cert = frame(11, b"\x00" + vec(entries, 3))
                    transcript += cert
                    proof = spec.make_server_certificate_verify("sha256", handshake,
                        credentials.private_key, fields[0xff02], H(transcript))
                    flight += cert + proof
                    transcript += proof
                finished = frame(20, F(shs, transcript))
                transcript += finished
                writer.write(plain(sh) + sender.seal(flight + finished, 22))
                await writer.drain()
                master = X(D(handshake, b"derived"), bytes(32))
                cap, sap = L(master, b"c ap traffic", H(transcript)), L(master, b"s ap traffic", H(transcript))
                exporter = L(master, b"exp master", H(transcript))
                request = b""
                if accepted:
                    early_cipher = Cipher(L(early, b"c e traffic", H(spec.BOOTSTRAP + hello)))
                    kind, request = early_cipher.open(await record(reader))
                    assert kind == 23 and request.startswith(b"GET /")
                    kind, end = early_cipher.open(await record(reader))
                    assert kind == 22 and end == b"\x05\x00\x00\x00"
                    transcript += end
                kind, cf = receiver.open(await record(reader))
                assert kind == 22 and cf == frame(20, F(chs, transcript))
                transcript += cf
                resumption = L(master, b"res master", H(transcript))
                sender, receiver = Cipher(sap), Cipher(cap)
                identity, nonce = os.urandom(32), os.urandom(8)
                tickets[identity] = L(resumption, b"resumption", nonce)
                # A well-formed unknown extension must not kill ticket ingestion.
                ticket_ext = extension(42, (16384).to_bytes(4, "big")) + extension(0xface, b"ignored")
                nst = frame(4, (3600).to_bytes(4, "big") + bytes(4) + vec(nonce, 1)
                            + vec(identity) + vec(ticket_ext))
                writer.write(sender.seal(nst, 22))
                if not accepted:
                    kind, update = receiver.open(await record(reader))
                    assert kind == 22 and update == frame(24, b"\x01")
                    receiver = Cipher(L(cap, b"traffic upd"))
                    writer.write(sender.seal(frame(24, b"\x00"), 22))
                    sender = Cipher(L(sap, b"traffic upd"))
                    kind, request = receiver.open(await record(reader))
                    assert kind == 23
                    expected = spec.export_keying_material("sha256", exporter,
                        b"test exporter", b"\x01\x02\x03", 64).hex().encode()
                    assert b"X-Test-Exporter: " + expected + b"\r\n" in request
                writer.write(sender.seal(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", 23)
                             + sender.seal(b"\x01\x00", 21))
                await writer.drain()
                observations[number] = (bool(number), accepted)
        except BaseException as error:
            errors.append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()
            handlers.discard(task)

    with tempfile.TemporaryDirectory(prefix="httpps-spec-oracle-") as directory:
        root = Path(directory) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        try:
            process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-resume",
                "localhost", str(server.sockets[0].getsockname()[1]), str(root),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                output, error = await asyncio.wait_for(process.communicate(), 25)
            except BaseException:
                process.kill()
                await process.wait()
                raise
            if handlers:
                await asyncio.gather(*handlers)
            assert process.returncode == 0 and not errors, (error, errors)
            assert output.count(b"HTTP/1.1 200 OK") == 3
            assert observations == [(False, False), (True, False), (True, True)]
        finally:
            server.close()
            await server.wait_closed()
    print("Current-spec oracle passed: MAC, KDF, HRR, binders, exporters, tickets, 0-RTT, KeyUpdate")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--spec-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
