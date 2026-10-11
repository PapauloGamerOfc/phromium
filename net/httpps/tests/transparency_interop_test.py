#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""CT v2 real signed evidence at the native engine's trust/0-RTT boundary."""
import argparse
import asyncio
from dataclasses import replace
import hashlib
from pathlib import Path
import sys
import tempfile
import time


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.tickets import TicketStore

    def vec(value, width=2):
        return len(value).to_bytes(width, "big") + value

    credentials, ca = generate_lab_credentials("localhost")
    cert = x509.load_der_x509_certificate(credentials.chain_der[0])
    log_key = ec.generate_private_key(ec.SECP256R1())
    issuer = ca.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time() * 1000)
    entry = b"\x01\x00" + now.to_bytes(8, "big") + vec(hashlib.sha256(issuer).digest(), 1)
    entry += vec(cert.tbs_certificate_bytes, 3) + b"\x00\x00"
    signature = log_key.sign(entry, ec.ECDSA(hashes.SHA256()))
    sct = b"\x01\x02" + vec(bytes.fromhex("2b06010401"), 1) + now.to_bytes(8, "big") + b"\x00\x00" + vec(signature)
    evidence = vec(vec(sct))
    with tempfile.TemporaryDirectory(prefix="httpps-ct-") as directory:
        root, log = Path(directory) / "root.der", Path(directory) / "log.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        log.write_bytes(log_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        for case in ("valid", "tampered", "missing", "untrusted-log"):
            selected = evidence if case != "tampered" else evidence[:-1] + bytes((evidence[-1] ^ 1,))
            metadata = (((52, selected),),) + ((),) * (len(credentials.chain_der) - 1)
            selected_credentials = credentials if case == "missing" else replace(credentials, entry_extensions=metadata)
            if case == "untrusted-log":
                other = ec.generate_private_key(ec.SECP256R1())
                log.write_bytes(other.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            store, errors, observed, handlers = TicketStore(), [], [], set()

            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                early_data = []
                async def early(data):
                    early_data.append(data)
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, selected_credentials, "localhost",
                            ticket_store=store, max_early_data=16384, on_early_data=early)
                        request = b"".join(early_data) or await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1\r\n")
                        observed.append((channel.resumed, channel.early_data_accepted))
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        await channel.close()
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (ConnectionError, OSError):
                        pass
                    handlers.discard(task)

            server = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-ct",
                    "localhost", str(server.sockets[0].getsockname()[1]), str(root), str(log),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 25)
                except BaseException:
                    process.kill()
                    await process.wait()
                    raise
                if handlers:
                    await asyncio.gather(*handlers)
                if case == "valid":
                    assert process.returncode == 0 and not errors, (output, error, errors)
                    assert observed == [(False, False), (True, False), (True, True)], observed
                else:
                    assert process.returncode != 0 and not observed, (case, error, observed)
            finally:
                server.close()
                await server.wait_closed()
    print("6 native CT v2 connections passed: fresh, resume, early, tampering, required evidence and explicit logs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
