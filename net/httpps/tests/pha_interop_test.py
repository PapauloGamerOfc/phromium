#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Native initial/PHA credential and current-epoch MAC interoperability."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tests.test_client_auth import client_credentials

    credentials, ca = generate_lab_credentials("localhost")
    credential = client_credentials(ed25519.Ed25519PrivateKey.generate())
    with tempfile.TemporaryDirectory(prefix="httpps-pha-") as directory:
        root, leaf, key = (Path(directory) / name for name in ("root.der", "client.der", "client.raw"))
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        leaf.write_bytes(credential.chain_der[0])
        key.write_bytes(credential.private_key.private_bytes_raw())
        for selected, algorithm in ((selected, algorithm) for selected in (False, True)
                                    for algorithm in (0, 1, 2, 3)):
            errors, identities, handlers, caches = [], [], set(), []

            def validate(chain):
                assert chain == credential.chain_der
                return credential.private_key.public_key()

            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, credentials, "localhost",
                                                         client_auth_validator=validate,
                                                         certificate_compression=(algorithm,) if algorithm else ())
                        caches.append(tuple(channel.cache_types))
                        request = await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1\r\n")
                        first = await channel.request_client_auth(required=selected)
                        await channel.key_update(request_peer=True)
                        second = await channel.request_client_auth(required=selected)
                        drive = asyncio.create_task(channel.recv())
                        identities.extend(await asyncio.gather(first, second))
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                        writer.write(channel.sender.seal(b"\x01\x00", 21))
                        await writer.drain()
                        assert await drive is None
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    await writer.wait_closed()
                    handlers.discard(task)

            server = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                command = [str(args.native.resolve()), "--get-cache" if args.cache else "--get-compression" if algorithm else "--get-pha", "localhost",
                           str(server.sockets[0].getsockname()[1]), str(root)]
                if algorithm or args.cache:
                    command.append(str(algorithm))
                process = await asyncio.create_subprocess_exec(*command,
                    str(leaf) if selected else "-", str(key) if selected else "-",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                output, error = await asyncio.wait_for(process.communicate(), 15)
                if handlers:
                    await asyncio.gather(*handlers)
                assert process.returncode == 0, (selected, algorithm, error, errors)
                assert not errors, errors
                assert b"HTTP/1.1 200 OK" in output
                assert identities == [tuple(credential.chain_der) if selected else None] * (6 if args.cache else 2), identities
                if args.cache:
                    assert caches == [(), (1, 2), (1, 2)], caches
            finally:
                server.close()
                await server.wait_closed()
    print("8 native PHA cases: identity/refusal, concurrent contexts, interleaved KeyUpdate, all 3 compression codecs passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--cache", action="store_true")
    asyncio.run(main(parser.parse_args()))
