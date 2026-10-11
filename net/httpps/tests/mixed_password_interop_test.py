#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Mixed PAKE/ordinary selection uses one connection and explicit offered modes."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from tls20_server import pake_handshake
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.pki import Credentials
    from tls20_server.pake import PasswordAccount, PasswordServer, password_base
    from tls20_server.pake_native import PakeProvider
    from tls20_server.openssl_provider import OpenSSLProvider
    from tls20_server.tickets import TicketStore
    credentials, root = generate_lab_credentials("localhost")
    provider = OpenSSLProvider(args.provider.resolve())
    primitive = PakeProvider(provider, args.helper.resolve())
    account = PasswordAccount(b"alice", password_base("alice", "correct horse", None), None)
    policy = PasswordServer("localhost", primitive, [account])
    count = 0
    cases = [("ordinary", 0x1301, True), ("ordinary", 0x1302, True),
             ("password", 0xc0b0, True), ("password", 0xc0b1, True),
             ("bad-password", 0xc0b0, False), ("bad-mac", 0x1301, False),
             ("password-only", 0x1301, False)]
    with tempfile.TemporaryDirectory(prefix="httpps-mixed-password-") as directory:
        root_file = Path(directory)/"root.der"
        root_file.write_bytes(root.public_bytes(serialization.Encoding.DER))
        for mode, suite, positive in cases:
            seen, errors, tasks, accepted = [], [], set(), []
            store = TicketStore()
            selected = Credentials(credentials.chain_der, x25519.X25519PrivateKey.generate()) if mode == "bad-mac" else credentials
            async def peer(reader, writer):
                accepted.append(True)
                task = asyncio.current_task(); tasks.add(task)
                early_bytes = []
                async def early(data): early_bytes.append(data)
                try:
                    async with asyncio.timeout(15):
                        if mode in ("password", "bad-password"):
                            channel = await pake_handshake.server(reader, writer, policy,
                                cipher_suites=(suite,), ticket_store=store, max_early_data=16384, on_early_data=early)
                        else:
                            channel = await server_handshake(reader, writer, selected, "localhost",
                                cipher_suites=(suite,), ticket_store=store, max_early_data=16384, on_early_data=early)
                        data = b"".join(early_bytes) or await channel.recv()
                        assert data.startswith(b"GET / HTTP/1.1\r\n")
                        if mode == "password": assert channel.pake_identity == b"alice"
                        seen.append((channel.resumed, channel.early_data_accepted))
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        await channel.close()
                except BaseException as error: errors.append(repr(error))
                finally:
                    writer.close()
                    try: await writer.wait_closed()
                    except (ConnectionError, OSError): pass
                    tasks.discard(task)
            listener = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()),
                    "--get-password" if mode == "password-only" else "--get-password-mixed",
                    "localhost", str(listener.sockets[0].getsockname()[1]), str(root_file),
                    str(args.provider.resolve()), str(args.helper.resolve()),
                    "c0b1" if suite in (0x1302, 0xc0b1) else "c0b0", "23",
                    "wrong password" if mode == "bad-password" else "correct horse", "resume",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try: output, error = await asyncio.wait_for(process.communicate(), 40)
                except BaseException:
                    if process.returncode is None: process.kill()
                    await process.wait()
                    raise
                if tasks: await asyncio.gather(*tasks)
                if positive:
                    assert process.returncode == 0 and not errors, (mode, suite, output, error, errors)
                    assert seen == [(False, False), (True, False), (True, True)], seen
                    assert len(accepted) == 3
                    count += 3
                else:
                    assert process.returncode != 0 and not seen and len(accepted) == 1, (mode, output, error, errors, seen)
                    assert not any("TypeError" in item or "AttributeError" in item for item in errors), errors
                    count += 1
            finally:
                listener.close(); await listener.wait_closed()
                for task in tuple(tasks): task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
    provider.close()
    print(f"{count} mixed PAKE/ordinary connections passed: SHA256/SHA384 selection, resumption/0RTT, failed password/MAC and no retry downgrade")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("native", "server-source", "provider", "helper"):
        parser.add_argument("--"+name, type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
