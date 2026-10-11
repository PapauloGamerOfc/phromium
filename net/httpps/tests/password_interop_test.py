#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Native RFC8492 EC/FFC exchanges, successor PSK, KU, exporters and rejection."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from tls20_server import pake_handshake
    from tls20_server.pake import PasswordAccount, PasswordServer, password_base
    from tls20_server.pake_native import PakeProvider
    from tls20_server.openssl_provider import OpenSSLProvider
    from tls20_server.tickets import TicketStore
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    provider = OpenSSLProvider(args.provider.resolve())
    primitive = PakeProvider(provider, args.helper.resolve())
    count = 0
    with tempfile.TemporaryDirectory(prefix="httpps-password-") as directory:
        root = Path(directory) / "unused.der"
        root.write_bytes(b"unused: password mode does not assert CA trust")
        cases = [(suite, group, salt, "correct horse")
                 for suite in range(0xc0b0, 0xc0b4) for group in (23, 24, 25)
                 for salt in (None, bytes(range(32)))]
        cases += [(0xc0b0, group, None, "correct horse") for group in range(256, 261)]
        cases += [(0xc0b0, 23, salt, "wrong password") for salt in (None, bytes(32))]
        cases = [(*value, None) for value in cases]
        cases += [(0xc0b1, 24, bytes(range(32)), "correct horse", curve)
                  for curve in (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1())]
        for suite, group, salt, password, curve in cases:
            account = PasswordAccount(b"alice", password_base("alice", "correct horse", salt), salt)
            protection = ec.generate_private_key(curve) if curve else None
            policy = PasswordServer("localhost", primitive, [account], protection_key=protection)
            extra = []
            if protection:
                spki = Path(directory) / "protection.der"
                spki.write_bytes(protection.public_key().public_bytes(serialization.Encoding.DER,
                                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
                extra.append(str(spki))
            store, errors, seen, tasks = TicketStore(), [], [], set()

            async def peer(reader, writer):
                task = asyncio.current_task()
                tasks.add(task)
                early_bytes = []
                async def early(data):
                    early_bytes.append(data)
                try:
                    async with asyncio.timeout(35):
                        channel = await pake_handshake.server(reader, writer, policy, timeout=30,
                            cipher_suites=(suite,), ticket_store=store, max_early_data=16384,
                            on_early_data=early)
                        request = b"".join(early_bytes) or await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1\r\n")
                        if b"X-Test-Exporter:" in request:
                            expected = request.split(b"X-Test-Exporter: ")[1].split(b"\r\n")[0]
                            assert channel.exporter("test exporter", b"\x01\x02\x03", 64).hex().encode() == expected
                        assert channel.pake_identity == b"alice"
                        seen.append((channel.resumed, channel.early_data_accepted))
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        await channel.close()
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, ConnectionError):
                        pass
                    tasks.discard(task)

            listener = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-password",
                    "localhost", str(listener.sockets[0].getsockname()[1]), str(root),
                    str(args.provider.resolve()), str(args.helper.resolve()), f"{suite:x}", str(group),
                    password, "resume", *extra, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 110)
                except BaseException:
                    if process.returncode is None:
                        process.kill()
                    await process.wait()
                    raise
                if tasks:
                    await asyncio.gather(*tasks)
                if password == "correct horse":
                    assert process.returncode == 0 and not errors, (suite, group, salt, output, error, errors)
                    assert seen == [(False, False), (True, False), (True, True)], seen
                    count += 3
                else:
                    assert process.returncode != 0 and not seen, (output, error, errors)
                    count += 1
                print(f"PWD {suite:04x}, group {group}, salted={salt is not None}, positive={password == 'correct horse'} passed", flush=True)
            finally:
                listener.close()
                await listener.wait_closed()
    provider.close()
    print(f"{count} native password connections passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("native", "server-source", "provider", "helper"):
        parser.add_argument("--" + flag, type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
