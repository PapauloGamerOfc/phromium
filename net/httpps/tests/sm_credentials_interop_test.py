#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Independent OpenSSL-signed SM2 certificates/grants across native records."""
import argparse
import asyncio
from dataclasses import replace
import os
from pathlib import Path
import sys


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    os.environ["TLS20_TEST_OPENSSL"] = str(args.provider.resolve())
    os.environ["TLS20_TEST_OPENSSL_CLI"] = str(args.openssl.resolve())
    from tests.test_sm2_credentials import SM2CredentialTests
    from tls20_server.handshake import server_handshake
    from tls20_server.pki import Credentials
    from tls20_server.tickets import TicketStore
    fixture = SM2CredentialTests()
    fixture.setUp()
    try:
        parent, grant, _, _ = fixture.delegated_fixture()
        root = fixture.work / "root.der"
        root.write_bytes(fixture.der(fixture.root))
        for delegated, suite, case in ((False, 0xc6, "valid"), (False, 0xc7, "valid"),
                                      (True, 0xc6, "valid"), (True, 0xc7, "valid"),
                                      (False, 0xc6, "tampered-cert"), (True, 0xc6, "tampered-grant")):
            leaf = fixture.der(parent if delegated else fixture.leaf)
            selected_grant = grant if delegated else b""
            if case == "tampered-cert":
                leaf = leaf[:-1] + bytes((leaf[-1] ^ 1,))
            if case == "tampered-grant":
                selected_grant = selected_grant[:-1] + bytes((selected_grant[-1] ^ 1,))
            credentials = Credentials([leaf, fixture.der(fixture.root)], fixture.key, delegation=selected_grant)
            store, errors, seen, tasks = TicketStore(), [], [], set()

            async def peer(reader, writer):
                task = asyncio.current_task()
                tasks.add(task)
                early_data = []
                async def early(data):
                    early_data.append(data)
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, credentials, "example.test",
                            native_provider=fixture.provider, cipher_suites=(suite,), ticket_store=store,
                            max_early_data=16384, on_early_data=early)
                        request = b"".join(early_data) or await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1\r\n")
                        seen.append((channel.resumed, channel.early_data_accepted))
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
                    tasks.discard(task)

            listener = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-native-provider",
                    "example.test", str(listener.sockets[0].getsockname()[1]), str(root), str(args.provider.resolve()),
                    "41", hex(suite)[2:], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 25)
                except BaseException:
                    if process.returncode is None:
                        process.kill()
                    await process.wait()
                    raise
                if tasks:
                    await asyncio.gather(*tasks)
                if case == "valid":
                    assert process.returncode == 0 and not errors, (delegated, suite, output, error, errors)
                    assert seen == [(False, False), (True, False), (True, True)], seen
                else:
                    assert process.returncode != 0 and not seen, (case, output, error, seen)
            finally:
                listener.close()
                await listener.wait_closed()
    finally:
        fixture.doCleanups()
    print("14 native SM2 certificate/grant connections passed: real PKIX, independent signing IDs, full/resume/early and tampering")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
