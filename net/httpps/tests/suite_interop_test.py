#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Independent Python/C++ cipher/hash/group full, PSK, early and KU matrix."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile

from interop_runtime import run, start_process


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.tickets import TicketStore

    credentials, ca = generate_lab_credentials("localhost")
    provider = None
    if args.native_provider:
        if args.gost_module:
            from tls20_server.gost_provider import GOSTProvider
            provider = GOSTProvider(args.native_provider.resolve(), args.gost_module.resolve())
        else:
            from tls20_server.openssl_provider import OpenSSLProvider
            provider = OpenSSLProvider(args.native_provider)
    with tempfile.TemporaryDirectory(prefix="httpps-suites-") as directory:
        root = Path(directory) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        suites = range(0xc103, 0xc107) if args.gost_module else (0x1301, 0x1302, 0x00c6, 0x00c7) if provider else (0x1301, 0x1302) if args.ffdhe else (0x1301, 0x1302, 0x1303, 0x1304, 0x1305)
        groups = range(34, 41) if args.gost_module else (30, 31, 32, 33, 41) if provider else (256, 257, 258, 259, 260) if args.ffdhe else (29, 23, 24, 25, 4588, 4587, 4589)
        for suite in suites:
            for group in groups:
                store, errors, observations, handlers = TicketStore(), [], [], set()

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    handlers.add(task)
                    early_bytes = []

                    async def early(data):
                        early_bytes.append(data)

                    try:
                        async with asyncio.timeout(30):
                            channel = await server_handshake(
                                reader, writer, credentials, "localhost",
                                cipher_suites=(suite,), ticket_store=store,
                                max_early_data=16384, on_early_data=early,
                                native_provider=provider)
                            request = b"".join(early_bytes) or await channel.recv()
                            assert request.startswith(b"GET / HTTP/1.1\r\n")
                            observations.append((channel.resumed, channel.early_data_accepted))
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                               b"Connection: close\r\n\r\nOK")
                            await channel.close()
                    except BaseException as error:
                        errors.append(repr(error))
                    finally:
                        writer.close()
                        try:
                            await asyncio.wait_for(writer.wait_closed(), 2)
                        except TimeoutError as error:
                            errors.append(f"writer cleanup timeout: {error!r}")
                            writer.transport.abort()
                        except (ConnectionError, OSError) as error:
                            errors.append(f"writer cleanup failed: {error!r}")
                        finally:
                            handlers.discard(task)

                server = await asyncio.start_server(peer, "127.0.0.1", 0)
                try:
                    port = str(server.sockets[0].getsockname()[1])
                    arguments = (["--get-gost", "localhost", port, str(root), str(args.native_provider.resolve()), str(args.gost_module.resolve()), f"{suite:x}", str(group)] if args.gost_module else ["--get-native-provider", "localhost", port, str(root), str(args.native_provider), str(group), f"{suite:x}"]
                                 if provider else ["--get-suite-resume", f"{suite:x}", str(group), "localhost", port, str(root)])
                    process = await start_process(
                        str(args.native.resolve()), *arguments,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    try:
                        output, error = await asyncio.wait_for(process.communicate(), 100)
                    except BaseException:
                        if process.returncode is None:
                            process.kill()
                        await process.wait()
                        raise
                    if handlers:
                        await asyncio.wait_for(asyncio.gather(*handlers), 32)
                    assert process.returncode == 0, (suite, group, error, errors)
                    assert not errors, (suite, group, errors)
                    assert output.count(b"HTTP/1.1 200 OK") == 3
                    assert observations == [(False, False), (True, False), (True, True)], observations
                    print(f"suite={suite:04x} group={group}: full/resume/early/KU passed", flush=True)
                finally:
                    server.close()
                    for task in tuple(handlers):
                        task.cancel()
                    if handlers:
                        await asyncio.wait_for(asyncio.gather(*tuple(handlers), return_exceptions=True), 4)
                    await server.wait_closed()
    print(f"{len(suites) * len(groups) * 3} native negotiated-suite/group connections passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--ffdhe", action="store_true")
    parser.add_argument("--native-provider", type=Path)
    parser.add_argument("--gost-module", type=Path)
    run(main(parser.parse_args()))
