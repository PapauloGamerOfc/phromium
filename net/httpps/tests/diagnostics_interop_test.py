#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Test-only category gating and GREASE/padded ClientHello interoperability."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.tickets import TicketStore
    credentials, ca = generate_lab_credentials("localhost")
    cases = [("--get-diagnostics", mode) for mode in ("off", "on", "exporters", "failure")]
    cases += [("--get-grease", padding) for padding in ("0", "512", "20000")]
    with tempfile.TemporaryDirectory(prefix="httpps-diagnostics-") as directory:
        root = Path(directory) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        for mode, argument in cases:
            errors, handlers = [], set()
            store = TicketStore()
            async def peer(reader, writer):
                handlers.add(asyncio.current_task())
                received = []
                async def early(value):
                    received.append(value)
                try:
                    async with asyncio.timeout(10):
                        channel = await server_handshake(reader, writer, credentials, "localhost",
                            ticket_store=store, max_early_data=16384, on_early_data=early)
                        request = b"".join(received) if received else await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1\r\n")
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                        await channel.close()
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except ConnectionError:
                        pass
                    handlers.discard(asyncio.current_task())
            server = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()), mode, "localhost",
                    str(server.sockets[0].getsockname()[1]), str(root), argument,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 20)
                except BaseException:
                    process.kill()
                    await process.wait()
                    raise
                if handlers:
                    await asyncio.gather(*handlers)
                assert process.returncode == 0, (mode, argument, error, errors)
                assert not errors, errors
            finally:
                server.close()
                await server.wait_closed()
    print("21 native connections: diagnostic opt-in/exporter separation/failure isolation, GREASE, padded and fragmented ClientHellos, PSK binders and 0-RTT passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
