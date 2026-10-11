#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Directional record limits, fragmented certificates and remembered 0-RTT."""
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
    with tempfile.TemporaryDirectory(prefix="httpps-record-limits-") as directory:
        root = Path(directory) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        for local, remote in ((64, 256), (256, 64), (16385, 512)):
            store, errors, observed, handlers = TicketStore(), [], [], set()

            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                early = []

                async def on_early(data):
                    early.append(data)

                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, credentials, "localhost",
                            ticket_store=store, max_early_data=16384, on_early_data=on_early,
                            record_size_limit=remote)
                        request = b"".join(early)
                        while b"\r\n\r\n" not in request:
                            request += await channel.recv()
                        observed.append((channel.sender.record_limit, channel.receiver.record_limit,
                                         channel.resumed, channel.early_data_accepted))
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\nConnection: close\r\n\r\n" + b"a" * 2048)
                        await channel.close()
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    await writer.wait_closed()
                    handlers.discard(task)

            server = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                process = await asyncio.create_subprocess_exec(
                    str(args.native.resolve()), "--get-limit", "localhost", str(server.sockets[0].getsockname()[1]),
                    str(root), str(local), "128", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                output, error = await asyncio.wait_for(process.communicate(), 15)
                if handlers:
                    await asyncio.gather(*handlers)
                assert process.returncode == 0 and not errors, ((local, remote), error, errors)
                assert output.count(b"HTTP/1.1 200 OK") == 3
                assert observed == [(local, remote, False, False), (local, remote, True, False),
                                    (local, remote, True, True)], observed
            finally:
                server.close()
                await server.wait_closed()
    print("9 native directional RSL full/resume/0RTT connections passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
