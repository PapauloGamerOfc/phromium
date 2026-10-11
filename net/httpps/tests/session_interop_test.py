#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Real TCP/AEAD resumption and early-data rejection, no production endpoints."""

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
    with tempfile.TemporaryDirectory(prefix="httpps-session-") as directory:
        root = Path(directory) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        for reject_early in (False, True):
            store = TicketStore()
            errors, observations, handlers = [], [], set()

            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                number = len(observations)
                observations.append(None)
                received_early = []

                async def early(data):
                    if data:
                        received_early.append(data)

                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(
                            reader, writer, credentials, "localhost",
                            ticket_store=store,
                            max_early_data=0 if reject_early and number == 2 else 16384,
                            on_early_data=early,
                        )
                        request = b"".join(received_early)
                        if not request:
                            request = await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1\r\n")
                        observations[number] = (channel.resumed, channel.early_data_accepted,
                                                len(received_early))
                        # KeyUpdate is handled by recv(); this response verifies
                        # both directions after the client's requested update.
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                           b"Connection: close\r\n\r\nOK")
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
                    str(args.native.resolve()),
                    "--get-resume-reject" if reject_early else "--get-resume",
                    "localhost", str(server.sockets[0].getsockname()[1]), str(root),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 20)
                except BaseException:
                    process.kill()
                    await process.wait()
                    raise
                if handlers:
                    await asyncio.gather(*handlers)
                assert process.returncode == 0, (error, errors)
                assert not errors, errors
                assert output.count(b"HTTP/1.1 200 OK") == 3
                assert observations == [(False, False, 0), (True, False, 0),
                                        (True, not reject_early, int(not reject_early))], observations
            finally:
                server.close()
                await server.wait_closed()
        print("6 native session connections passed: full, PSK, 0-RTT acceptance/rejection, KeyUpdate")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
