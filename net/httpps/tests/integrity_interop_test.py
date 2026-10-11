#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""RFC 9150 opt-in native/Python record, resumption, early and update paths."""
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
    total = 0
    with tempfile.TemporaryDirectory(prefix="httpps-integrity-") as directory:
        root = Path(directory) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        for suite in (0xc0b4, 0xc0b5):
            for allow in (True, False):
                store, errors, observations, handlers = TicketStore(), [], [], set()

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    handlers.add(task)
                    received_early = []
                    async def early(data):
                        received_early.append(data)
                    try:
                        async with asyncio.timeout(10):
                            channel = await server_handshake(reader, writer, credentials,
                                "localhost", cipher_suites=(suite,), allow_non_confidential=allow,
                                ticket_store=store, max_early_data=16384, on_early_data=early)
                            assert not channel.confidential
                            size = 32 if suite == 0xc0b4 else 48
                            assert len(channel.sender.key) == len(channel.sender.iv) == size
                            request = b"".join(received_early)
                            while b"\r\n\r\n" not in request:
                                fragment = await channel.recv()
                                assert fragment, "closed before fixture request"
                                request += fragment
                            observations.append((channel.resumed, channel.early_data_accepted))
                            # The native peer requests KeyUpdate and includes the
                            # normal exporter on its non-early fixture requests.
                            for line in request.split(b"\r\n"):
                                if line.startswith(b"X-Test-Exporter: "):
                                    actual = bytes.fromhex(line.split(b": ", 1)[1].decode("ascii"))
                                    assert actual == channel.exporter("test exporter", b"\x01\x02\x03", 64)
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                            await channel.close()
                    except BaseException as error:
                        errors.append((type(error).__name__, str(error)))
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except (ConnectionError, OSError):
                            pass
                        handlers.discard(task)

                server = await asyncio.start_server(peer, "127.0.0.1", 0)
                try:
                    process = await asyncio.create_subprocess_exec(str(args.native.resolve()),
                        "--get-integrity", "localhost", str(server.sockets[0].getsockname()[1]),
                        str(root), f"{suite:x}", stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE)
                    try:
                        output, error = await asyncio.wait_for(process.communicate(), 40)
                    except BaseException:
                        process.kill()
                        await process.wait()
                        raise
                    if handlers:
                        await asyncio.gather(*handlers)
                    if allow:
                        assert process.returncode == 0 and not errors, (suite, output, error, errors)
                        assert observations == [(False, False), (True, False), (True, True)], observations
                        assert output.count(b"HTTP/1.1 200 OK") == 3
                        total += 3
                    else:
                        assert process.returncode != 0 and len(errors) == 1 and not observations, (error, errors)
                        total += 1
                finally:
                    server.close()
                    await server.wait_closed()
    print(f"{total} native integrity-only connections: explicit bilateral opt-in, both hashes, full/resume/early/KU/exporters and no-policy rejection passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
