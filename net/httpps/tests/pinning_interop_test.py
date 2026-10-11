#!/usr/bin/env python3
"""Native pin continuity across fresh handshakes, key rotation and rejection."""
import argparse
import asyncio
import os
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.pinning import ServerPinning
    from tls20_server.tickets import TicketStore

    with tempfile.TemporaryDirectory(prefix="httpps-pin-") as directory:
        credentials, root = generate_lab_credentials("localhost")
        root_path = Path(directory) / "root.der"
        root_path.write_bytes(root.public_bytes(serialization.Encoding.DER))
        total = 0
        for case in ("refresh", "rotation", "ramp-down", "missing", "corrupt"):
            key_id, key = os.urandom(16), os.urandom(32)
            new_id, new_key = os.urandom(16), os.urandom(32)
            normal = ServerPinning({key_id: key}, key_id)
            rotated = ServerPinning({key_id: key, new_id: new_key}, new_id)
            ramp = ServerPinning({key_id: key}, key_id, ramp_down=True)
            errors, seen, handlers = [], [], set()
            connections = 0
            store = TicketStore()

            class Corrupt(ServerPinning):
                def respond(self, *values, **options):
                    result = bytearray(super().respond(*values, **options))
                    if result[0]:
                        result[1] ^= 1
                    return bytes(result)

            corrupt = Corrupt({key_id: key}, key_id)

            async def peer(reader, writer):
                nonlocal connections
                task = asyncio.current_task()
                handlers.add(task)
                ordinal = connections
                connections += 1
                policy = normal
                if ordinal:
                    policy = {"rotation": rotated, "ramp-down": ramp,
                              "missing": None, "corrupt": corrupt}.get(case, normal)
                try:
                    async with asyncio.timeout(10):
                        channel = await server_handshake(reader, writer, credentials,
                            "localhost", pinning=policy,
                            pinning_port=writer.get_extra_info("sockname")[1],
                            ticket_store=store)
                        request = b""
                        while b"\r\n\r\n" not in request:
                            fragment = await channel.recv()
                            assert fragment, "client closed before HTTP"
                            request += fragment
                        assert not channel.resumed and not channel.early_data_accepted
                        seen.append(ordinal)
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        await channel.close()
                except BaseException as error:
                    errors.append((ordinal, type(error).__name__, str(error)))
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
                    "--get-pinning", "localhost", str(server.sockets[0].getsockname()[1]),
                    str(root_path), stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 30)
                except BaseException:
                    process.kill()
                    await process.wait()
                    raise
                if handlers:
                    await asyncio.gather(*handlers)
                if case in ("missing", "corrupt"):
                    assert process.returncode != 0, (case, output, error)
                    assert b"authenticated server flight" in error, (case, error)
                    assert seen == [0] and connections == 2, (case, seen, connections, errors)
                    assert len(errors) == 1 and errors[0][0] == 1, (case, errors)
                    assert errors[0][1] not in ('TypeError', 'AttributeError', 'NameError'), (case, errors)
                else:
                    assert process.returncode == 0 and not errors, (case, output, error, errors)
                    assert seen == [0, 1, 2], (case, seen)
                total += connections
            finally:
                server.close()
                await server.wait_closed()
        print(f"{total} native pinning connections passed: enrollment, cross-hash refresh, rotation, ramp-down and fail-closed proof checks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
