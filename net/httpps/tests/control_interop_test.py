#!/usr/bin/env python3
"""Native external-signaling and ticket-count negotiation over real records."""
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
    from tls20_server.optional_controls import SignalingBinding
    from tls20_server.tickets import TicketStore

    credentials, ca = generate_lab_credentials("localhost")
    with tempfile.TemporaryDirectory(prefix="httpps-controls-") as directory:
        root = Path(directory) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        for case in ("valid", "missing", "wrong-identity", "wrong-session"):
            store = TicketStore()
            errors, observations, handlers = [], [], set()
            signaling = SignalingBinding(bytes([0x22]) * 32, bytes([0x11]) * 32,
                b"server-0123456789012345", b"client-0123456789012345")
            if case == "missing":
                signaling = None
            elif case == "wrong-identity":
                signaling = SignalingBinding(bytes([0x33]) * 32, signaling.peer_hash,
                    signaling.local_session_id, signaling.peer_session_id)
            elif case == "wrong-session":
                signaling = SignalingBinding(signaling.local_hash, signaling.peer_hash,
                    b"other--0123456789012345", signaling.peer_session_id)

            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                received_early = []
                async def early(data):
                    received_early.append(data)
                try:
                    async with asyncio.timeout(10):
                        channel = await server_handshake(reader, writer, credentials,
                            "localhost", signaling=signaling, ticket_store=store,
                            ticket_count_limit=3, max_early_data=16384, on_early_data=early)
                        request = b"".join(received_early)
                        while b"\r\n\r\n" not in request:
                            fragment = await channel.recv()
                            assert fragment, "closed before HTTP request"
                            request += fragment
                        observations.append((channel.resumed, channel.early_data_accepted))
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
                    "--get-controls", "localhost", str(server.sockets[0].getsockname()[1]),
                    str(root), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 30)
                except BaseException:
                    process.kill()
                    await process.wait()
                    raise
                if handlers:
                    await asyncio.gather(*handlers)
                if case == "valid":
                    assert process.returncode == 0 and not errors, (case, output, error, errors)
                    assert observations == [(False, False), (True, False), (True, True)], observations
                else:
                    assert process.returncode != 0 and b"authenticated server flight" in error, (case, error)
                    assert not observations and len(errors) == 1, (case, observations, errors)
            finally:
                server.close()
                await server.wait_closed()
        print("6 native control connections passed: external signaling, ticket hints, resumption/early binding and required mismatch rejection")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
