#!/usr/bin/env python3
"""Role-separated server and client X25519 delegation with a real signing CA."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from tls20_server.handshake import server_handshake
    from tls20_server.pki import Credentials
    from tls20_server.tickets import TicketStore
    from tls20_server.credential_profiles import CredentialPolicy
    from tests.test_credential_profiles import CredentialProfileTests
    fixture = CredentialProfileTests()
    fixture.setUp()
    parent, grant = fixture.parent_and_grant()
    client_parent, client_grant = fixture.parent_and_grant(role="client")
    der = lambda cert: cert.public_bytes(serialization.Encoding.DER)
    credentials = Credentials([der(parent)], fixture.key, delegation=grant)
    with tempfile.TemporaryDirectory(prefix="httpps-delegation-") as directory:
        directory = Path(directory)
        root, leaf, key, client_grant_path = [directory / name for name in ("root.der", "client.der", "client.key", "client.grant")]
        root.write_bytes(der(fixture.root))
        leaf.write_bytes(der(client_parent))
        key.write_bytes(fixture.key.private_bytes_raw())
        client_grant_path.write_bytes(client_grant)
        for selected in (False, True):
            errors, seen, handlers, store = [], [], set(), TicketStore()
            options = {}
            if selected:
                options = dict(require_client_auth=True, client_credential_policy=CredentialPolicy(
                    trust_roots=(fixture.root,), peer_name="device", authorize_client=lambda material, evidence:
                    material == (der(client_parent),)))
            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                early = []
                async def receive_early(data):
                    early.append(data)
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, credentials, "example.test",
                            ticket_store=store, max_early_data=16384, on_early_data=receive_early, **options)
                        request = b"".join(early)
                        while b"\r\n\r\n" not in request:
                            request += await channel.recv()
                        seen.append((channel.resumed, channel.early_data_accepted))
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        await channel.close()
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except ConnectionError:
                        pass
                    handlers.discard(task)
            server = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-delegation", "example.test",
                    str(server.sockets[0].getsockname()[1]), str(root),
                    str(leaf) if selected else "-", str(key) if selected else "-",
                    str(client_grant_path) if selected else "-", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                output, error = await asyncio.wait_for(process.communicate(), 15)
                if handlers:
                    await asyncio.gather(*handlers)
                assert process.returncode == 0 and not errors, (selected, output, error, errors)
                assert seen == [(False, False), (True, False), (True, True)], seen
            finally:
                server.close()
                await server.wait_closed()
    print("6 native delegated credential connections passed: both roles, compressed certificates, resume and early")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
