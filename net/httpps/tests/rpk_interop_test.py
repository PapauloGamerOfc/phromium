#!/usr/bin/env python3
"""Both roles authenticate provisioned raw keys across full/resumed/early TLS2."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from tls20_server.credential_profiles import CredentialPolicy, RawPublicKeyBinding
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.pki import Credentials
    from tls20_server.tickets import TicketStore
    _, ca = generate_lab_credentials("localhost")
    def raw():
        key = X25519PrivateKey.generate()
        return Credentials([key.public_key().public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)], key, credential_type=2)
    credentials, client = raw(), raw()
    with tempfile.TemporaryDirectory(prefix="httpps-rpk-") as directory:
        directory = Path(directory)
        root, pin, leaf, key = [directory / name for name in ("root.der", "pin.der", "client.der", "client.key")]
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        pin.write_bytes(credentials.chain_der[0])
        leaf.write_bytes(client.chain_der[0])
        key.write_bytes(client.private_key.private_bytes_raw())
        for with_client in (False, True):
            store, errors, seen, handlers = TicketStore(), [], [], set()
            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                early = []
                async def on_early(data):
                    early.append(data)
                options = {}
                if with_client:
                    options = dict(require_client_auth=True, client_certificate_types=(2,),
                        client_credential_policy=CredentialPolicy(peer_name="device", raw_public_keys=(
                            RawPublicKeyBinding("client", "device", client.chain_der[0]),)))
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, credentials, "localhost",
                            ticket_store=store, max_early_data=16384, on_early_data=on_early, **options)
                        request = b"".join(early)
                        while b"\r\n\r\n" not in request:
                            request += await channel.recv()
                        seen.append((channel.resumed, channel.early_data_accepted, bool(channel.authenticated_client)))
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
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-rpk", "localhost",
                    str(server.sockets[0].getsockname()[1]), str(root), str(pin),
                    str(leaf) if with_client else "-", str(key) if with_client else "-",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                output, error = await asyncio.wait_for(process.communicate(), 20)
                if handlers:
                    await asyncio.gather(*handlers)
                assert process.returncode == 0 and not errors, (output, error, errors)
                assert seen == [(False, False, with_client), (True, False, with_client),
                                (True, True, with_client)], seen
            finally:
                server.close()
                await server.wait_closed()
    print("6 native RPK connections passed: server/client raw credentials, resumption and 0-RTT")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
