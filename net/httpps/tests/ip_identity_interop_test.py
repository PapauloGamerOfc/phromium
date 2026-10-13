#!/usr/bin/env python3
"""DNS/IP SAN authentication, exact SNI and resumption in the actual native peer."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.x509.oid import NameOID
    from tls20_server import messages
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.tickets import TicketStore
    from tests.test_pki import issue, der

    async def run(*parameters, success=True):
        process = await asyncio.create_subprocess_exec(str(args.native.resolve()),
            *map(str, parameters), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            output, error = await asyncio.wait_for(process.communicate(), 25)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        assert (process.returncode == 0) == success, (parameters, output, error)

    with tempfile.TemporaryDirectory(prefix="httpps-ip-") as directory:
        directory = Path(directory)
        root_path, leaf_path = directory / "root.der", directory / "leaf.der"
        for service in ("127.0.0.1", "::1", "localhost"):
            is_ip = service != "localhost"
            credentials, root = generate_lab_credentials(service)
            root_path.write_bytes(root.public_bytes(serialization.Encoding.DER))
            leaf_path.write_bytes(credentials.chain_der[0])
            await run("--verify", service, root_path, leaf_path)
            wrong_service = {"127.0.0.1": "127.0.0.2", "::1": "::2", "localhost": "other.example"}[service]
            await run("--verify", wrong_service,
                      root_path, leaf_path, success=False)
            seen, errors, tasks, offers = [], [], set(), []
            store = TicketStore()
            original = messages.parse_client_hello
            def inspect(data, **options):
                hello = original(data, **options)
                offers.append(hello)
                if is_ip:
                    assert not hello.name and 0 not in hello.extensions, "IP must not be an SNI DNS name"
                else:
                    hostname = service.encode("ascii")
                    entry = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
                    # Match the whole vector, not just the decoded first name:
                    # every full/resumed/early CH needs exactly one nonempty
                    # host_name entry and no trailing or duplicate names.
                    assert hello.name == service
                    assert dict(hello.extension_values).get(0) == len(entry).to_bytes(2, "big") + entry
                return hello

            async def peer(reader, writer):
                task = asyncio.current_task()
                tasks.add(task)
                early = []
                async def receive_early(data):
                    early.append(data)
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, credentials, service,
                            ticket_store=store, max_early_data=16384, on_early_data=receive_early)
                        request = b"".join(early)
                        while b"\r\n\r\n" not in request:
                            part = await channel.recv()
                            assert part is not None
                            request += part
                        seen.append((channel.resumed, channel.early_data_accepted))
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        await channel.close()
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    await writer.wait_closed()
                    tasks.discard(task)

            server = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                with patch.object(messages, "parse_client_hello", inspect):
                    try:
                        await run("--get-resume", service, server.sockets[0].getsockname()[1], root_path)
                    except AssertionError as error:
                        raise AssertionError((str(error), errors)) from error
                    if tasks:
                        await asyncio.gather(*tasks)
                assert not errors and len(offers) == 3, (errors, offers)
                assert seen == [(False, False), (True, False), (True, True)], seen
            finally:
                server.close()
                await server.wait_closed()

            if not is_ip:
                continue

            # A DNSName containing an IP-looking string cannot authorize an IP
            # reference, even when issuer and all other key usages are valid.
            ca_key, key = ed25519.Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IP negative fixture")])
            root = issue(ca_key, ca_key, name, name, ca=True)
            leaf = issue(key, ca_key, name, name, hostname=service)
            root_path.write_bytes(der(root))
            leaf_path.write_bytes(der(leaf))
            await run("--verify", service, root_path, leaf_path, success=False)
        print("9 native DNS/IP connections and 8 SAN checks passed: exact DNS SNI, IPv4/IPv6 without SNI, full/resume/early, no DNS-text fallback")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
