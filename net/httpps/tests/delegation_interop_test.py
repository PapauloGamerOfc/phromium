#!/usr/bin/env python3
"""Role-separated server and client X25519 delegation with a real signing CA."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile


async def independent_directions(args):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from tls20_server import messages as m
    from tls20_server.application_auth import credential_validator
    from tls20_server.credential_profiles import CredentialPolicy, DELEGATION_USAGE
    from tls20_server.handshake import server_handshake
    from tls20_server.pki import Credentials
    from tests.test_credential_profiles import CredentialProfileTests, spki
    from tests.test_pki import issue

    fixture = CredentialProfileTests()
    fixture.setUp()
    der = lambda cert: cert.public_bytes(serialization.Encoding.DER)
    client_parent, client_grant = fixture.parent_and_grant(role="client")
    # Actually negotiate ECDSA server delegation while the client identity's
    # independent offline grant uses Ed25519 (both certificate paths use ECDSA).
    signer = ec.generate_private_key(ec.SECP256R1())
    parent = issue(signer, fixture.ca_key, fixture.name, fixture.ca_name,
        key_usage=x509.KeyUsage(True, False, False, False, False, False, False, False, False),
        extra=[(x509.UnrecognizedExtension(DELEGATION_USAGE, b"\x05\x00"), False)])
    public = spki(fixture.key)
    body = (3900).to_bytes(4, "big") + b"\xfe\x00" + len(public).to_bytes(3, "big") + public + b"\x04\x03"
    signature = signer.sign(b" " * 64 + b"TLS20 server delegated credentials\x00" + der(parent) + body,
                            ec.ECDSA(hashes.SHA256()))
    credentials = Credentials([der(parent)], fixture.key,
                              delegation=body + len(signature).to_bytes(2, "big") + signature)
    policy = CredentialPolicy(trust_roots=(fixture.root,), peer_name="device",
        authorize_client=lambda material, evidence: material == (der(client_parent),))
    raw_key = fixture.key.private_bytes_raw()
    with tempfile.TemporaryDirectory(prefix="httpps-delegation-directions-") as directory:
        directory = Path(directory)
        root, leaf, key, grant_path = [directory / name for name in ("root.der", "client.der", "client.key", "client.grant")]
        root.write_bytes(der(fixture.root))

        async def run_local(parent_der, private, grant, expected):
            leaf.write_bytes(parent_der)
            key.write_bytes(private)
            grant_path.write_bytes(grant)
            process = await asyncio.create_subprocess_exec(str(args.native.resolve()),
                "--check-client-delegation", str(leaf), str(key), str(grant_path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                output, error = await asyncio.wait_for(process.communicate(), 15)
            except BaseException:
                if process.returncode is None:
                    process.kill()
                await process.wait()
                raise
            assert process.returncode == expected, (expected, process.returncode, output, error)

        await run_local(der(client_parent), raw_key, client_grant, 0)
        invalid = [client_grant[:-1], client_grant + b"\0",
                   client_grant[:-1] + bytes((client_grant[-1] ^ 1,))]
        for grant in invalid:
            await run_local(der(client_parent), raw_key, grant, 1)
        for kwargs in ({"role": "server"}, {"role": "client", "valid_time": 1},
                       {"role": "client", "delegation": False},
                       {"role": "client", "scheme": 0xaaaa}):
            bad_parent, bad_grant = fixture.parent_and_grant(**kwargs)
            await run_local(der(bad_parent), raw_key, bad_grant, 1)
        await run_local(der(client_parent), x25519.X25519PrivateKey.generate().private_bytes_raw(), client_grant, 1)
        leaf.write_bytes(der(client_parent))
        key.write_bytes(raw_key)
        grant_path.write_bytes(client_grant)

        for mode in ("initial", "initial-unoffered", "pha", "ea"):
            errors, seen, handlers = [], [], set()

            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                try:
                    async with asyncio.timeout(10):
                        channel = await server_handshake(reader, writer, credentials, "example.test",
                            client_credential_policy=None if mode == "ea" else policy,
                            require_client_auth=mode == "initial", enable_authenticators=mode == "ea",
                            client_delegation_signature_algorithms=(0x0807,) if mode == "initial" else (0x0403,))
                        assert m._u16_list(dict(channel.peer_capabilities)[0xff04]) == (0x0403,)
                        assert channel.authenticated_client == ((der(client_parent),) if mode == "initial" else None)
                        if mode == "ea":
                            manager = channel.authenticators()
                            buffered = bytearray()

                            async def receive():
                                while True:
                                    if len(buffered) >= 4:
                                        size = int.from_bytes(buffered[:4], "big")
                                        assert size <= 1048576
                                        if len(buffered) >= size + 4:
                                            result = bytes(buffered[4:4 + size])
                                            del buffered[:4 + size]
                                            return result
                                    value = await channel.recv()
                                    assert value is not None
                                    buffered.extend(value)

                            validator = credential_validator(policy, role="client", authorize=lambda identity: True)
                            for scheme in (0x0807, 0x0403):
                                request = manager.request(extra_extensions=((34, b"\x00\x02\xfe\x01"),
                                    (0xff04, b"\x00\x02" + scheme.to_bytes(2, "big"))))
                                await channel.send(len(request).to_bytes(4, "big") + request)
                                response = await receive()
                                result = await manager.validate(response, validator, request=request)
                                assert result.authenticated == (scheme == 0x0807)
                                if result.authenticated:
                                    assert result.certificate.chain == (der(client_parent),)
                                seen.append(result.authenticated)
                            assert await receive() == b"OK"
                        else:
                            request = b""
                            while b"\r\n\r\n" not in request:
                                value = await channel.recv()
                                assert value is not None
                                request += value
                            if mode == "pha":
                                first = await channel.request_client_auth(required=True,
                                    delegation_signature_algorithms=(0x0807,))
                                await channel.key_update(request_peer=True)
                                second = await channel.request_client_auth(
                                    delegation_signature_algorithms=(0x0403,))
                                drive = asyncio.create_task(channel.recv())
                                seen.extend(await asyncio.gather(first, second))
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        if mode == "pha":
                            # Let the active reader consume the peer's close
                            # before close() releases both record states.
                            writer.write(channel.sender.seal(b"\x01\x00", 21))
                            await writer.drain()
                            assert await drive is None
                        await channel.close()
                        seen.append("complete")
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
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()),
                    "--get-delegation-direction", "example.test", str(server.sockets[0].getsockname()[1]),
                    str(root), str(leaf), str(key), str(grant_path), mode,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 15)
                except BaseException:
                    if process.returncode is None:
                        process.kill()
                    await process.wait()
                    raise
                if handlers:
                    await asyncio.gather(*handlers)
                assert process.returncode == 0 and not errors, (mode, output, error, errors)
                assert seen == ([(der(client_parent),), None, "complete"] if mode == "pha" else
                                [True, False, "complete"] if mode == "ea" else ["complete"]), (mode, seen)
            finally:
                server.close()
                await server.wait_closed()


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
    await independent_directions(args)
    print("10 native delegated credential connections and 9 local validity checks passed: both roles, compression, resume/early, independent initial/PHA/EA grant offers and unoffered refusals")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
