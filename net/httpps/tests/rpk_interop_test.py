#!/usr/bin/env python3
"""Both roles authenticate provisioned raw keys across full/resumed/early TLS2."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


async def oid_filter_cases(native, directory, credentials, client, ca):
    """Recognized X.509 filters cannot select an RPK, initially or in PHA."""
    from cryptography.hazmat.primitives import serialization
    from tls20_server import messages as m
    from tls20_server.credential_profiles import CredentialPolicy, RawPublicKeyBinding
    from tls20_server.handshake import server_handshake

    root, leaf, key = (directory / name for name in ("filter-root.der", "filter-client.der", "filter-client.key"))
    root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
    leaf.write_bytes(client.chain_der[0])
    key.write_bytes(client.private_key.private_bytes_raw())
    policy = CredentialPolicy(peer_name="device", raw_public_keys=(
        RawPublicKeyBinding("client", "device", client.chain_der[0]),))
    filters = (
        ("none", (), True),
        ("unknown", (("1.2.3.4", b"\xff\x00\x80"),), True),
        ("KU presence", (("2.5.29.15", b""),), False),
        ("KU value", (("2.5.29.15", b"\x03\x02\x03\x08"),), False),
        ("EKU presence", (("2.5.29.37", b""),), False),
        ("EKU value", (("2.5.29.37", b"\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02"),), False),
    )
    parse_certificate, parse_proof = m.parse_certificate, m.parse_certificate_verify
    failures = []
    count = 0
    for suite in (0x1301, 0x1302):
        for pha in (False, True):
            for required in (False, True):
                for name, requested, selected in filters:
                    errors, identities, certificates, proofs, tasks = [], [], [], [], []
                    accepted = asyncio.Event()
                    case = (hex(suite), "PHA" if pha else "initial", required, name)

                    def observe_certificate(body, **kwargs):
                        parsed = parse_certificate(body, **kwargs)
                        chain = parsed[0] if kwargs.get("details") else parsed
                        certificates.append((kwargs.get("context", b""), len(chain)))
                        return parsed

                    def observe_proof(body, **kwargs):
                        parsed = parse_proof(body, **kwargs)
                        proofs.append(kwargs.get("client", False))
                        return parsed

                    async def peer(reader, writer):
                        channel = drive = pending = None
                        try:
                            async with asyncio.timeout(8):
                                channel = await server_handshake(reader, writer, credentials, "localhost",
                                    cipher_suites=(suite,), client_certificate_types=(2,),
                                    client_credential_policy=policy, certificate_compression=(),
                                    require_client_auth=required and not pha,
                                    client_oid_filters=() if pha else requested)
                                identities.append(channel.authenticated_client)
                                request = await channel.recv()
                                assert request.startswith(b"GET / HTTP/1.1\r\n"), request
                                if pha:
                                    pending = await channel.request_client_auth(required=required, oid_filters=requested)
                                    drive = asyncio.create_task(channel.recv())
                                    await asyncio.wait((pending, drive), return_when=asyncio.FIRST_COMPLETED)
                                    if drive.done():
                                        await drive
                                    identities.append(await pending)
                                await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                                if drive:
                                    # Keep the receiving half alive for the
                                    # native peer's authenticated close reply.
                                    writer.write(channel.sender.seal(b"\x01\x00", 21))
                                    await writer.drain()
                                    assert await drive is None
                                else:
                                    await channel.close()
                        except BaseException as error:
                            errors.append((type(error).__name__, getattr(error, "alert", None), str(error)))
                        finally:
                            if channel:
                                channel.abort()
                            if drive and not drive.done():
                                drive.cancel()
                            if drive:
                                await asyncio.gather(drive, return_exceptions=True)
                            if pending:
                                if not pending.done():
                                    pending.cancel()
                                await asyncio.gather(pending, return_exceptions=True)
                            writer.close()
                            try:
                                await writer.wait_closed()
                            except ConnectionError:
                                pass

                    def accept(reader, writer):
                        tasks.append(asyncio.create_task(peer(reader, writer)))
                        accepted.set()

                    server = await asyncio.start_server(accept, "127.0.0.1", 0)
                    process = None
                    try:
                        with patch.object(m, "parse_certificate", observe_certificate), patch.object(m, "parse_certificate_verify", observe_proof):
                            process = await asyncio.create_subprocess_exec(str(native.resolve()), "--get-pha", "localhost",
                                str(server.sockets[0].getsockname()[1]), str(root), str(leaf), str(key),
                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                            output, error = await asyncio.wait_for(process.communicate(), 15)
                            await asyncio.wait_for(accepted.wait(), 3)
                            await asyncio.gather(*tasks)
                        expected_counts = ([1] if pha else []) + [int(selected)]
                        assert [size for _, size in certificates] == expected_counts, (case, certificates, errors)
                        assert [bool(context) for context, _ in certificates] == ([False, True] if pha else [False]), (case, certificates)
                        assert proofs == [True] * sum(expected_counts), (case, proofs)
                        if required and not selected:
                            assert process.returncode != 0 and not output, (case, output, error)
                            assert len(errors) == 1 and errors[0][:2] == ("ProtocolError", 116), (case, errors)
                        else:
                            assert process.returncode == 0 and not errors and b"HTTP/1.1 200 OK" in output, (case, output, error, errors)
                            expected_identity = tuple(client.chain_der) if selected else None
                            assert identities == ([tuple(client.chain_der)] if pha else []) + [expected_identity], (case, identities)
                        count += 1
                    except AssertionError as error:
                        failures.append(str(error))
                    finally:
                        server.close()
                        await server.wait_closed()
                        if process and process.returncode is None:
                            process.kill()
                            await process.wait()
                        for task in tasks:
                            if not task.done():
                                task.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
    assert not failures, "RPK OID filter failures:\n" + "\n".join(failures)
    print(f"{count} native RPK OID-filter connections passed: initial/PHA, required/optional, SHA256/SHA384, presence/value/unknown controls")


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from tls20_server.credential_profiles import CredentialPolicy, RawPublicKeyBinding
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.pki import Credentials
    from tls20_server.tickets import TicketStore
    x509_credentials, ca = generate_lab_credentials("localhost")
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
        await oid_filter_cases(args.native, directory, x509_credentials, client, ca)
    print("6 native RPK connections passed: server/client raw credentials, resumption and 0-RTT")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
