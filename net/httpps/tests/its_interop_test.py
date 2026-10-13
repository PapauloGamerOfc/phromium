#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Real IEEE1609.2 offline authorization followed by native TLS2 live MACs."""
import argparse
import asyncio
from contextlib import suppress
from dataclasses import replace
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch


async def test_profile(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    os.environ["TLS20_TEST_ITS_LIBRARY"] = str(args.provider.resolve())
    os.environ["TLS20_ITS_FIXTURE_DIR"] = str(args.fixtures.resolve())
    from tests.test_its_handshake import load_live_fixture
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from tls20_server.handshake import server_handshake
    from tls20_server.pki import Credentials
    from tls20_server.tickets import TicketStore
    from tls20_server.credential_profiles import CredentialPolicy
    from tls20_server.errors import ProtocolError
    from tls20_server import messages as m
    directory, policy = load_live_fixture()
    private = X25519PrivateKey.from_private_bytes(bytes([9]) * 32)
    count = 0
    for mode in ("valid", "client", "client-unknown-oid", "client-ku", "client-eku",
                 "tamper", "revoked", "expired", "wrong-role", "wrong-service"):
        grant = (directory / "live-server.bin").read_bytes()
        if mode == "tamper":
            grant = grant[:-1] + bytes([grant[-1] ^ 1])
        credentials = Credentials([grant], private, credential_type=3, its_policy=policy)
        store, errors, seen, handlers = TicketStore(), [], [], set()
        with_client = mode.startswith("client")
        selected = mode not in ("client-ku", "client-eku")
        filters = {"client-unknown-oid": (("1.2.3.4", b"\xff\x00\x80"),),
                   "client-ku": (("2.5.29.15", b""),),
                   "client-eku": (("2.5.29.37", b""),)}.get(mode, ())
        certificates = []
        parse_certificate = m.parse_certificate

        def observe_certificate(body, **kwargs):
            parsed = parse_certificate(body, **kwargs)
            chain = parsed[0] if kwargs.get("details") else parsed
            certificates.append((bool(kwargs.get("context", b"")), len(chain)))
            return parsed

        options = {}
        if with_client:
            options = dict(client_credential_policy=CredentialPolicy(peer_name="example.test",
                its_policy=replace(policy, role="client")), require_client_auth=selected,
                client_certificate_types=(3,), client_oid_filters=filters)

        async def peer(reader, writer):
            task = asyncio.current_task()
            handlers.add(task)
            channel = None
            pump = None
            early = []
            async def receive_early(data):
                early.append(data)
            try:
                async with asyncio.timeout(8):
                    channel = await server_handshake(reader, writer, credentials, "example.test",
                        ticket_store=store, max_early_data=16384, on_early_data=receive_early, **options)
                    request = b"".join(early) or await channel.recv()
                    assert request.startswith(b"GET / HTTP/1.1\r\n")
                    seen.append((channel.resumed, channel.early_data_accepted))
                    if with_client:
                        identity = ((directory / "live-client.bin").read_bytes(),) if selected else None
                        assert channel.authenticated_client == identity
                        future = await channel.request_client_auth(required=selected)
                        pump = asyncio.create_task(channel.recv())
                        assert await asyncio.wait_for(asyncio.shield(future), 5) == identity
                    await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    await channel.close()
                    if pump:
                        # close() owns transport shutdown; the PHA pump has
                        # already completed the authenticated response above.
                        with suppress(ProtocolError, ConnectionError, OSError):
                            await pump
            except BaseException as error:
                errors.append(repr(error))
            finally:
                if pump:
                    if not pump.done():
                        pump.cancel()
                    with suppress(asyncio.CancelledError, ProtocolError, ConnectionError, OSError):
                        await pump
                writer.close()
                with suppress(ConnectionError, OSError):
                    await writer.wait_closed()
                handlers.discard(task)

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        try:
            with patch.object(m, "parse_certificate", observe_certificate):
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-its", "example.test",
                    str(server.sockets[0].getsockname()[1]), str(directory / "live-root.coer"),
                    str(args.provider.resolve()), str(directory), "client" if with_client else mode,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 25)
                except BaseException:
                    if process.returncode is None:
                        process.kill()
                    await process.wait()
                    raise
                if handlers:
                    await asyncio.gather(*handlers)
            if mode == "valid" or with_client:
                assert process.returncode == 0 and not errors, (mode, output, error, errors)
                assert seen == [(False, False), (True, False), (True, True)], seen
                if with_client:
                    # Resumption omits the initial certificate flight; each
                    # fresh PHA still applies its current recognized filters.
                    assert certificates == [(False, int(selected))] + [(True, int(selected))] * 3, (mode, certificates)
                count += 3
            else:
                assert process.returncode != 0 and not seen, (mode, output, error, seen)
                assert not any("TypeError" in value or "AttributeError" in value for value in errors), errors
                count += 1
        finally:
            server.close()
            await server.wait_closed()
    print(f"{count} native ITS connections passed: full/resume/early, both MAC roles/PHA, KU/EKU refusal and unknown-OID verification, tamper, revocation, service/role and expiry")


async def main(args):
    for profile in ("", "brainpool256", "brainpool384", "implicit-nist256", "implicit-brainpool256"):
        print("ITS credential profile:", profile or "nist256", flush=True)
        options = dict(vars(args))
        options["fixtures"] = args.fixtures / profile
        await test_profile(SimpleNamespace(**options))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("native", "server-source", "provider", "fixtures"):
        parser.add_argument("--" + name, type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
