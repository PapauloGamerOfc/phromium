#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Both application-authentication directions, refusals, replay and bindings."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from interop_runtime import run, start_process


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from tls20_server.handshake import server_handshake
    from tls20_server import application_auth as auth
    from tls20_server.application_auth import AuthorizedIdentity, parse_request
    from tests.test_client_auth import client_credentials
    from tests.test_credential_profiles import CredentialProfileTests
    from tests.test_pki import issue, der
    from tls20_server.pki import Credentials

    fixture = CredentialProfileTests()
    fixture.setUp()
    fixture.leaf = issue(fixture.key, fixture.ca_key, fixture.name, fixture.ca_name, hostname="localhost")
    credentials, ca = Credentials([der(fixture.leaf), der(fixture.root)], fixture.key), fixture.root
    status = fixture.make_ocsp()
    status = b"\x01" + len(status).to_bytes(3, "big") + status
    credential = client_credentials(ed25519.Ed25519PrivateKey.generate())
    password_policy = None
    if args.password_provider:
        from tls20_server import pake_handshake
        from tls20_server.pake import PasswordAccount, PasswordServer, password_base
        from tls20_server.pake_native import PakeProvider
        from tls20_server.openssl_provider import OpenSSLProvider
        provider = OpenSSLProvider(args.password_provider.resolve())
        password_policy = PasswordServer("localhost", PakeProvider(provider, args.password_helper.resolve()),
            [PasswordAccount(b"alice", password_base("alice", "correct horse", None), None)])
    with tempfile.TemporaryDirectory(prefix="httpps-ea-") as directory:
        root, leaf, key = (Path(directory) / name for name in ("root.der", "client.der", "client.raw"))
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        leaf.write_bytes(credential.chain_der[0])
        key.write_bytes(credential.private_key.private_bytes_raw())
        for selected in (False, True):
            for suite in ((0xc0b1,) if password_policy else (0x1301, 0x1302, 0x1303)):
                errors, handlers, cleanup_errors = [], set(), []
                completed = asyncio.Event()

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    handlers.add(task)
                    channel = None
                    try:
                        async with asyncio.timeout(20):
                            channel = (await pake_handshake.server(reader, writer, password_policy,
                                cipher_suites=(suite,), enable_authenticators=True) if password_policy else
                                await server_handshake(reader, writer, credentials, "localhost",
                                    cipher_suites=(suite,), enable_authenticators=True))
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

                            async def send(value):
                                await channel.send(len(value).to_bytes(4, "big") + value)

                            def validate(identity, request):
                                assert identity.chain == tuple(credential.chain_der)
                                assert request.role == "client"
                                assert dict(request.extensions)[5] == b""
                                return AuthorizedIdentity(credential.private_key.public_key(), "authorized-loopback-client")
                            from tls20_server import messages as m
                            for index, schemes in enumerate(((0x0a0a,), (0xaaaa,), (0xfe00,), (0x0a0a, 0xfe01))):
                                request = manager.request(context=b"client-first" + bytes((index,)), extra_extensions=(
                                    (34, m._vec(b"".join(value.to_bytes(2, "big") for value in schemes), 2)),
                                    (0xff04, m._vec(b"\x08\x07", 2)), (5, b"")))
                                if index == 0:
                                    parsed = parse_request(request)
                                    for invalid in (b"\x01\0\0\0\0", b"\x01", b"\xff"):
                                        # These malformed requests reuse the valid pending context.
                                        # The native API must reject them before consuming it,
                                        # whether returning a credential or an authenticated refusal.
                                        await send(m.frame(13, m._vec(parsed.context, 1) + m._vec(b"".join(
                                            m.extension(kind, invalid if kind == 5 else value)
                                            for kind, value in parsed.extensions), 2)))
                                await send(request)
                                response = await receive()
                                assert response[0] == (11 if selected else 20)
                                result = await manager.validate(response, validate, request=request)
                                assert result.authenticated == selected
                            assert await receive() == channel.channel_binding()
                            for schemes in ((0x0a0a,), (0xaaaa,), (0xfe01,), (0x0a0a, 0xfe00)):
                                request = await receive()
                                offers = dict(parse_request(request).extensions)
                                assert m._u16_list(offers[34]) == schemes
                                assert offers[5] == b""
                                await send(manager.authenticate(credentials, request=request))
                            request = await receive()
                            await send(manager.authenticate(request=request))
                            assert dict(channel.peer_capabilities)[5] == b"\x01\0\0\0\0"
                            await send(manager.authenticate(credentials, context=b"spontaneous-loopback"))
                            request = await receive()
                            tampered = bytearray(manager.authenticate(credentials, request=request))
                            tampered[-1] ^= 1
                            await send(bytes(tampered))
                            # Exactly bounded extension block, including a maximum
                            # size SCT envelope whose unknown version is ignorable.
                            large_sct = m._vec(m._vec(b"\xff" * 65527, 2), 2)
                            evidence = [(18, b"\0\x03\0\x01\xff", True),
                                        (18, b"\0\x06\0\x01\xfe\0\x01\xff", True),
                                        (18, large_sct, True), (5, status, True)]
                            evidence += [(18, value, False) for value in
                                (b"", b"\0", b"\0\0", b"\0\x01\0", b"\0\x02\0\0",
                                 b"\0\x03\0\x02\x01", b"\0\x03\0\x01\x01\0", b"\0\x04\0\x01\xff\0")]
                            evidence += [(5, value, False) for value in
                                (b"", b"\x01", b"\x01\0\0", b"\x01\0\0\0",
                                 b"\x01\0\0\x02\0", b"\x01\0\0\x01\0\0", b"\x02\0\0\x01\0")]
                            assert len(evidence) == 19
                            requested_evidence = evidence + [(52, b"", True), (52, b"\0\x04\0\x02\xff\xff", True)]
                            requested_evidence += [(52, value, False) for value in
                                (b"\0", b"\0\0", b"\0\x02\0\0", b"\0\x03\0\x01\xff",
                                 b"\0\x04\0\x03\xff\xff", b"\0\x04\0\x02\xff\xff\0")]
                            assert len(requested_evidence) == 27
                            for spontaneous in (False, True):
                                for index, (kind, value, valid) in enumerate(evidence if spontaneous else requested_evidence):
                                    request = None if spontaneous else await receive()
                                    context = bytes((0x40, int(spontaneous), index))
                                    if request is not None:
                                        parsed = parse_request(request)
                                        assert parsed.context == context and dict(parsed.extensions)[kind] == b""
                                    else:
                                        assert kind in dict(channel.peer_capabilities)
                                    metadata = (((kind, value),),) + ((),) * (len(credentials.chain_der) - 1)
                                    if valid:
                                        response = manager.authenticate(credentials, request=request,
                                            context=context if spontaneous else None, entry_extensions=metadata)
                                    else:
                                        # Malicious peer bypasses only its local metadata checks,
                                        # never the proof, Finished, transcript or credential bytes.
                                        with patch.object(auth, "_check_certificate_extensions", lambda *args: None), \
                                             patch("tls20_server.credential_evidence._status_response", return_value=b""), \
                                             patch("tls20_server.status_request.response_matches_request", return_value=True):
                                            response = manager.authenticate(credentials, request=request,
                                                context=context if spontaneous else None, entry_extensions=metadata)
                                    await send(response)
                                    assert await receive() == b"NEXT"
                            assert await receive() == b"OK"
                            await channel.close()
                    except BaseException as error:
                        errors.append(repr(error))
                    finally:
                        if channel is not None: channel.abort()
                        writer.close()
                        try:
                            await asyncio.wait_for(writer.wait_closed(), 2)
                        except TimeoutError as error:
                            cleanup_errors.append(error)
                            writer.transport.abort()
                        except ConnectionError:
                            pass
                        finally:
                            handlers.discard(task)
                            completed.set()

                server = await asyncio.start_server(peer, "127.0.0.1", 0)
                process = None
                try:
                    parameters = ["--get-password-authenticator", "localhost", str(server.sockets[0].getsockname()[1]),
                        str(root), str(args.password_provider.resolve()), str(args.password_helper.resolve())] if password_policy else [
                        "--get-authenticator", "localhost", str(server.sockets[0].getsockname()[1]), str(root), f"{suite:x}"]
                    process = await start_process(str(args.native.resolve()), *parameters,
                        str(leaf) if selected else "-", str(key) if selected else "-",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    try:
                        output, error = await asyncio.wait_for(process.communicate(), 25)
                    except BaseException:
                        if process.returncode is None: process.kill()
                        await process.wait()
                        raise
                    await asyncio.wait_for(completed.wait(), 22)
                    if handlers: await asyncio.wait_for(asyncio.gather(*handlers), 22)
                    assert process.returncode == 0, (selected, suite, error, errors)
                    assert not errors and not cleanup_errors, (errors, cleanup_errors)
                finally:
                    if process is not None and process.returncode is None:
                        process.kill()
                        await process.wait()
                    server.close()
                    for task in tuple(handlers): task.cancel()
                    if handlers: await asyncio.wait_for(asyncio.gather(*tuple(handlers), return_exceptions=True), 4)
                    await server.wait_closed()
    if password_policy: provider.close()
    print(f"{2 if password_policy else 6} native application-authenticator cases: client/server MAC, request/response evidence framing, 46 genuine-proof envelope checks per connection, GREASE/unknown delegation fallback, refusals, spontaneous identities, consumed contexts, continued application traffic and channel binding passed; PAKE={password_policy is not None}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--password-provider", type=Path)
    parser.add_argument("--password-helper", type=Path)
    run(main(parser.parse_args()))
