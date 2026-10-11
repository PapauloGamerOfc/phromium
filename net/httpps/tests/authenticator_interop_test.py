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


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.application_auth import AuthorizedIdentity
    from tests.test_client_auth import client_credentials

    credentials, ca = generate_lab_credentials("localhost")
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
                errors, handlers = [], set()

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    handlers.add(task)
                    try:
                        async with asyncio.timeout(10):
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
                                return AuthorizedIdentity(credential.private_key.public_key(), "authorized-loopback-client")
                            from tls20_server import messages as m
                            for index, schemes in enumerate(((0x0a0a,), (0xaaaa,), (0xfe00,), (0x0a0a, 0xfe01))):
                                request = manager.request(context=b"client-first" + bytes((index,)), extra_extensions=(
                                    (34, m._vec(b"".join(value.to_bytes(2, "big") for value in schemes), 2)),
                                    (0xff04, m._vec(b"\x08\x07", 2))))
                                await send(request)
                                response = await receive()
                                assert response[0] == (11 if selected else 20)
                                result = await manager.validate(response, validate, request=request)
                                assert result.authenticated == selected
                            assert await receive() == channel.channel_binding()
                            for schemes in ((0x0a0a,), (0xaaaa,), (0xfe01,), (0x0a0a, 0xfe00)):
                                request = await receive()
                                from tls20_server.application_auth import parse_request
                                assert m._u16_list(dict(parse_request(request).extensions)[34]) == schemes
                                await send(manager.authenticate(credentials, request=request))
                            request = await receive()
                            await send(manager.authenticate(request=request))
                            await send(manager.authenticate(credentials, context=b"spontaneous-loopback"))
                            request = await receive()
                            tampered = bytearray(manager.authenticate(credentials, request=request))
                            tampered[-1] ^= 1
                            await send(bytes(tampered))
                            assert await receive() == b"OK"
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
                    parameters = ["--get-password-authenticator", "localhost", str(server.sockets[0].getsockname()[1]),
                        str(root), str(args.password_provider.resolve()), str(args.password_helper.resolve())] if password_policy else [
                        "--get-authenticator", "localhost", str(server.sockets[0].getsockname()[1]), str(root), f"{suite:x}"]
                    process = await asyncio.create_subprocess_exec(str(args.native.resolve()), *parameters,
                        str(leaf) if selected else "-", str(key) if selected else "-",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    try:
                        output, error = await asyncio.wait_for(process.communicate(), 20)
                    except BaseException:
                        if process.returncode is None: process.kill()
                        await process.wait()
                        raise
                    if handlers:
                        await asyncio.gather(*handlers)
                    assert process.returncode == 0, (selected, suite, error, errors)
                    assert not errors, errors
                finally:
                    server.close()
                    await server.wait_closed()
    print(f"{2 if password_policy else 6} native application-authenticator cases: client/server MAC, GREASE/unknown delegation direct fallback and refusals, spontaneous identity, consumed contexts, tampered Finished and channel binding passed; PAKE={password_policy is not None}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--password-provider", type=Path)
    parser.add_argument("--password-helper", type=Path)
    asyncio.run(main(parser.parse_args()))
