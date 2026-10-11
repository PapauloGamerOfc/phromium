#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Explicit POK client RPK possession and scoped descendant tickets."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile
from dataclasses import replace
from unittest.mock import patch


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from tls20_server.bootstrap_credentials import BootstrapBinding, bootstrap_server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.tickets import TicketStore
    from tls20_server.handshake import Wire, server_handshake
    from tls20_server.psk import bootstrap_public_key_psk

    credentials, ca = generate_lab_credentials("localhost")
    _, unrelated = generate_lab_credentials("localhost")
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    with tempfile.TemporaryDirectory(prefix="httpps-pok-") as directory:
        root, leaf, key = (Path(directory) / name for name in ("root.der", "client.der", "client.raw"))
        leaf.write_bytes(public)
        key.write_bytes(private.private_bytes_raw())
        for mode in ("validated", "provisioning"):
            for suite in (0x1301, 0x1302):
                root.write_bytes((ca if mode == "validated" else unrelated).public_bytes(serialization.Encoding.DER))
                binding = BootstrapBinding(public, "localhost", "loopback-provisioning",
                    "credential-validated" if mode == "validated" else "provisioning-trust")
                store = TicketStore()
                errors, channels, handlers = [], [], set()

                async def peer(reader, writer):
                    handlers.add(asyncio.current_task())
                    early = []
                    async def accept_early(data):
                        early.append(data)
                    try:
                        async with asyncio.timeout(10):
                            channel = await bootstrap_server_handshake(reader, writer, credentials, binding,
                                ticket_store=store, cipher_suites=(suite,), max_early_data=16384,
                                on_early_data=accept_early)
                            channels.append(channel)
                            assert channel.bootstrap_authorization["scope"] == "loopback-provisioning"
                            assert channel.authenticated_client == (public,)
                            request = b"".join(early) if early else await channel.recv()
                            assert request.startswith(b"GET / HTTP/1.1\r\n")
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                            await channel.close()
                    except BaseException as error:
                        errors.append(repr(error))
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except ConnectionError:
                            pass
                        handlers.discard(asyncio.current_task())

                server = await asyncio.start_server(peer, "127.0.0.1", 0)
                try:
                    process = await asyncio.create_subprocess_exec(str(args.native.resolve()),
                        "--get-bootstrap", "localhost", str(server.sockets[0].getsockname()[1]),
                        str(root), f"{suite:x}", str(leaf), str(key), mode,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    output, error = await asyncio.wait_for(process.communicate(), 20)
                    if handlers:
                        await asyncio.gather(*handlers)
                    assert process.returncode == 0, (mode, suite, error, errors)
                    assert not errors, errors
                    assert [channel.resumed for channel in channels] == [False, True, True]
                    assert [channel.early_data_accepted for channel in channels] == [False, False, True]
                    assert [channel.bootstrap_authorization["fresh_client_possession"] for channel in channels] == [True, False, False]
                finally:
                    server.close()
                    await server.wait_closed()
        for fault in ("bad-proof", "bad-finished", "missing-client-request", "wrong-ca", "unknown-bsk"):
            mode = "validated" if fault == "wrong-ca" else "provisioning"
            root.write_bytes(unrelated.public_bytes(serialization.Encoding.DER))
            binding = BootstrapBinding(public, "localhost", "loopback-provisioning",
                "credential-validated" if mode == "validated" else "provisioning-trust")
            if fault == "unknown-bsk":
                other = x25519.X25519PrivateKey.generate()
                binding = replace(binding, spki=other.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            store, disclosed, handlers = TicketStore(), [], set()
            real_send, real_receive = Wire.send_frame, Wire.receive_frame
            async def modified_send(wire, message, state=None):
                if (fault == "bad-proof" and message[0] == 15) or (fault == "bad-finished" and message[0] == 20):
                    message = message[:-1] + bytes((message[-1] ^ 1,))
                return await real_send(wire, message, state)
            async def observe_receive(wire, *args, **kwargs):
                message = await real_receive(wire, *args, **kwargs)
                if message[0] in (11, 25):
                    disclosed.append(message)
                return message
            async def rejected_peer(reader, writer):
                handlers.add(asyncio.current_task())
                try:
                    async with asyncio.timeout(5):
                        if fault == "missing-client-request":
                            psk = bootstrap_public_key_psk(public[12:], "localhost")
                            channel = await server_handshake(reader, writer, credentials, "localhost",
                                                             external_psks=(psk,), ticket_store=store)
                        else:
                            channel = await bootstrap_server_handshake(reader, writer, credentials, binding,
                                                                       ticket_store=store)
                        raise AssertionError("invalid bootstrap unexpectedly established")
                except (ConnectionError, TimeoutError):
                    pass
                except Exception as error:
                    from tls20_server.errors import ProtocolError
                    assert isinstance(error, ProtocolError), error
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except ConnectionError:
                        pass
                    handlers.discard(asyncio.current_task())
            server = await asyncio.start_server(rejected_peer, "127.0.0.1", 0)
            try:
                with patch.object(Wire, "send_frame", modified_send), patch.object(Wire, "receive_frame", observe_receive):
                    process = await asyncio.create_subprocess_exec(str(args.native.resolve()),
                        "--get-bootstrap", "localhost", str(server.sockets[0].getsockname()[1]),
                        str(root), "1301", str(leaf), str(key), mode,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    output, error = await asyncio.wait_for(process.communicate(), 10)
                    if handlers:
                        await asyncio.gather(*handlers)
                    assert process.returncode != 0, (fault, output, error)
                    assert not disclosed, f"BSK disclosed before authenticated complete required bootstrap: {fault}"
                    assert not store._tickets, fault
            finally:
                server.close()
                await server.wait_closed()
    print("12 native bootstrap connections + 5 rejection gates: imported derivation, exact client RPK/MAC, both trust policies, SHA256/SHA384, resumption/0-RTT and no BSK disclosure on failed authentication passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
