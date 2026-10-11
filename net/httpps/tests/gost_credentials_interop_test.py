#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Independent GOST certificate/grant signatures with strict native PKIX."""
import argparse
import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
import sys


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    os.environ.update(TLS20_TEST_OPENSSL=str(args.provider.resolve()),
                      TLS20_TEST_GOST_MODULE=str(args.module.resolve()),
                      TLS20_TEST_OPENSSL_CLI=str(args.openssl.resolve()))
    from cryptography.hazmat.primitives import serialization
    from tests.test_gost_credentials import GOSTCredentialTests
    from tls20_server.handshake import server_handshake
    from tls20_server.pki import Credentials
    from tls20_server.tickets import TicketStore
    connections = 0
    for group in range(34, 41):
        fixture = GOSTCredentialTests()
        fixture.setUp()
        try:
            fixture.create_chain(group)
            root = fixture.work / "root.der"
            root.write_bytes(fixture.der(fixture.root))
            cases = ["valid"]
            if group in (34, 38):
                cases += ["delegated", "tampered-cert", "tampered-grant", "reversed-grant",
                          "wrong-ku", "wrong-eku", "unknown-critical"]
                fixture.run_cli("pkey", "-in", "root.key", "-pubout", "-out", "parent.pub")
                fixture.issue("parent", "parent.pub", "digitalSignature", "1.3.6.1.4.1.44363.44=DER:05:00\n")
                parent = fixture.cert("parent")
                public = fixture.key.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                duration = int((datetime.now(timezone.utc) - parent.not_valid_before_utc).total_seconds()) + 600
                signed = (duration.to_bytes(4, "big") + b"\xfe\x00" + len(public).to_bytes(3, "big") +
                          public + fixture.scheme.to_bytes(2, "big"))
                fixture.write("message.bin", b" " * 64 + b"TLS20 server delegated credentials\0" + fixture.der(parent) + signed)
                fixture.run_cli("dgst", "-" + fixture.hash, "-sign", "root.key", "-out", "signature.bin", "message.bin")
                signature = (fixture.work / "signature.bin").read_bytes()[::-1]
                grant = signed + len(signature).to_bytes(2, "big") + signature
                fixture.issue("wrong-ku", "leaf.pub", "digitalSignature")
                fixture.issue("wrong-eku", "leaf.pub", "keyAgreement", eku="clientAuth")
                fixture.issue("unknown-critical", "leaf.pub", "keyAgreement", "1.2.3.99=critical,DER:05:00\n")
            for case in cases:
                delegated = case in ("delegated", "tampered-grant", "reversed-grant")
                leaf = fixture.der(parent if delegated else fixture.cert(case) if case.startswith("wrong-") or case == "unknown-critical" else fixture.leaf)
                selected_grant = grant if delegated else b""
                if case == "tampered-cert":
                    leaf = leaf[:-1] + bytes([leaf[-1] ^ 1])
                elif case == "tampered-grant":
                    selected_grant = selected_grant[:-1] + bytes([selected_grant[-1] ^ 1])
                elif case == "reversed-grant":
                    selected_grant = signed + len(signature).to_bytes(2, "big") + signature[::-1]
                # Issuer metadata is local selection information, never part of
                # the sent chain or a replacement for the client's trust root.
                credentials = Credentials([leaf], fixture.key, delegation=selected_grant,
                    signature_issuers=(fixture.der(fixture.root),))
                store, errors, seen, tasks = TicketStore(), [], [], set()

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    tasks.add(task)
                    early_data = []
                    async def early(data):
                        early_data.append(data)
                    try:
                        async with asyncio.timeout(8):
                            channel = await server_handshake(reader, writer, credentials, "example.test",
                                native_provider=fixture.provider, cipher_suites=(0xc103,), ticket_store=store,
                                max_early_data=16384, on_early_data=early)
                            request = b"".join(early_data) or await channel.recv()
                            assert request.startswith(b"GET / HTTP/1.1\r\n")
                            seen.append((channel.resumed, channel.early_data_accepted))
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                            await channel.close()
                    except BaseException as error:
                        errors.append(repr(error))
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except (ConnectionError, OSError):
                            pass
                        tasks.discard(task)

                listener = await asyncio.start_server(peer, "127.0.0.1", 0)
                try:
                    process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-gost",
                        "example.test", str(listener.sockets[0].getsockname()[1]), str(root),
                        str(args.provider.resolve()), str(args.module.resolve()), "c103", str(group),
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    try:
                        output, error = await asyncio.wait_for(process.communicate(), 25)
                    except BaseException:
                        if process.returncode is None:
                            process.kill()
                        await process.wait()
                        raise
                    if tasks:
                        await asyncio.gather(*tasks)
                    if case in ("valid", "delegated"):
                        assert process.returncode == 0 and not errors, (group, case, output, error, errors)
                        assert seen == [(False, False), (True, False), (True, True)], seen
                        connections += 3
                    else:
                        assert process.returncode != 0 and not seen, (group, case, output, error, seen)
                        assert not any("TypeError" in value or "AttributeError" in value for value in errors), errors
                        connections += 1
                finally:
                    listener.close()
                    await listener.wait_closed()
        finally:
            fixture.doCleanups()
    print(f"{connections} native GOST credential connections passed: all 7 signing curves, delegation, resumption/early and strict PKIX negatives")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("native", "server-source", "provider", "module", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
