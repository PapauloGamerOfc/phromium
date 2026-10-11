#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Initial client MAC authentication and optional refusal over real loopback TCP."""

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from tls20_server.errors import ProtocolError
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.tickets import TicketStore

    credentials, ca = generate_lab_credentials("localhost")
    issuer = ed25519.Ed25519PrivateKey.generate()
    private = x25519.X25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "authorized fixture user")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(False, None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, True, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(issuer, algorithm=None))
    der = cert.public_bytes(serialization.Encoding.DER)
    with tempfile.TemporaryDirectory(prefix="httpps-client-auth-") as directory:
        root, leaf, key = [Path(directory) / filename for filename in ("root.der", "client.der", "client.raw")]
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        leaf.write_bytes(der)
        key.write_bytes(private.private_bytes_raw())
        for selected, required, authorized, resume in (
                (False, False, False, False), (False, True, False, False),
                (True, False, True, False), (True, True, True, False),
                (True, True, False, False), (True, True, True, True)):
            errors, identities, handlers = [], [], set()
            store = TicketStore()

            def validate(chain):
                if not authorized or chain != [der]:
                    raise ProtocolError("client not authorized by fixture policy")
                issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
                assert cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
                return cert.public_key()

            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                early = []
                async def on_early(data):
                    early.append(data)
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, credentials, "localhost",
                                                         client_auth_validator=validate,
                                                         require_client_auth=required,
                                                         ticket_store=store if resume else None,
                                                         max_early_data=16384,
                                                         on_early_data=on_early)
                        identities.append(channel.authenticated_client)
                        request = b"".join(early) or await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1\r\n")
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                           b"Connection: close\r\n\r\nOK")
                        await channel.close()
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    await writer.wait_closed()
                    handlers.discard(task)

            server = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                mode = "--get-client-auth-resume" if resume else "--get-client-auth" if selected else "--get"
                command = [str(args.native.resolve()), mode,
                           "localhost", str(server.sockets[0].getsockname()[1]), str(root)]
                if selected:
                    command.extend((str(leaf), str(key)))
                process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                                                               stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 20)
                except BaseException:
                    process.kill()
                    await process.wait()
                    raise
                if handlers:
                    await asyncio.gather(*handlers)
                success = (selected and authorized) or (not selected and not required)
                assert (process.returncode == 0) == success, (command, error, errors)
                if success:
                    assert not errors and b"HTTP/1.1 200 OK" in output, errors
                    assert identities == [tuple([der]) if selected else None] * (3 if resume else 1), identities
                else:
                    assert errors and not identities, (errors, identities)
            finally:
                server.close()
                await server.wait_closed()
        print("6 native client-auth cases passed: optional/required refusal, MAC identity, authorization failure, resumed identity/0-RTT/removal")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
