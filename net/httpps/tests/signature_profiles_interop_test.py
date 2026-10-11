#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Native Ed448, Brainpool and constrained RSA-PSS credential interoperability."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, rsa
    from tests.test_pki import der, issue
    from tests.test_signature_profiles import SignatureProfiles, pss_parameters
    from tls20_server.handshake import server_handshake
    from tls20_server.credential_profiles import DELEGATION_USAGE
    from tls20_server.pki import Credentials
    from tls20_server.tickets import TicketStore

    profiles = [(0x0808, ed448.Ed448PrivateKey.generate(), None)]
    profiles += [(scheme, ec.generate_private_key(curve), digest) for scheme, curve, digest in (
        (0x081a, ec.BrainpoolP256R1(), hashes.SHA256()),
        (0x081b, ec.BrainpoolP384R1(), hashes.SHA384()),
        (0x081c, ec.BrainpoolP512R1(), hashes.SHA512()))]
    profiles += [(scheme, rsa.generate_private_key(public_exponent=65537, key_size=2048), digest)
                 for scheme, digest in ((0x0809, hashes.SHA256()),
                                        (0x080a, hashes.SHA384()),
                                        (0x080b, hashes.SHA512()))]
    connections = 0
    with tempfile.TemporaryDirectory(prefix="httpps-signatures-") as directory:
        root_file = Path(directory) / "root.der"
        for scheme, signing_key, digest in profiles:
            fixture = SignatureProfiles()
            fixture.setUp()
            def signing_parent(key):
                return issue(key, fixture.ca_key, fixture.peer_name, fixture.name,
                    key_usage=x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                    extra=[(x509.UnrecognizedExtension(DELEGATION_USAGE, b"\x05\x00"), False),
                           (x509.AuthorityKeyIdentifier.from_issuer_public_key(fixture.ca_key.public_key()), False)])
            fixture.parent = signing_parent
            restricted = 0x0809 <= scheme <= 0x080b
            parent = (fixture.pss_parent(signing_key, pss_parameters(
                hash_number=scheme - 0x0808, mgf_number=scheme - 0x0808,
                salt=digest.digest_size)) if restricted else fixture.parent(signing_key))
            if scheme == 0x0808:
                public = fixture.proof_key.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                body = (3900).to_bytes(4, "big") + b"\xfe\x00" + len(public).to_bytes(3, "big") + public + scheme.to_bytes(2, "big")
                message = b" " * 64 + b"TLS20 server delegated credentials\0" + der(parent) + body
                signature = signing_key.sign(message)
                grant = body + len(signature).to_bytes(2, "big") + signature
            else:
                grant = fixture.grant(parent, signing_key, scheme, digest)
            cases = ["delegated", "tampered-grant"]
            if restricted:
                cases += ["rsae-as-pss", "wrong-restrictions"]
            else:
                cases += ["certificate", "tampered-certificate"]
            for case in cases:
                selected_grant = grant
                selected_parent = parent
                trusted_root = fixture.root
                if case in ("certificate", "tampered-certificate"):
                    trusted_root = issue(signing_key, signing_key, fixture.name, fixture.name,
                                         ca=True, algorithm=digest)
                    selected_parent = issue(fixture.proof_key, signing_key, fixture.peer_name,
                        fixture.name, algorithm=digest,
                        extra=[(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), False)])
                    selected_grant = b""
                elif case == "rsae-as-pss":
                    selected_parent = fixture.parent(signing_key)
                    selected_grant = fixture.grant(selected_parent, signing_key, scheme, digest)
                elif case == "wrong-restrictions":
                    selected_parent = fixture.pss_parent(signing_key, pss_parameters(
                        hash_number=scheme - 0x0808, mgf_number=scheme - 0x0808,
                        salt=digest.digest_size + 1))
                    selected_grant = fixture.grant(selected_parent, signing_key, scheme, digest)
                elif case == "tampered-grant":
                    selected_grant = grant[:-1] + bytes([grant[-1] ^ 1])
                certificate = der(selected_parent)
                if case == "tampered-certificate":
                    certificate = certificate[:-1] + bytes([certificate[-1] ^ 1])
                root_file.write_bytes(der(trusted_root))
                if case == "delegated":
                    parent_file, grant_file = Path(directory) / "parent.der", Path(directory) / "grant.bin"
                    parent_file.write_bytes(certificate)
                    grant_file.write_bytes(selected_grant)
                    check = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--check-delegated-credential",
                        str(parent_file), str(root_file), str(grant_file), str(args.provider.resolve()),
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    try:
                        checked, failure = await asyncio.wait_for(check.communicate(), 10)
                    except BaseException:
                        if check.returncode is None:
                            check.kill()
                        await check.wait()
                        raise
                    assert check.returncode == 0, (hex(scheme), checked, failure)
                # Deliberately omit the issuer: algorithm selection must use the
                # validated path, not insist that the peer sends our trust root.
                credentials = Credentials([certificate], fixture.proof_key, delegation=selected_grant)
                store, tasks, seen, errors = TicketStore(), set(), [], []

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    tasks.add(task)
                    early_bytes = []
                    async def early(data):
                        early_bytes.append(data)
                    try:
                        async with asyncio.timeout(8):
                            channel = await server_handshake(reader, writer, credentials, "example.test",
                                ticket_store=store, max_early_data=16384, on_early_data=early)
                            request = b"".join(early_bytes) or await channel.recv()
                            assert request.startswith(b"GET / HTTP/1.1\r\n"), request
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
                    process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-public-signature",
                        "example.test", str(listener.sockets[0].getsockname()[1]), str(root_file), str(args.provider.resolve()),
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
                    if case in ("certificate", "delegated"):
                        assert process.returncode == 0 and not errors, (hex(scheme), case, output, error, errors)
                        assert seen == [(False, False), (True, False), (True, True)], seen
                        connections += 3
                    else:
                        assert process.returncode != 0 and not seen, (hex(scheme), case, output, error, seen)
                        assert not any("TypeError" in value or "AttributeError" in value for value in errors), errors
                        connections += 1
                finally:
                    listener.close()
                    await listener.wait_closed()
                    for task in tuple(tasks):
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
    print(f"{connections} native public-signature connections passed: Ed448, Brainpool, constrained RSA-PSS, omitted issuers and negative proofs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("native", "server-source", "provider"):
        parser.add_argument("--" + name, type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
