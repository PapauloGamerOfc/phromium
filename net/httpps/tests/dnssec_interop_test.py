#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Real DANE handshakes: no caller-supplied success booleans or implicit pins."""
import argparse
import asyncio
from dataclasses import replace
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import time


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    import dns.dnssec
    import dns.name
    import dns.rrset
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.pki import Credentials
    from tls20_server.tickets import TicketStore

    credentials, ca = generate_lab_credentials('localhost')
    dns_key = ed25519.Ed25519PrivateKey.generate()
    root_name = dns.name.root
    dnskey = dns.dnssec.make_dnskey(dns_key.public_key(), 'ED25519', flags=257)
    keys = dns.rrset.from_rdata(root_name, 300, dnskey)
    leaf_spki = credentials.private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ca_spki = ca.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())
    def wire(*records):
        output = io.BytesIO()
        for rrset in records: rrset.to_wire(output, compress=None)
        return output.getvalue()
    def sign(rrset, expired=False):
        signature = dns.dnssec.sign(rrset, dns_key, root_name, dnskey,
            inception=now-100, expiration=now-1 if expired else now+3600)
        return rrset, dns.rrset.from_rdata(rrset.name, rrset.ttl, signature)
    count = 0
    with tempfile.TemporaryDirectory(prefix='httpps-dane-') as directory:
        base = Path(directory)
        root, anchor = base/'root.der', base/'dns-anchors.rr'
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        anchor.write_bytes(wire(keys))
        for mode, usage, case in (
            ('certificate', 0, 'valid'), ('certificate', 1, 'valid'),
            ('certificate', 2, 'valid'), ('certificate', 3, 'valid'), ('raw', 3, 'valid'),
            ('certificate', 3, 'missing'), ('raw', 3, 'missing'),
            ('certificate', 3, 'expired'), ('raw', 3, 'tampered'),
            ('certificate', 3, 'wrong-port'), ('raw', 3, 'wrong-association'),
        ):
            store, errors, observed, tasks = TicketStore(), [], [], set()
            selected = None
            async def peer(reader, writer):
                task = asyncio.current_task(); tasks.add(task)
                early = []
                async def receive_early(data): early.append(data)
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, selected, 'localhost',
                            ticket_store=store, max_early_data=16384, on_early_data=receive_early)
                        request = b''.join(early) or await channel.recv()
                        assert request.startswith(b'GET / HTTP/1.1\r\n')
                        observed.append((channel.resumed, channel.early_data_accepted))
                        await channel.send(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
                        await channel.close()
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    try: await writer.wait_closed()
                    except (ConnectionError, OSError): pass
                    tasks.discard(task)
            server = await asyncio.start_server(peer, '127.0.0.1', 0)
            try:
                port = server.sockets[0].getsockname()[1]
                data = ca_spki if usage in (0,2) else leaf_spki
                if case == 'wrong-association': data = ca_spki
                record = dns.rrset.from_text(f'_{port if case != "wrong-port" else 343}._tcp.localhost.',
                    300, 'IN', 'TLSA', f'{usage} 1 1 '+hashlib.sha256(data).hexdigest())
                chain = wire(*sign(keys), *sign(record, expired=case == 'expired'))
                if case == 'tampered': chain = chain[:-1] + bytes((chain[-1]^1,))
                evidence = b'\0\x18' + len(chain).to_bytes(2,'big') + chain
                material = credentials.chain_der if mode == 'certificate' else [leaf_spki]
                metadata = (((59,evidence),),) + ((),)*(len(material)-1)
                selected = Credentials(material, credentials.private_key,
                    credential_type=0 if mode == 'certificate' else 2,
                    entry_extensions=() if case == 'missing' else metadata,
                    dnssec_service=('localhost',port))
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()), '--get-dane',
                    'localhost', str(port), str(root), str(args.getdns.resolve()), str(anchor), mode,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(),25)
                except BaseException:
                    if process.returncode is None: process.kill()
                    await process.wait()
                    raise
                if tasks: await asyncio.gather(*tasks)
                if case == 'valid':
                    assert process.returncode == 0 and not errors, (mode,usage,case,output,error,errors)
                    assert observed == [(False,False),(True,False),(True,True)], (mode,usage,observed)
                    count += 3
                else:
                    assert process.returncode != 0 and not observed, (mode,case,error,observed)
                    count += 1
            finally:
                server.close(); await server.wait_closed()
                if tasks: await asyncio.gather(*tasks)
    print(f'{count} native DANE handshake cases passed (full/resume/0-RTT and fail-closed evidence)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--server-source',type=Path,required=True)
    parser.add_argument('--getdns',type=Path,required=True)
    asyncio.run(main(parser.parse_args()))
