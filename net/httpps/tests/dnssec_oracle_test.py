#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Independent signed DNSSEC fixtures exercised by the native offline provider."""
import argparse
import hashlib
import io
from pathlib import Path
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone

import dns.dnssec
import dns.name
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.x509.oid import NameOID


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', required=True)
    parser.add_argument('--getdns', required=True)
    args = parser.parse_args()
    native, provider = str(Path(args.native).resolve()), str(Path(args.getdns).resolve())
    now = int(time.time())
    root, zone = dns.name.root, dns.name.from_text('example.test.')
    root_key, zone_key = ed25519.Ed25519PrivateKey.generate(), ec.generate_private_key(ec.SECP256R1())
    root_dnskey = dns.dnssec.make_dnskey(root_key.public_key(), 'ED25519', flags=257)
    zone_dnskey = dns.dnssec.make_dnskey(zone_key.public_key(), 'ECDSAP256SHA256', flags=257)
    root_keys = dns.rrset.from_rdata(root, 300, root_dnskey)
    zone_keys = dns.rrset.from_rdata(zone, 300, zone_dnskey)
    ds = dns.rrset.from_rdata(zone, 300, dns.dnssec.make_ds(zone, zone_dnskey, 'SHA256'))
    spki = x25519.X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    cert_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.test')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(cert_key.public_key())
            .serial_number(1).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('example.test')]), False)
            .sign(cert_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    cert_spki = cert_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    owner = '_343._tcp.example.test.'
    def sign(rrset, *, root_signer=False, expired=False):
        key, dnskey, signer = (root_key, root_dnskey, root) if root_signer else (zone_key, zone_dnskey, zone)
        sig = dns.dnssec.sign(rrset, key, signer, dnskey, inception=now-100,
                             expiration=now-1 if expired else now+3600)
        return rrset, dns.rrset.from_rdata(rrset.name, rrset.ttl, sig)
    def wire(*rrsets):
        output = io.BytesIO()
        for record in rrsets:
            record.to_wire(output, compress=None)
        return output.getvalue()
    prefix = (*sign(root_keys, root_signer=True), *sign(ds, root_signer=True), *sign(zone_keys))
    def chain(*records): return wire(*prefix, *records)
    def tlsa(host=owner, usage=3, selector=1, matching=1, data=spki):
        association = (hashlib.sha256(data).digest() if matching == 1 else
                       hashlib.sha512(data).digest() if matching == 2 else data)
        return dns.rrset.from_text(host, 300, 'IN', 'TLSA', f'{usage} {selector} {matching} {association.hex()}')
    def envelope(raw, lifetime=24): return lifetime.to_bytes(2, 'big') + len(raw).to_bytes(2, 'big') + raw
    checks = 0
    with tempfile.TemporaryDirectory(prefix='httpps-dnssec-') as directory:
        base = Path(directory)
        def check(label, evidence, *, expected=0, expected_usage=3, material=spki, ctype=2,
                  port=343, hostname='example.test', anchors=None, at=now, denial=False, callback=0,
                  expected_error=None):
            nonlocal checks
            (base/'anchors').write_bytes(wire(root_keys) if anchors is None else anchors)
            (base/'evidence').write_bytes(evidence)
            (base/'material').write_bytes(material)
            run = subprocess.run([native, provider, str(base/'anchors'), hostname, str(port), str(at),
                                  str(base/'evidence'), str(base/'material'), str(ctype), str(int(denial)), str(callback)],
                                 capture_output=True, text=True, timeout=15)
            assert run.returncode == expected, (label, run.returncode, run.stdout, run.stderr)
            if expected_error is not None:
                assert expected_error in run.stderr, (label, run.stderr)
            if expected == 0:
                usage, expiry, lifetime = map(int, run.stdout.split())
                assert usage == expected_usage and at <= expiry <= at+300, (label, run.stdout)
            checks += 1
        valid_raw = chain(*sign(tlsa()))
        valid = envelope(valid_raw)
        check('signed Ed25519 root + ECDSA zone + raw key', valid)
        check('DNS names case insensitive', valid, hostname='ExAmPlE.TeSt')
        check('zone DNSKEY anchor', valid, anchors=wire(zone_keys))
        check('zone DS anchor', valid, anchors=wire(ds))
        for matching in (0, 1, 2):
            check(f'RPK match {matching}', envelope(chain(*sign(tlsa(matching=matching)))))
            for selector in (0, 1):
                data = cert if selector == 0 else cert_spki
                check(f'X509 selector {selector} match {matching}', envelope(chain(*sign(tlsa(selector=selector, matching=matching, data=data)))), material=cert, ctype=0)
        for lifetime in (0, 1, 65535): check('support lifetime not TTL', envelope(valid_raw, lifetime))
        for label, kwargs in [('wrong port', {'port':443}), ('wrong name', {'hostname':'other.test'}),
                              ('expired signatures', {'at':now+4000}), ('wrong material', {'material':cert_spki}),
                              ('junk SPKI', {'material':spki+b'\0'})]:
            check(label, valid, expected=1, **kwargs)
        check('unsigned TLSA', envelope(chain(tlsa())), expected=1)
        check('expired TLSA cannot use lifetime promise', envelope(chain(*sign(tlsa(), expired=True)),65535), expected=1)
        fake = dns.rrset.from_rdata(root, 300, dns.dnssec.make_dnskey(ed25519.Ed25519PrivateKey.generate().public_key(), 'ED25519', flags=257))
        check('wrong trust anchor', valid, anchors=wire(fake), expected=1)
        for offset in (0, len(valid_raw)//2, len(valid_raw)-1):
            damaged = bytearray(valid_raw); damaged[offset] ^= 1
            check('tampered chain', envelope(damaged), expected=1)
        for evidence in (b'', valid[:-1], valid+b'\0', valid_raw, b'\0\0'+valid_raw):
            check('malformed envelope', evidence, expected=1)
        check('compressed owner', envelope(b'\xc0\0'+valid_raw[1:]), expected=1)
        check('resource cap', envelope(valid_raw*20), expected=1)
        # Stay below the record/byte caps but exceed the separate estimated
        # key x signature x RRset work budget.
        many_keys = wire(*([root_keys]*480))
        check('key/signature work amplification rejected', envelope(valid_raw+many_keys), expected=1,
              expected_error='resource limit')
        target = '_343._tcp.target.example.test.'
        cname = dns.rrset.from_text(owner,300,'IN','CNAME',target)
        check('signed CNAME', envelope(chain(*sign(cname),*sign(tlsa(target)))))
        check('unsigned CNAME', envelope(chain(cname,*sign(tlsa(target)))), expected=1)
        loop = dns.rrset.from_text(target,300,'IN','CNAME',owner)
        check('CNAME loop', envelope(chain(*sign(cname),*sign(loop))), expected=1)
        dname = dns.rrset.from_text('_tcp.example.test.',300,'IN','DNAME','_tcp.target.example.test.')
        check('signed DNAME + locally synthesized CNAME', envelope(chain(*sign(dname),*sign(tlsa(target)))))
        check('unsigned DNAME', envelope(chain(dname,*sign(tlsa(target)))), expected=1)
        wild, sig = sign(tlsa('*.example.test.')); wild.name = sig.name = dns.name.from_text(owner)
        check('wildcard missing denial', envelope(chain(wild,sig)), expected=1)
        nsec = dns.rrset.from_text('*.example.test.',300,'IN','NSEC','z.example.test. TLSA RRSIG NSEC')
        check('wildcard with denial', envelope(chain(wild,sig,*sign(nsec))))
        nsec = dns.rrset.from_text(owner,300,'IN','NSEC','z.example.test. A RRSIG NSEC')
        check('authenticated NODATA disallowed', envelope(chain(*sign(nsec))), expected=1)
        check('authenticated NODATA explicit fallback', envelope(chain(*sign(nsec))), denial=True, expected_usage=-1)
        check('unsigned NODATA cannot permit fallback', envelope(chain(nsec)), denial=True, expected=1)
        for iterations in (0, 1, 150, 151):
            hashed = dns.dnssec.nsec3_hash(owner,b'',iterations,1)
            proof = dns.rrset.from_text(hashed+'.example.test.',300,'IN','NSEC3',f'1 0 {iterations} - {hashed} A RRSIG')
            check('NSEC3 no data or work limit',envelope(chain(*sign(proof))),denial=True,expected_usage=-1,expected=0 if iterations<=150 else 1)
        # Many individually permitted salts must not multiply the synchronous
        # provider's SHA-1 work without a separate aggregate budget. This stays
        # within all record/signature/key cross-product limits.
        expensive = []
        for salt in range(12):
            salt_bytes = bytes([salt])
            hashed = dns.dnssec.nsec3_hash(owner, salt_bytes, 150, 1)
            proof = dns.rrset.from_text(hashed+'.example.test.',300,'IN','NSEC3',
                                      f'1 0 150 {salt_bytes.hex()} {hashed} A RRSIG')
            expensive.extend(sign(proof))
        check('NSEC3 aggregate work rejected', envelope(chain(*expensive)), denial=True,
              expected=1, expected_error='resource limit')
        for usage in (0,1,2,4):
            proof = envelope(chain(*sign(tlsa(usage=usage,data=cert_spki))))
            check('not an EE pin without path validation',proof,material=cert,ctype=0,expected=1)
        pkix = envelope(chain(*sign(tlsa(usage=1,data=cert_spki))))
        check('PKIX-EE explicit validated path',pkix,material=cert,ctype=0,callback=1,expected_usage=1)
        check('PKIX-EE callback rejected',pkix,material=cert,ctype=0,callback=2,expected=1)
        check('RPK cannot be PKIX-EE',envelope(chain(*sign(tlsa(usage=1)))),callback=1,expected=1)
        for selector, matching in ((2,1),(1,3)):
            check('unsupported association',envelope(chain(*sign(tlsa(selector=selector,matching=matching)))),expected=1)
    print(f'{checks} native DNSSEC/DANE oracle checks passed')


if __name__ == '__main__':
    main()
