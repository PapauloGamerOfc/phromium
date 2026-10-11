#!/usr/bin/env python3
"""Independent cryptography/OpenSSL oracle for the native BoringSSL CTv2 policy.

No public log/network dependency. Temporary test log keys are never installed as
browser/HTTPS trust; actual CT signatures and exact RFC9162 formats are verified.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile


def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import NameOID
    from tls20_server.pki import _children, _element
    from tls20_server.credential_evidence import _ocsp_transparency
    from tls20_server.transparency import (TrustedLog, _der, precertificate_tbs,
        validate_ct_v2_list, verify_inclusion, verify_consistency)

    vec = lambda value, width=2: len(value).to_bytes(width, 'big') + value
    listed = lambda *items: vec(b''.join(vec(item) for item in items))
    encoded = lambda cert: cert.public_bytes(serialization.Encoding.DER)
    spki = lambda key: key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    timestamp = int(now.timestamp() * 1000)
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), x25519.X25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Explicit CT oracle')])
    base = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1)))
    root = base.public_key(ca_key.public_key()).serial_number(1).add_extension(x509.BasicConstraints(True, None), True).sign(ca_key, hashes.SHA256())
    builder = base.public_key(leaf_key.public_key()).serial_number(2).add_extension(x509.BasicConstraints(False, None), True)
    cert = builder.sign(ca_key, hashes.SHA256())
    cases = 0
    with tempfile.TemporaryDirectory(prefix='httpps-ct-oracle-') as directory:
        folder = Path(directory)
        def run(argv, expected=0):
            nonlocal cases
            result = subprocess.run([str(args.binary.resolve()), *map(str, argv)], capture_output=True, text=True, timeout=15)
            assert result.returncode == expected, (argv, result.returncode, result.stdout, result.stderr)
            cases += 1

        def check(log, evidence, *, leaf=cert, issuer=root, response=b'', expected=0,
                  minimum=1, inclusion=False, mmd=False, moment=timestamp, expires=(1 << 64)-1, prior=None):
            files = {}
            for label, data in (('log', spki(log_key)), ('leaf', encoded(leaf)), ('issuer', encoded(issuer)), ('tls', evidence), ('ocsp', response)):
                path = folder / label
                path.write_bytes(data)
                files[label] = path
            argv = ['--verify', log.log_id.hex(), files['log'], f'{log.signature_scheme:x}', log.hash_name,
                moment, files['leaf'], files['issuer'], files['tls'], files['ocsp'], minimum, int(inclusion), int(mmd), expires]
            if prior:
                path = folder / 'prior'
                path.write_bytes(prior[2])
                argv += [path, prior[0], prior[1]]
            run(argv, expected)

        for scheme, algorithm, hash_name in ((0x0403, ec.SECP256R1(), 'sha256'),
                (0x0503, ec.SECP384R1(), 'sha384'), (0x0603, ec.SECP521R1(), 'sha512'),
                (0x0807, None, 'sha256'), (0x0804, 'rsa', 'sha256')):
            log_key = (ed25519.Ed25519PrivateKey.generate() if algorithm is None else
                       rsa.generate_private_key(65537, 2048) if algorithm == 'rsa' else ec.generate_private_key(algorithm))
            log = TrustedLog(bytes.fromhex('2b060104018237'), log_key.public_key(), scheme, hash_name)
            digest = getattr(hashes, hash_name.upper())()
            def sign(data):
                if scheme == 0x0807:
                    return log_key.sign(data)
                if algorithm == 'rsa':
                    return log_key.sign(data, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
                return log_key.sign(data, ec.ECDSA(digest))

            def sct(*, precert=False, extensions=b'', at=timestamp):
                tbs = precertificate_tbs(cert, version=2) if precert else cert.tbs_certificate_bytes
                signed = (0x101 if precert else 0x100).to_bytes(2, 'big') + at.to_bytes(8, 'big')
                signed += vec(hashlib.new(hash_name, spki(ca_key)).digest(), 1) + vec(tbs, 3) + vec(extensions)
                item = (0x103 if precert else 0x102).to_bytes(2, 'big') + vec(log.log_id, 1) + at.to_bytes(8, 'big') + vec(extensions) + vec(sign(signed))
                return item, hashlib.new(hash_name, b'\0' + signed).digest()

            item, leaf_hash = sct()
            source = listed(item)
            assert validate_ct_v2_list(source, encoded(cert), encoded(root), {log.log_id: log}, now_ms=timestamp)[0].leaf_hash == leaf_hash
            check(log, source)
            check(log, listed(item, item), minimum=2, expected=1)
            check(log, source, inclusion=True, expected=1)
            check(log, source, moment=timestamp-1, expected=1)
            check(log, source, expires=timestamp-1, expected=1)
            check(log, source[:-1] + bytes([source[-1] ^ 1]), expected=1)
            check(log, source + b'\0', expected=1)
            check(log, listed(b'\x03\x03unknown', item))
            check(log, listed(b'\x03\x03unknown'), expected=1)
            check(log, source, moment=timestamp+86400001, mmd=True, expected=1)
            malformed, _ = sct(extensions=b'\x00\x01\x00\x00' * 2)
            check(log, listed(malformed), expected=1)
            for precert in (False, True):
                sct_item, node = sct(precert=precert)
                head_data = timestamp.to_bytes(8, 'big') + (1).to_bytes(8, 'big') + vec(node, 1) + b'\0\0'
                head = b'\x01\x04' + vec(log.log_id, 1) + head_data + vec(sign(head_data))
                proof = b'\x01\x06' + vec(log.log_id, 1) + (1).to_bytes(8, 'big') + bytes(8) + b'\0\0'
                source = listed(proof, head, sct_item)
                oracle = validate_ct_v2_list(source, encoded(cert), encoded(root), {log.log_id: log}, now_ms=timestamp, require_inclusion=True)
                assert oracle[0].included
                check(log, source, inclusion=True)
                check(log, source, inclusion=True, prior=(1, timestamp, node))
                check(log, source, prior=(2, timestamp, node), expected=1)
                check(log, listed(proof, head[:-1] + bytes([head[-1]^1]), sct_item), inclusion=True, expected=1)

            # The embedded certificate is reconstructed exactly, retaining its
            # original serial/time/extensions, then re-signed by the CA.
            pre_item, _ = sct(precert=True)
            embedded = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.101.75'), _der(4, listed(pre_item))), False).sign(ca_key, hashes.SHA256())
            assert precertificate_tbs(embedded, version=2) == cert.tbs_certificate_bytes
            check(log, b'', leaf=embedded)
            wrong_embedded = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.101.75'), _der(4, listed(item))), False).sign(ca_key, hashes.SHA256())
            check(log, b'', leaf=wrong_embedded, expected=1)

            # OCSP's CT information belongs to SingleResponse extensions. Build
            # and actually sign that envelope independently of the native parser.
            response = (ocsp.OCSPResponseBuilder().add_response(cert=cert, issuer=root, algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.GOOD, this_update=now, next_update=now+timedelta(hours=1),
                revocation_time=None, revocation_reason=None).responder_id(ocsp.OCSPResponderEncoding.HASH, root).sign(ca_key, hashes.SHA256()))
            fields = _children(_element(response.tbs_response_bytes)[1])
            response_index = 3 if fields[0][0] == 0xa0 else 2
            singles = _children(fields[response_index][1])
            ct_extension = _der(0x30, _der(6, bytes.fromhex('2b654b')) + _der(4, _der(4, listed(item))))
            changed = _der(0x30, singles[0][1] + _der(0xa1, _der(0x30, ct_extension)))
            tbs = _der(0x30, b''.join(_der(0x30, changed) if i == response_index else raw for i, (_, _, raw) in enumerate(fields)))
            outer_fields = _children(_element(encoded(response))[1])
            response_bytes = _children(_element(outer_fields[1][1])[1])
            basic = _children(_element(response_bytes[1][1])[1])
            signed = _der(0x30, tbs + basic[1][2] + _der(3, b'\0' + ca_key.sign(tbs, ec.ECDSA(hashes.SHA256()))))
            envelope = _der(0x30, outer_fields[0][2] + _der(0xa0, _der(0x30, response_bytes[0][2] + _der(4, signed))))
            assert _ocsp_transparency(envelope, cert, root)[52] == listed(item)
            check(log, b'', response=envelope)
            check(log, b'', response=envelope, issuer=cert, expected=1)

        # Exhaustive small unbalanced trees, independent recursive path oracle.
        for hash_name in ('sha256', 'sha384', 'sha512'):
            digest_bytes = lambda data: hashlib.new(hash_name, data).digest()
            leaves = [digest_bytes(b'\0' + bytes([i])) for i in range(9)]
            def tree(values):
                if not values: return digest_bytes(b'')
                if len(values) == 1: return values[0]
                split = 1 << ((len(values)-1).bit_length()-1)
                return digest_bytes(b'\1' + tree(values[:split]) + tree(values[split:]))
            def path(values, index):
                if len(values) == 1: return []
                split = 1 << ((len(values)-1).bit_length()-1)
                return (path(values[:split], index) + [tree(values[split:])] if index < split else
                        path(values[split:], index-split) + [tree(values[:split])])
            def consistency(values, count, complete=True):
                if count == len(values): return [] if complete else [tree(values)]
                split = 1 << ((len(values)-1).bit_length()-1)
                return (consistency(values[:split], count, complete) + [tree(values[split:])] if count <= split else
                        consistency(values[split:], count-split, False) + [tree(values[:split])])
            for size in range(1, 10):
                root_hash = tree(leaves[:size])
                for index in range(size):
                    proof = path(leaves[:size], index)
                    assert verify_inclusion(leaves[index], index, size, proof, root_hash, hash_name=hash_name)
                    argv = ['--inclusion', hash_name, leaves[index].hex(), index, size, root_hash.hex()]
                    run([*argv, 1, *[p.hex() for p in proof]])
                    run([*argv, 0, *[p.hex() for p in proof], leaves[0].hex()])
                for count in range(1, size+1):
                    proof = consistency(leaves[:size], count)
                    old = tree(leaves[:count])
                    assert verify_consistency(count, size, old, root_hash, proof, hash_name=hash_name)
                    run(['--consistency', hash_name, count, size, old.hex(), root_hash.hex(), 1, *[p.hex() for p in proof]])
        print(f'CTv2 native/server oracle: {cases} checks passed (5 signature keys, 3 hashes, TLS/cert/OCSP, Merkle).')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--server-source', type=Path, required=True)
    main(parser.parse_args())
