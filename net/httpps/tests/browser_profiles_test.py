#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Production browser profile provisioning, over real browser loopback sockets.

Only ephemeral fixture keys are generated; no OS trust changes or certificate
bypasses, no sandbox disable flag, and no secrets on command lines.
"""
import argparse
import asyncio
import base64
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from browser_e2e_test import Browser, Fixtures, HOST, close_writer


def b64(value):
    return base64.b64encode(value).decode("ascii")


@contextmanager
def provider_staging_directory(browser):
    # Windows tempfile directories deliberately install a private DACL. These
    # public test libraries instead need the browser output's inherited read /
    # execute access for its sandbox. Keep profile credentials in tempfile's
    # private directory; never write them into this public-library directory.
    parent = browser.resolve().parent
    directory = parent / ("httpps-provider-fixture-" + uuid.uuid4().hex)
    directory.mkdir()
    try:
        yield directory
    finally:
        if directory.is_symlink() or directory.resolve() != directory or directory.parent != parent:
            raise AssertionError("Provider staging cleanup escaped its browser output")
        shutil.rmtree(directory)


def stage_library(source, directory):
    staged = Path(directory) / Path(source).name
    # Copy only bytes into a new file. CopyFile2/copystat metadata propagation
    # can preserve a source DACL instead of the browser output's inherited ACL.
    shutil.copyfile(source, staged)
    if sys.platform == "win32":
        environment = dict(os.environ, HTTPPS_STAGED_FIXTURE=str(staged))
        script = (
            "$ErrorActionPreference = 'Stop'; "
            "Import-Module ($PSHOME + '/Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1'); "
            "$acl = Get-Acl -LiteralPath $env:HTTPPS_STAGED_FIXTURE; "
            "$sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-15-2-2'); "
            "$rx = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute; "
            "$match = @($acl.GetAccessRules($true, $true, $sid.GetType()) | "
            "Where-Object { $_.IdentityReference -eq $sid -and $_.IsInherited -and "
            "$_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $rx) -eq $rx }); "
            "[Console]::WriteLine([bool]($match.Count -gt 0))"
        )
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                env=environment, capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise RuntimeError("Unable to query staged-library ACL diagnostic")
        assert result.stdout.strip() in ("True", "False"), "Unexpected ACL diagnostic"
        print("Staged provider", staged.name, "restricted AppContainer inherited read/execute:",
              result.stdout.strip(), flush=True)
    return staged


def ct_fixture(credentials, root, tampered):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    def vec(value, width=2):
        return len(value).to_bytes(width, "big") + value
    certificate = x509.load_der_x509_certificate(credentials.chain_der[0])
    issuer = x509.load_der_x509_certificate(root).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key = ec.generate_private_key(ec.SECP256R1())
    now = int(time.time() * 1000)
    entry = b"\x01\x00" + now.to_bytes(8, "big") + vec(hashlib.sha256(issuer).digest(), 1)
    entry += vec(certificate.tbs_certificate_bytes, 3) + b"\x00\x00"
    signature = key.sign(entry, ec.ECDSA(hashes.SHA256()))
    if tampered:
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    log_id = bytes.fromhex("2b06010401")
    sct = b"\x01\x02" + vec(log_id, 1) + now.to_bytes(8, "big") + b"\x00\x00" + vec(signature)
    credentials = replace(credentials, entry_extensions=(((52, vec(vec(sct))),),))
    policy = {"minimum_logs": 1, "logs": [{"id": b64(log_id), "public_key_spki": b64(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))}]}
    return credentials, policy


def dane_fixture(credentials, host, port, wrong_association):
    import dns.dnssec
    import dns.name
    import dns.rrset
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    dnskey = dns.dnssec.make_dnskey(key.public_key(), "ED25519", flags=257)
    keys = dns.rrset.from_rdata(dns.name.root, 300, dnskey)
    spki = credentials.private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(spki).digest() if not wrong_association else bytes(32)
    tlsa = dns.rrset.from_text(f"_{port}._tcp.{host}.", 300, "IN", "TLSA", "3 1 1 " + digest.hex())
    now = int(time.time())
    def wire(*records):
        output = io.BytesIO()
        for record in records:
            record.to_wire(output, compress=None)
        return output.getvalue()
    def signed(record):
        signature = dns.dnssec.sign(record, key, dns.name.root, dnskey, inception=now-60, expiration=now+3600)
        return record, dns.rrset.from_rdata(record.name, record.ttl, signature)
    chain = wire(*signed(keys), *signed(tlsa))
    evidence = b"\0\x18" + len(chain).to_bytes(2, "big") + chain
    return replace(credentials, entry_extensions=(((59, evidence),),), dnssec_service=(host, port)), wire(keys)


def its_fixture(environment, revoked):
    from tests.test_its_handshake import load_live_fixture
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from tls20_server.pki import Credentials
    os.environ["TLS20_TEST_ITS_LIBRARY"] = environment["TLS20_TEST_ITS_LIBRARY"]
    os.environ["TLS20_ITS_FIXTURE_DIR"] = environment["TLS20_ITS_FIXTURE_DIR"]
    directory, policy = load_live_fixture()
    grant = (directory / "live-server.bin").read_bytes()
    # Fail with a clear fixture error before launching a browser if an earlier
    # long build consumed the short-lived grant's 25-minute validity window.
    policy.authorize(grant, role="server", identity=policy.identity)
    options = {"library": policy.provider.library_path, "identity": policy.identity, "role": 0,
        "psid": str(policy.psid), "application_scope": b64(policy.application_scope),
        "ssp_coer": b64(policy.ssp_coer), "trust_roots": list(map(b64, policy.trust_roots)),
        "authorized_leaves": list(map(b64, policy.authorized_leaf_sha256)),
        "revoked": list(map(b64, policy.authorized_leaf_sha256)) if revoked else [],
        "inventory_valid_until": str(policy.inventory_valid_until),
        "max_grant_lifetime_microseconds": str(policy.max_grant_lifetime_microseconds),
        "tai_utc_offset": policy.tai_utc_offset}
    return Credentials([grant], X25519PrivateKey.from_private_bytes(bytes([9]) * 32),
                       credential_type=3, its_policy=policy), options


async def run(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from tls20_server.errors import ProtocolError
    from tls20_server.credential_profiles import CredentialPolicy, RawPublicKeyBinding
    from tls20_server.handshake import server_handshake
    from tls20_server.pki import Credentials
    from tls20_server.psk import ExternalPSK, import_psk
    from tls20_server.retry_cookie import RetryCookiePolicy

    native_provider = gost_provider = password_policy = None
    environment = {}
    if args.manifest:
        from tls20_server.openssl_provider import OpenSSLProvider
        from tls20_server.gost_provider import GOSTProvider
        from tls20_server.pake import PasswordAccount, PasswordServer, password_base
        from tls20_server.pake_native import PakeProvider
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        environment = manifest["environment"]
        environment["TLS20_TEST_GETDNS"] = manifest["getdns"]
        server_environment = dict(environment)
        for name in ("TLS20_TEST_OPENSSL", "TLS20_TEST_PAKE", "TLS20_TEST_GOST_MODULE",
                     "TLS20_TEST_GETDNS", "TLS20_TEST_ITS_LIBRARY"):
            assert Path(environment[name]).is_file(), ("missing provider fixture", name)
            if args.provider_directory:
                staged = stage_library(environment[name], args.provider_directory)
                environment[name] = str(staged)
        if args.provider_directory and sys.platform == "win32":
            # getdns/GOST may import libssl as well as the already selected
            # libcrypto. Resolve this exact runtime name from the build manifest,
            # never from PATH or an unrestricted directory search.
            runtime = Path(manifest["openssl_prefix"]) / "bin" / "libssl-3-x64.dll"
            if runtime.is_file():
                stage_library(runtime, args.provider_directory)
        native_provider = OpenSSLProvider(Path(server_environment["TLS20_TEST_OPENSSL"]).resolve())
        gost_provider = GOSTProvider(Path(server_environment["TLS20_TEST_OPENSSL"]).resolve(),
                                     Path(server_environment["TLS20_TEST_GOST_MODULE"]).resolve())
        primitive = PakeProvider(native_provider, Path(server_environment["TLS20_TEST_PAKE"]).resolve())
        account = PasswordAccount(b"alice", password_base("alice", "fixture password", None), None)
        password_policy = PasswordServer(HOST, primitive, [account])

    with tempfile.TemporaryDirectory(prefix="httpps-browser-profiles-") as tmp:
        folder = Path(tmp)
        fixtures = Fixtures(folder)
        try:
            cases = ["private-ca", "no-alpn", "client-mac", "raw-key", "external-psk", "imported-psk",
                     "combined-psk", "retry-cookie", "hybrid", "wrong-psk", "wrong-raw-key", "wrong-scope", "malformed",
                     "missing-native-library", "invalid-native-library", "ct-v2", "ct-v2-tampered"]
            if args.manifest:
                cases += ["native-x448", "native-sm", "native-gost", "password", "mixed-password",
                          "mixed-ordinary", "wrong-password", "dane", "dane-wrong-association", "its", "its-revoked"]
            if args.case:
                assert set(args.case) <= set(cases), "Unknown or unavailable profile case"
                cases = [case for case in cases if case in args.case]
            for kind in cases:
                listener_start = len(fixtures.listeners)
                case_host = "example.test" if kind.startswith("its") else HOST
                credentials = fixtures.credentials["valid"]
                options = {"trust_anchors": [b64(fixtures.root)]}
                server_options = {}
                completed, rejected = [], []
                client_key = x25519.X25519PrivateKey.generate()
                client_spki = client_key.public_key().public_bytes(serialization.Encoding.DER,
                                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
                if kind == "no-alpn":
                    options["no_alpn_http11"] = True
                    server_options["require_alpn"] = False
                elif kind == "client-mac":
                    options["client_credential"] = {"certificates": [b64(client_spki)],
                        "private_key": b64(client_key.private_bytes_raw()), "certificate_type": 2}
                    policy = CredentialPolicy(peer_name="fixture client", raw_public_keys=(
                        RawPublicKeyBinding("client", "fixture client", client_spki),))
                    server_options.update(client_credential_policy=policy, require_client_auth=True,
                                          client_certificate_types=(2,))
                elif kind in ("raw-key", "wrong-raw-key"):
                    spki = credentials.private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                                            serialization.PublicFormat.SubjectPublicKeyInfo)
                    credentials = Credentials([spki], credentials.private_key, credential_type=2)
                    options.update(server_certificate_types=[2], server_raw_public_keys=[b64(
                        client_spki if kind == "wrong-raw-key" else spki)])
                elif "psk" in kind:
                    key = ExternalPSK(b"browser fixture", bytes(range(32)), HOST, combined=kind == "combined-psk")
                    item = {"identity": b64(key.identity), "secret": b64(key.psk), "combined": key.combined}
                    if kind == "imported-psk":
                        item["import_context"] = b64(b"browser fixture context")
                        key = import_psk(key.psk, key.identity, b"browser fixture context", HOST)
                    elif kind == "wrong-psk":
                        item["secret"] = b64(bytes([42]) * 32)
                    options["external_psks"] = [item]
                    server_options["external_psks"] = (key,)
                elif kind == "retry-cookie":
                    server_options["retry_cookie_policy"] = RetryCookiePolicy()
                elif kind == "hybrid":
                    options["groups"] = [4588]
                elif kind.startswith("native-"):
                    suite, group = {"native-x448": (0x1301, 30), "native-sm": (0x00c6, 41),
                                    "native-gost": (0xc103, 34)}[kind]
                    options.update(native_library=str(Path(environment["TLS20_TEST_OPENSSL"]).resolve()),
                                   cipher_suites=[suite], groups=[group])
                    server_options.update(cipher_suites=(suite,), native_provider=native_provider)
                    if kind == "native-gost":
                        options["gost_module"] = str(Path(environment["TLS20_TEST_GOST_MODULE"]).resolve())
                        server_options["native_provider"] = gost_provider
                elif kind in ("password", "mixed-password", "mixed-ordinary", "wrong-password"):
                    options.update(native_library=str(Path(environment["TLS20_TEST_OPENSSL"]).resolve()),
                                   cipher_suites=[0xc0b0, 0x1301] if kind.startswith("mixed-") else [0xc0b0],
                                   groups=[23], password={"service": HOST, "username": "alice",
                                       "password": "wrong password" if kind == "wrong-password" else "fixture password",
                                       "helper_library": str(Path(environment["TLS20_TEST_PAKE"]).resolve())})
                    server_options["cipher_suites"] = (0x1301,) if kind == "mixed-ordinary" else (0xc0b0,)
                elif kind == "missing-native-library":
                    options["native_library"] = str(folder / "not-present-provider.dll")
                elif kind == "invalid-native-library":
                    invalid_library = folder / "not-a-native-library.dll"
                    invalid_library.write_bytes(b"This is a deliberately invalid test library, not executable code.\n")
                    options["native_library"] = str(invalid_library)
                elif kind == "malformed":
                    options["ignore_certificate_errors"] = True
                elif kind.startswith("ct-v2"):
                    credentials, options["ct_v2"] = ct_fixture(credentials, fixtures.root, kind.endswith("tampered"))
                elif kind.startswith("its"):
                    credentials, its_options = its_fixture(server_environment, kind.endswith("revoked"))
                    its_options["library"] = environment["TLS20_TEST_ITS_LIBRARY"]
                    options.update(server_certificate_types=[3], its=its_options)

                selected_credentials = [credentials]

                async def peer(reader, writer, *, kind=kind, selected_credentials=selected_credentials,
                               case_host=case_host,
                               server_options=server_options, completed=completed,
                               rejected=rejected, client_spki=client_spki):
                    try:
                        async with asyncio.timeout(15):
                            if kind in ("password", "mixed-password", "wrong-password"):
                                from tls20_server import pake_handshake
                                channel = await pake_handshake.server(reader, writer, password_policy, **server_options)
                            else:
                                channel = await server_handshake(reader, writer, selected_credentials[0], case_host, **server_options)
                            request = b""
                            while b"\r\n\r\n" not in request:
                                part = await channel.recv()
                                if part is None:
                                    return  # Browser speculative connection closed before GET.
                                request += part
                                assert len(request) < 16384
                            completed.append(channel.authenticated_client)
                            if kind == "client-mac":
                                assert channel.authenticated_client == (client_spki,)
                            if kind in ("password", "mixed-password"):
                                assert channel.pake_identity == b"alice"
                            body = ("profile:" + kind).encode()
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
                                str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                            await channel.close()
                    except (ProtocolError, ConnectionError, asyncio.IncompleteReadError) as error:
                        rejected.append(f"{type(error).__name__}: {error}")
                    finally:
                        await close_writer(writer)

                port = await fixtures.listen(peer)
                if kind.startswith("dane"):
                    selected_credentials[0], anchors = dane_fixture(credentials, case_host, port, kind.endswith("association"))
                    options.update(native_library=environment["TLS20_TEST_OPENSSL"], dane={
                        "library": environment["TLS20_TEST_GETDNS"], "trust_anchors": b64(anchors),
                        "application_policy_context": b64(b"explicit browser DNSSEC fixture")})
                origin = f"httpps://{case_host}:{port}"
                config = {"format": 1, "profiles": [{"origin": origin,
                    "top_frame_site": "httpps://wrong.test" if kind == "wrong-scope" else f"httpps://{case_host}",
                    "cross_site": False, "privacy_mode": 0, "route": "direct", "options": options}]}
                file = folder / (kind + ".json")
                file.write_text(json.dumps(config), encoding="utf-8")
                success = kind not in ("wrong-psk", "wrong-raw-key", "wrong-scope", "malformed",
                                       "wrong-password", "missing-native-library", "invalid-native-library",
                                       "ct-v2-tampered", "dane-wrong-association", "its-revoked")
                health_port = None
                if kind in ("missing-native-library", "invalid-native-library"):
                    # The bad profile must fail closed without turning a local
                    # optional-provider error into a network-service crash loop.
                    # A different HTTP origin exercises real network requests
                    # both before and after the rejected HTTPPS navigation.
                    health_port = await fixtures.listen(fixtures.http)
                try:
                    browser = Browser(args.browser.resolve(), folder / (kind + "-profile"), profile_config=file,
                                      enable_network_sandbox=args.enable_network_sandbox, fixture_host=case_host)
                    async with browser as cdp:
                        if health_port:
                            await cdp.navigate(f"http://{HOST}:{health_port}/health-before")
                            assert await cdp.evaluate("document.body.innerText") == "cookie fixture"
                        await cdp.navigate(origin + "/", success=success)
                        if success:
                            assert await cdp.evaluate("document.body.innerText") == "profile:" + kind
                            assert completed, kind
                        else:
                            assert not completed, (kind, completed)
                        if health_port:
                            await cdp.navigate(f"http://{HOST}:{health_port}/health-after")
                            assert await cdp.evaluate("document.body.innerText") == "cookie fixture"
                            assert browser.process.returncode is None
                    if health_port:
                        log_text = (folder / (kind + "-profile.browser.log")).read_text(
                            encoding="utf-8", errors="replace")
                        assert "Network service crashed" not in log_text, "Optional library caused network-service restart"
                except BaseException as error:
                    error.add_note(f"Profile case: {kind}; network sandbox requested: {args.enable_network_sandbox}; "
                                   f"completed requests: {len(completed)}; peer rejections: {rejected}")
                    log = folder / (kind + "-profile.browser.log")
                    if log.exists():
                        with log.open("rb") as stream:
                            stream.seek(max(0, log.stat().st_size - 16384))
                            error.add_note("Browser log tail: " + stream.read().decode("utf-8", errors="replace"))
                    raise
                print("PASS: browser profile", kind, "[network sandbox explicitly enabled]"
                      if args.enable_network_sandbox else "[upstream sandbox defaults]", flush=True)
                if fixtures.errors:
                    raise AssertionError(fixtures.errors)
                while len(fixtures.listeners) > listener_start:
                    listener = fixtures.listeners.pop()
                    listener.close()
                    await listener.wait_closed()
                tasks = list(fixtures.tasks)
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await fixtures.close()
            if gost_provider:
                gost_provider.close()
            if native_provider:
                native_provider.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--manifest", type=Path,
                        help="Build manifest enables real browser PWD/native/GOST profile checks")
    parser.add_argument("--enable-network-sandbox", action="store_true",
                        help="Explicitly enable NetworkServiceSandbox rather than relying on upstream defaults")
    parser.add_argument("--stage-native-libraries", action="store_true",
                        help="Copy the manifest's five selected providers and existing OpenSSL libssl runtime into a temporary browser-output subdirectory; do not change ACLs")
    parser.add_argument("--case", action="append", help="Run only this named case; repeatable")
    args = parser.parse_args()
    if args.stage_native_libraries and not args.manifest:
        parser.error("--stage-native-libraries requires --manifest")
    errors = []
    # Same bounded subprocess wrapper/selector networking as the main browser
    # suite: deliberately rejected peers trigger a Windows Proactor shutdown
    # defect on some Python releases.
    factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    with ExitStack() as stack:
        args.provider_directory = (stack.enter_context(provider_staging_directory(args.browser))
            if args.stage_native_libraries else None)
        runner = stack.enter_context(asyncio.Runner(loop_factory=factory))
        def loop_error(loop, context):
            errors.append(context.get("message", "unexpected event-loop error"))
            loop.default_exception_handler(context)
        runner.get_loop().set_exception_handler(loop_error)
        runner.run(run(args))
    assert not errors, errors
