"""Interoperability using explicit, locally built optional providers.

The manifest is produced by the pinned reference server's
tools/build_native_dependencies.py --with-gost --with-getdns --with-its. No network peer
can choose a provider library, password helper, trust anchor or policy.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--native-build', type=Path, required=True)
    parser.add_argument('--server-source', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
    values = manifest['environment']
    environment = os.environ.copy()
    for key, value in values.items():
        if key.startswith('TLS20_TEST_') or key in ('TLS20_ITS_FIXTURE_DIR', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH'):
            environment[key] = value
    directory = args.native_build.resolve()
    if os.name == 'nt':
        directory /= 'Release'
    suffix = '.exe' if os.name == 'nt' else ''
    native = directory/f'httpps_native_test{suffix}'
    server = args.server_source.resolve()
    source = Path(__file__).resolve().parent
    provider = values['TLS20_TEST_OPENSSL']
    helper = values['TLS20_TEST_PAKE']
    cli = values['TLS20_TEST_OPENSSL_CLI']
    gost = values['TLS20_TEST_GOST_MODULE']
    getdns = manifest['getdns']
    its = values['TLS20_TEST_ITS_LIBRARY']
    fixtures = values['TLS20_ITS_FIXTURE_DIR']
    for path in (native, provider, helper, cli, getdns, gost, its):
        if not Path(path).is_file():
            raise SystemExit(f'Missing explicitly built fixture: {path}')

    def run(*command):
        print('Test:', ' '.join(str(item) for item in command), flush=True)
        subprocess.run([str(item) for item in command], env=environment, check=True,
                       timeout=600)

    def interop(script, *extra):
        run(sys.executable, source/script, '--native', native,
            '--server-source', server, *extra)

    run(native, '--native-provider-test', provider, helper)
    run(directory/f'httpps_provider_erasure_test{suffix}', provider)
    run(native, '--gost-provider-test', provider, gost)
    run(directory/f'httpps_secret_erasure_test{suffix}', '--gost', provider, gost)
    run(directory/f'httpps_its_test{suffix}', its, fixtures)
    run(directory/f'httpps_its_test{suffix}', its, Path(fixtures)/'geometry-static')
    interop('its_interop_test.py', '--provider', its, '--fixtures', fixtures)
    interop('suite_interop_test.py', '--native-provider', provider)
    interop('suite_interop_test.py', '--native-provider', provider, '--gost-module', gost)
    interop('sm_credentials_interop_test.py', '--provider', provider, '--openssl', cli)
    interop('gost_credentials_interop_test.py', '--provider', provider, '--module', gost, '--openssl', cli)
    interop('signature_profiles_interop_test.py', '--provider', provider)
    interop('password_interop_test.py', '--provider', provider, '--helper', helper)
    interop('hello_structure_interop_test.py', '--provider', provider, '--helper', helper)
    interop('mixed_password_interop_test.py', '--provider', provider, '--helper', helper)
    interop('authenticator_interop_test.py', '--password-provider', provider,
            '--password-helper', helper)
    interop('credential_requests_test.py')
    interop('chain_limit_interop_test.py', '--native-provider', provider)
    interop('transparency_interop_test.py')
    run(sys.executable, source/'transparency_oracle_test.py', '--binary',
        directory/f'httpps_transparency_test{suffix}', '--server-source', server)
    interop('dnssec_interop_test.py', '--getdns', getdns)
    run(sys.executable, source/'dnssec_oracle_test.py', '--native',
        directory/f'httpps_dnssec_test{suffix}', '--getdns', getdns)


if __name__ == '__main__':
    main()
