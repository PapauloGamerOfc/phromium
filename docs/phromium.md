# Phromium experimental browser

Phromium changes the unbranded Chromium desktop build. Upstream C++ namespaces,
internal `chrome://` URLs, source paths, API compatibility names and third-party
copyright notices remain intact. They are not product branding.

## Navigation defaults

New profiles do not automatically upgrade HTTP to HTTPS. Schemeless omnibox
input defaults to HTTP; history and explicit user selections can still select
an HTTPS URL. Automatic HTTPS-First heuristics, including the incognito default,
are disabled. A user can still explicitly enable HTTPS-First.

This is not a removal of HSTS. HSTS (including preload), a server's HTTP redirect,
and server-delivered security policies still apply. Explicit `https://` remains
HTTPS. No certificate verification is disabled by these defaults.

## HTTPPS

`httpps://example.test/` connects to TCP **343**. An explicit port, such as
`httpps://localhost:1343/`, overrides it. Port 343 is an experimental project
choice, not a registered HTTPPS service assignment. Binding the server to a low
port may require privileges; use a high server test port if needed. The browser
needs no elevated privilege to connect to port 343 and must not run as root.

The native client implements the first TLS 2.0 framing, key schedule,
authenticated handshake and encrypted records. Its specification is
[tls20-spec](https://github.com/PapauloGamerOfc/tls20-spec), revision
`0c9c8bf0914697d521050554e545a167fa8fc345`. It negotiates `0x0400`, uses the
`TLS20-EXPERIMENT\r\n` bootstrap and rejects older TLS versions. The reference peer is
[tls20-server](https://github.com/PapauloGamerOfc/tls20-server).
Configure that server's listening port explicitly to match the URL; do not
assume an older server build has the same default port.

The client generates independent fresh X25519 authentication and X25519/P-256
traffic keys with BoringSSL's cryptographic random generator. It validates the server's
certificate chain, hostname, authentication proof and Finished message before
releasing ordinary application traffic. Opt-in early data uses a previously
authenticated ticket and revalidates its cached certificate chain first (see below).
HTTPS and HTTPPS are distinct origins and socket
pool keys, even on the same host and port. HTTPPS is not a TLS version negotiated
on an HTTPS connection and is not an approved replacement for TLS 1.3.

### Certificate trust

On desktop, HTTPPS uses the same browser certificate verifier and effective
trusted-root set as HTTPS, plus the HTTPPS-only project CA described below.
The shared roots are not a copied, aging list of root
certificates. Browser/root-store updates, local trust configuration, distrust,
name constraints, certificate validity, hostname checks, CRLSet and applicable
Certificate Transparency policies remain in effect. HTTPPS opts into an
X25519 server-leaf profile; it does not enable that key type for ordinary HTTPS.
The leaf must be a non-CA certificate with critical keyAgreement-only key usage
and serverAuth extended key usage. Issuer signatures are still verified.

Sharing roots does **not** make an existing RSA/ECDSA HTTPS server certificate
usable for HTTPPS. A CA must issue the appropriate X25519 leaf. Public CAs may
not offer this experimental profile, and public-root certificates must still
meet the browser's CT requirements. A private project CA can be explicitly
trusted without a public CA's approval; that grants trust only where it is
configured, not automatically in other browsers.

Peers must send the complete intermediate chain. This path disables network
certificate fetching (including recursive fetches through a proxy being
authenticated); it does not invent a revocation service for this protocol. Android
and iOS native verifiers reject this profile; the current project targets the
desktop built-in verifier.

An optional additional **public CA certificate**, Base64-encoded DER, can be
configured for destination sites using the implementation's strict offline lab profile:

```text
phromium --httpps-trust-anchor=BASE64_DER_CA httpps://localhost:1343/
```

The binary's filename depends on the platform/build target; the Chromium GN
target is still `chrome`. On Windows, with the build's `chrome.exe` and a PEM CA:

```powershell
$caPem = Get-Content -Raw -LiteralPath .\lab-root.pem
$caBase64 = ($caPem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', '')
& .\out\Default\chrome.exe "--httpps-trust-anchor=$caBase64" 'httpps://localhost:1343/'
```

Supply only a CA obtained through a trusted channel. This argument is public
certificate material, **never a CA or server private key**. Invalid input does
not add a private anchor; the default browser verifier still applies. These
additional roots are not imported into HTTPS or the operating system trust
store. HTTPS certificate-ignore flags and clicked-through HTTPS exceptions
cannot bypass HTTPPS validation.

Phromium also bundles the public **HTTPPS Root CA** certificate for HTTPPS
destination sites. It was verified against the owner's original public
certificate, not trusted merely because a remote server supplied it:

```text
SHA-256 (DER): 14b07ff9d677b070863c54db0eee1f6b5c879274068775db2519d327fc39a9bb
Validity: 2026-10-10T13:29:21Z through 2036-10-10T13:34:21Z
```

This built-in root is **not** installed in Windows, added to ordinary HTTPS
trust, or enabled for HTTPPS proxies. It uses the same strict offline
additional-anchor validation path as the destination flag. The certificate is
public; no CA private key is included. A valid `--httpps-trust-anchor` adds an
extra destination root instead of replacing the built-in root. An absent or
malformed flag does not remove the built-in root. Changing this compiled root
requires rebuilding Phromium; testing another root using the flag does not.

### Cookies

HTTPPS cookies are enabled and isolated from HTTP/HTTPS by default, including
when the upstream scheme-bound cookies experiment is disabled. The same host,
cookie name and path can have independent HTTPS and HTTPPS values. Neither
protocol can read, overwrite or expire the other's cookies through web cookie
APIs. Secure, HttpOnly, SameSite, cookie prefixes and partitioning still apply;
HTTPPS and HTTPS remain distinct schemeful sites and origins.

The namespace survives SQLite persistence, restart, network-service IPC and
DevTools round trips. HTTP/HTTPS retain their existing sharing behavior. The
profile database and storage quotas are still shared: this is an access/key
namespace boundary, not separate browser profiles or independent storage quotas.
`Clear-Site-Data: "cookies"` clears cookie records only in the requesting
protocol's namespace. Shared ancillary cache cleanup retains upstream behavior.
User-directed clearing of all cookies can still clear both namespaces.

### Proxies

HTTPPS does not require a proxy. Without a configured proxy it connects
directly. Optional automatic discovery (WPAD) and PAC failures use Chromium's
normal fallback rules: failed initialization falls back to manual settings
(or `DIRECT` if none exist), and optional PAC runtime errors/backoff may use
`DIRECT`. An explicitly mandatory PAC configuration still fails closed.
Valid manual proxies and successful PAC routing decisions remain respected;
these defaults do not disable the operating system's proxy settings.

HTTPPS destinations support HTTP and HTTPS proxies through `CONNECT`, and
SOCKS4/SOCKS5 proxies. With an HTTPS proxy, conventional TLS protects the proxy
connection; the independent HTTPPS handshake runs inside the resulting tunnel.
Manual per-scheme settings select the HTTPS proxy list for HTTPPS destinations.
This does not rewrite the destination scheme for bypass rules or PAC scripts.
An explicit proxy bypass or PAC `DIRECT` decision is still respected.

The proxy itself can also use HTTPPS. Use `httpps://proxy.example:343` as its
URI, or `HTTPPS proxy.example:343` in a Chromium PAC return value. The default
proxy port is 343. This is a distinct proxy type, not an alias for HTTPS.
An HTTPPS proxy always opens an HTTP/1.1 `CONNECT` tunnel, including for plain
HTTP destinations; the destination protocol then operates inside that tunnel.
Only a single HTTPPS proxy hop is supported, not multi-proxy chains. HTTPPS
proxy connections do not negotiate HTTP/2 or QUIC.

HTTPPS proxy authentication is isolated from HTTPS proxies and destination
sites. Proxies also use the default HTTPS root/verifier policy. Additional
private anchors are role-specific; configure the proxy's public CA separately:

```text
phromium --proxy-server="httpps://proxy.example:343" --httpps-proxy-trust-anchor=BASE64_DER_PROXY_CA --httpps-trust-anchor=BASE64_DER_SITE_CA httpps://site.example/
```

The additional site CA is needed only for private HTTPPS destinations not
trusted by the default verifier. HTTPS destinations retain ordinary HTTPS
certificate validation. Neither private trust option falls back to the other;
when both use the same additional CA, explicitly supply it to both options.
The proxy certificate must match the proxy hostname and pass the same TLS 2.0
verification before any `CONNECT` request is sent. Proxy credentials use an
`httpps://` authentication origin, separate from `https://` on the same port.
No HTTPPS CA is installed into the operating system's trust store.

Use manual proxy configuration or Chromium's default V8 PAC evaluator. Native
OS PAC resolvers do not support this experimental scheme or proxy type:
`--use-system-proxy-resolver`, `--winhttp-proxy-resolver` and builds without V8
PAC support are not supported for HTTPPS proxy setups. Native resolvers reject
HTTPPS destination URLs, but the OS may discard an unrecognized `HTTPPS` proxy
result when evaluating an ordinary HTTP/HTTPS destination. Do not rely on
native PAC for this setup. Imported manual system proxy settings do not use
native PAC evaluation. If a proxy is required by policy, make its PAC
configuration mandatory; optional PAC configurations permit fallback just as
they do for ordinary HTTP/HTTPS.

The low-level `ProxyResolvingClientSocket` API has not been opted into HTTPPS
proxies; normal browser navigation uses the HTTP stream and CONNECT path above.
These client changes do not turn the reference reverse proxy into a forward
proxy. The selected proxy server must terminate HTTPPS and implement HTTP
`CONNECT` (or forward the decrypted stream to a suitable forward proxy).

### Sessions and early data

The HTTPPS client supports in-memory session tickets, PSK+DHE resumption,
HelloRetryRequest, KeyUpdate and exporters. Cached tickets are partitioned by
host/port, network-anonymization key, privacy mode, proxy route and role,
application protocol and certificate policy. They are not ordinary HTTPS TLS
sessions and are not persisted to disk. Trust changes and session-cache flushes
invalidate them. Cached certificate chains are revalidated before early writes.

For destinations, `EnableHttppsEarlyData` enables 0-RTT by default when the server
offers it. `--disable-features=EnableHttppsEarlyData` disables that optimization;
it does not change ordinary HTTPS's independent early-data default. HTTPPS proxy
connections do not send early CONNECT or proxy-authorization data. Chromium's
request eligibility and handshake-confirmation rules still apply: not every
request can be sent early. A TLS early-data refusal or HTTP 425 triggers the
existing bounded retry path without early data, not a protocol downgrade.

0-RTT is replayable at the protocol level and does not have fresh-DHE forward
secrecy. A compatible server must explicitly authorize replay-safe processing,
maintain replay state and cooperate with its backend. Merely labelling a request
GET is not proof of safety. The reference server therefore enables resumption
but requires a separate explicit route policy before it forwards early HTTP.

### Client authentication

The portable engine implements initial client-certificate MAC authentication.
An API caller can explicitly supply a `ClientCredential` containing an X25519
client credential and its matching private key. The client verifies the server
and Server Finished before releasing its Certificate and role-separated
`client_x25519_mac(0xfe01)` proof. The server must independently validate and
authorize that client credential; presenting a certificate alone is not
authorization.

The browser integration currently has no client-identity selection UI or
credential-provider integration. It sends an empty Certificate when an initial
CertificateRequest arrives, preserving the server's optional/required-client
decision. Post-handshake client authentication (PHA) is not offered by the
browser. The Python reference peer's initial/PHA APIs and the native engine's
explicit credential API do not imply that these browser features exist.

### Initial scope and limitations

- Direct or proxied TCP and HTTP/1.1, with fresh or resumed HTTPPS handshakes.
  Connections may be reused only for the same socket-pool identity,
  including proxy type and route.
- Shared desktop HTTPS trust policy with an HTTPPS-specific X25519 leaf, plus
  optional independent private anchors. The wire protocol remains experimental;
  shared root trust is not a claim of public CA issuance or protocol approval.
- Isolated HTTPPS cookie values/keys, with shared profile storage and quotas.
- No HTTP/2, HTTP/3, QUIC, alternative-service transport, ECH
  or WebSockets for an HTTPPS destination. This does not disable an HTTPS
  destination's own TLS/HTTP negotiation inside an HTTPPS proxy tunnel.
- The legacy TLS-version display reports an unknown version for HTTPPS, not
  a fabricated TLS 1.3 result. The URL retains `httpps://`.
- HTTPPS responses cannot add or remove HTTPS HSTS policy. HSTS enforcement
  for ordinary HTTP/HTTPS is unchanged. HTTPPS Alt-Svc is ignored.
- Device-bound sessions, service workers, WebSockets, early hints and generated
  script-code caches have not been opted into HTTPPS in this alpha.
- Optional specification profiles such as post-handshake client authentication,
  raw public keys, delegated credentials, certificate compression, exported
  authenticators and PAKE are not yet browser features. They are not advertised.
  Initial client MAC is available only through the engine's explicit credential
  API; browser identity selection remains unimplemented as explained above.
- Internal source filenames `draft01.cc`/`.h` are retained temporarily for build
  compatibility; they no longer select the former draft wire format or KDF.

## Build and verification

This is a Chromium source tree, not a small standalone browser. A shallow Git
clone or sparse checkout alone does **not** include the complete build inputs.
Follow the upstream [Windows](windows_build_instructions.md),
[Linux](linux/build_instructions.md), or [macOS](mac_build_instructions.md) guide
with this fork as the main solution. Chromium's DEPS and build tooling expect
that solution to be named `src`, inside a parent directory containing `.gclient`.
A standalone clone named `phromium` is not already a configured `gclient` tree;
do not simply run `gclient sync` there or name its solution `phromium`. Prepare
the required parent/`src` layout while preserving the local modifications and
using this fork's URL, then expand any sparse checkout and synchronize the
pinned DEPS before using GN/Ninja. Do not replace this fork with a fresh upstream
checkout during that synchronization.

The `httpps_boringssl_spki` DEPS hook applies the small tracked patch in
`net/httpps/patches` to the pinned BoringSSL revision. The patch only enables
parsing of X25519 SPKIs; the normal HTTPS key policy still rejects them. The hook
is idempotent and fails rather than overwriting conflicting local edits or
silently patching a different revision. Run `gclient runhooks` after dependency
sync. The standalone CMake build runs the same hook automatically.

Use `is_chrome_branded=false`. Do not enable official Google Chrome branding.
Do not remove the sandbox or use `--ignore-certificate-errors` as a workaround.
Build and run the upstream `url_unittests`, `net_unittests`, `unit_tests`,
`blink_platform_unittests` and targeted `browser_tests` for modified paths.

Relevant regression filters include:

```text
PhromiumHttpDefaultBrowserTest.*
AutocompleteInputTest.PhromiumPreservesHttpByDefault
HttpsFirstModeSettingsTrackerTest.PhromiumDefaultRequiresExplicitHttpsFirstChoice
*/ConnectJobParamsFactoryTest.HttppsUsesIsolatedTls20Config/*
*/ConnectJobParamsFactoryTest.*Httpps*/*
ProxyServerTest.*Httpps*
ProxySpecificationUtilTest.*
ProxyChainTest.HttppsSingleProxyOnly
ProxyConfigTest.*Httpps*
ConfiguredProxyResolutionServiceTest.*Httpps*
HttpStreamFactoryJobControllerTest.*Httpps*
ClientSocketPool.HttppsNeverSharesHttpsSocketGroup
HttpAuthCacheTest.HttppsDoesNotReuseHttpsCredentials
HttpAuthCacheTest.HttppsProxyCredentialsAreSeparateFromHttpsProxy
*Cookie*.*Httpps*
CertVerifyProcBuiltinTest.*Httpps*
CertVerifierTest.*Httpps*
URLRequestHttpJobTest.HttppsCannotModifyHttpsHstsPolicy
HttppsClientSocketTest.*
HttppsClientSocketProxyTest.*
```

The independent CMake tests under `net/httpps/tests` compile the transport engine
against the exact BoringSSL submodule. They are useful for wire interoperability
and negative cryptographic cases, but **do not replace compiling and testing the
complete Chromium browser**, async socket adapter, renderer or installer.

The portable CI matrix also runs `session_interop_test.py` and
`client_auth_interop_test.py` against a pinned reference server, plus
`spec_oracle_test.py` against specification revision
`0c9c8bf0914697d521050554e545a167fa8fc345`. The latter uses the specification's
derivation helpers and an independent peer state machine, not the reference
server's handshake implementation. See the
[test instructions](../net/httpps/tests/browser_e2e_README.md) for commands and
the distinction between engine, async-adapter and real-browser coverage.

### Local validation status

#### Current specification migration: 2026-10-11

The current Windows standalone Release build passed all three CTest suites,
47 interoperability/certificate checks, 70 wire checks, 364 certificate-mutation
checks, six session checks, six client-authentication checks, and the independent
specification oracle. The oracle uses specification revision
`0c9c8bf0914697d521050554e545a167fa8fc345`.

The complete Windows x64 browser (`out/Phromium/chrome.exe`) and
`net_unittests` were rebuilt successfully. All 866 targeted network/HTTPPS
tests and all 5,381 broader proxy, cookie, SSL and HTTP regression tests passed.
These selections overlap and must not be added as a count of distinct tests.

The real-browser harness passed all 34 assertions against a **clean checkout**
of reference server revision `4f28b2c2da40e8a8371e9846dd3c5cd8a6c9401f`,
without `--allow-server-worktree`. This includes actual session resumption,
0-RTT HTTP received before client Finished, and an HTTP 425 response followed
by a browser retry without early application data, alongside the cookie and
certificate isolation checks. The run reported no asynchronous fixture errors.
Current integrated logs and reports are
`out/Phromium/httpps-net-final.log`,
`out/Phromium/network-regression-final.json`, and
`out/Phromium/httpps-pinned-browser-results.json`.

The reference server's separate CI passed all seven jobs for that commit,
including its three-OS/two-Python test matrix and packaging. That is server
coverage, not evidence of a full Phromium browser build on those other systems.
The services and components targets listed below were **not rerun on
2026-10-11**; their results remain historical.

#### Historical baseline: 2026-10-10

The following results predate the current specification migration. They do not
validate the new session, 0-RTT or client-MAC paths.

The Windows standalone Release build passed three CTest suites: primitive/vector,
PKI parser/default-HTTPS policy, and actual libpki path building (including issuer
trust, expiration, EKU and name-constraint rejection). It also passed 46
interoperability and certificate checks
(including eight concurrent encrypted HTTP exchanges and deferred trust checks),
rejection of a mutation at every byte of the generated certificate (363-364
cases in local runs, depending on DER length), and 38 wire cases
against reference server revision `b5cf91bbe19b77c02d4bcaf52782d7701f205c82`.
The nine branding checks also passed. These standalone results cover the
isolated engine and source-level branding checks; the integrated checks below
exercise the compiled browser libraries as well.

Proxy-specific C++ regressions have been added for URI/PAC parsing,
serialization, route selection, PAC failure, auth-cache isolation, per-hop
handshake configuration, HTTP CONNECT/SOCKS5 encrypted traffic, 407 restart,
proxy failures, nested HTTPPS channels and rejection of an untrusted proxy.
These regressions were compiled and passed in the Windows `net_unittests`
target. The standalone checks alone do not exercise Chromium's proxy stack.

Cookie and shared-verifier C++ regressions have also been added for namespace
isolation, persistence, IPC, DevTools, permission checks, X25519 leaf policy,
untrusted/expired/wrong-host certificates, CT, asynchronous cancellation and
rejection of certificate-ignore bypasses. The focused Windows net, services and
components checks were compiled and run successfully.
The portable deferred-trust tests use the fixture validator, not Chromium's
root store; they validate the engine's suspension/resumption boundary only.

On 2026-10-10, the complete Windows x64 browser (`out/Phromium/chrome.exe`) and
`net_unittests`, `services_unittests`, and `components_unittests` compiled
successfully. This is a release-mode **component developer build**, with DCHECKs
enabled, not a signed distribution or a standalone executable: keep its DLLs,
resources, locales and other output files alongside it.

Integrated test results (two jobs, zero automatic retries):

- 751 focused network/HTTPPS/certificate tests passed.
- 860 extended cookie tests passed, including ordinary HTTP/HTTPS compatibility
  and SQLite persistence/migrations.
- 675 extended network-service/cookie tests passed, including HTTPPS navigation
  routing, IPC and restricted renderer cookie access.
- Eight focused components tests passed.

The selections overlap and should not be added as a count of distinct tests.
Results and logs are saved under `out/Phromium/httpps-*`. The first full-browser
run exposed a missing HTTPPS network-service routing entry; it was corrected
and covered by `URLUtilTest.IsURLHandledByNetworkServiceIncludesHttpps`.

The real-browser harness then passed all 28 checks in two consecutive runs,
including actual encrypted navigation/fetch, the renderer's secure-context
classification, HTTPPS cookie isolation on the same host/port even without
`Secure`, `HttpOnly`, script overwrites, expiration and persistence after a
browser restart. Wrong-host, expired, unknown-CA and invalid-proof connections
were rejected before any HTTP application bytes, and a private HTTPPS trust
anchor did not authorize ordinary HTTPS. Both browser runs exited normally
with zero asynchronous errors. See
`out/Phromium/httpps-browser-verified-results.json` and
[`browser_e2e_README.md`](../net/httpps/tests/browser_e2e_README.md) for the
reproducible harness and its exact limits. Twelve harness self-tests also passed.

After adding the built-in HTTPPS origin root and restoring optional PAC/WPAD
fallback on the same date, the incremental browser and `net_unittests` build
passed. All 843 selected network/certificate/proxy tests passed with two jobs
and zero retries, including the complete `ConfiguredProxyResolutionServiceTest`
suite. The 28 real-browser checks passed again with no asynchronous errors.
The seven-case browser configuration regression was compiled but its
`browser_tests` executable was not linked or run.

A separate fresh-profile live navigation also returned HTTP 200 using the
built-in root, with neither an extra CA argument nor `--no-proxy-server`.
NetLog confirmed that system automatic proxy discovery remained enabled.
The same site still loaded when given a different additional public CA,
malformed base64, or base64 that was not a DER certificate: none removed the
built-in root. These live checks do not replace the isolated rejection tests.
Reports are `out/Phromium/httpps-ca-proxy-tests.json`,
`out/Phromium/httpps-browser-ca-proxy-results.json`, and the
`out/Phromium/httpps-default-ca-*` / `httpps-ca-*` smoke-test directories.

The browser harness uses a temporary, explicitly trusted private CA; acceptance
through the shared/default path builder is covered separately by the integrated
certificate tests. These results are regression checks, not a security audit
or a claim that public CAs currently issue the experimental leaf profile.

The separate `content_unittests`, `content_browsertests`, extensions and Blink
web-test targets, the entire unfiltered upstream suites, native installers and
other operating systems have **not** been validated by this Windows build.
The added CI workflow runs portable engine and branding checks only; it does not
claim full-browser coverage and was not dispatched for this local work.

## Distribution and updates

Phromium currently has no automatic update service or Linux package update
repository. Its Debian and RPM packaging does not install Google's repository,
import Google's package-signing keys, or install repository-maintenance cron
jobs. The separate repository-package generator rejects Phromium builds.
Google Chrome's branded packaging path remains unchanged.

Install newer Phromium builds manually from a source you trust. Release signing,
an authenticated update channel and native installer validation are still
required before distributing this experimental browser to other users.
