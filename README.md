# ![Logo](chrome/app/theme/chromium/product_logo_64.png) Phromium

Phromium is an experimental Chromium fork with its own branding and profile,
HTTP-by-default navigation, and a native HTTPPS transport for the TLS 2.0
research protocol. It is not an official Chromium or Google Chrome release.

- Browser-initiated HTTPS upgrades are disabled by default. HSTS, explicit HTTPS
  URLs, server redirects, and a user's explicit HTTPS-First choice still work.
- `httpps://` uses TCP port **343** by default, or an explicit URL port. This is
  a project-local experimental default, not an IANA allocation.
- HTTPPS uses its own authenticated transport with the desktop HTTPS root
  policy and optional additional private CAs. It is not an alias for HTTPS
  or a local plaintext proxy. HTTPPS cookies are isolated from HTTP/HTTPS.
- Standard HTTPS remains standard TLS. HTTPPS never falls back to HTTP/HTTPS.

See [HTTPPS setup, scope and verification](docs/phromium.md) before testing.
The protocol and browser integration are experimental, not production-ready.

## Upstream Chromium

Chromium is an open-source browser project. Its licenses, attribution and
upstream development documentation are retained in this fork.

The project's web site is https://www.chromium.org.

For a complete Phromium build, use the fork-specific checkout notes in
[Build and verification](docs/phromium.md#build-and-verification). A Git clone
alone does not fetch Chromium's pinned build dependencies. The upstream
[checkout guide](docs/get_the_code.md) supplies the general tooling instructions;
keep this fork as the source repository.

Documentation in the source is rooted in [docs/README.md](docs/README.md).

Learn how to [Get Around the Chromium Source Code Directory
Structure](https://www.chromium.org/developers/how-tos/getting-around-the-chrome-source-code).

For historical reasons, there are some small top level directories. Now the
guidance is that new top level directories are for product (e.g. Chrome,
Android WebView, Ash). Even if these products have multiple executables, the
code should be in subdirectories of the product.

Report Phromium-specific issues in this fork's GitHub issue tracker, not the
upstream Chromium tracker.
