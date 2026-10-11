// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NET_HTTPPS_BUILTIN_ROOT_H_
#define CHROME_BROWSER_NET_HTTPPS_BUILTIN_ROOT_H_

namespace phromium {

// Public certificate supplied and approved by the project owner on 2026-10-10,
// from httpps-root/root-ca.crt.pem. This is the complete DER certificate
// encoded as base64, not a private key. Trust is limited to HTTPPS origin
// connections; it must not be added to HTTPS, the OS trust store, or HTTPPS
// proxy trust. Subject: CN=HTTPPS Root CA SHA-256 (DER):
// 14B07FF9D677B070863C54DB0EEE1F6B5C879274068775DB2519D327FC39A9BB
inline constexpr char kHttppsOriginRootBase64[] =
    "MIIBmDCCAT2gAwIBAgIUW7tmB76vgkGJpOA2UkwL5YrzUnMwCgYIKoZIzj0EAwIw"
    "GTEXMBUGA1UEAxMOSFRUUFBTIFJvb3QgQ0EwHhcNMjYxMDEwMTMyOTIxWhcNMzYx"
    "MDEwMTMzNDIxWjAZMRcwFQYDVQQDEw5IVFRQUFMgUm9vdCBDQTBZMBMGByqGSM49"
    "AgEGCCqGSM49AwEHA0IABLysjUFPSezczPz0ZgB82xhLQm7tQYYnbufihbeYkLqd"
    "ifY7J6Qya8xvrYp9r3+2nThP+S/7gkJOqEJEaJxP5nGjYzBhMA8GA1UdEwEB/wQF"
    "MAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSjcGxbVBZeN0qozaPnYO0u"
    "h9ArUTAfBgNVHSMEGDAWgBSjcGxbVBZeN0qozaPnYO0uh9ArUTAKBggqhkjOPQQD"
    "AgNJADBGAiEAhVKmwR1WZZ1as82B1/YD7/Viwdf2GGwn0dkDSftnYDoCIQC+2mzy"
    "GywZzigC3OJI6v5/InUhvxAusfkIT2mymd7mBw==";

}  // namespace phromium

#endif  // CHROME_BROWSER_NET_HTTPPS_BUILTIN_ROOT_H_
