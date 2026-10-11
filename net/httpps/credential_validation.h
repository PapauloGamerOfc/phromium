// Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.

#ifndef NET_HTTPPS_CREDENTIAL_VALIDATION_H_
#define NET_HTTPPS_CREDENTIAL_VALIDATION_H_

#include "net/httpps/draft01.h"

namespace net::httpps {

// Local chain-entry budget, shared by wire, cached and provisioned credentials.
// Byte-size, representation and trust-path checks remain independent.
inline constexpr size_t kMaxCertificates = 64;

// Decode the nonempty RFC 9846 authority-name vector and validate each DER Name.
// These are selection hints, not trust anchors or authorization decisions.
#if !defined(PHROMIUM_HTTPPS_STANDALONE)
NET_EXPORT_PRIVATE
#endif
bool ParseCertificateAuthorities(ByteSpan encoded,
                                 std::vector<Bytes>* authorities);

}  // namespace net::httpps

#endif  // NET_HTTPPS_CREDENTIAL_VALIDATION_H_
