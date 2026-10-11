// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTPPS_INTEGRITY_ONLY_H_
#define NET_HTTPPS_INTEGRITY_ONLY_H_

#include "net/httpps/draft01.h"

#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_INTEGRITY_EXPORT
#else
#define HTTPPS_INTEGRITY_EXPORT NET_EXPORT
#endif

namespace net::httpps {

// RFC 9150 Protect/Unprotect. These functions DO NOT encrypt anything. The
// connection must independently enforce explicit non-HTTPPS policy, nonce
// sequence, record size/usage limits and ticket confidentiality lineage.
// The header is the complete five-byte TLSCiphertext header. Inputs must not
// alias output. A failed operation clears output and releases no plaintext.
HTTPPS_INTEGRITY_EXPORT size_t IntegrityTagLength(uint16_t suite);
HTTPPS_INTEGRITY_EXPORT bool IntegrityProtect(uint16_t suite, ByteSpan key, ByteSpan nonce,
                                   ByteSpan header, ByteSpan plaintext,
                                   Bytes* output);
HTTPPS_INTEGRITY_EXPORT bool IntegrityUnprotect(uint16_t suite, ByteSpan key, ByteSpan nonce,
                                     ByteSpan header, ByteSpan protected_data,
                                     Bytes* output);

}  // namespace net::httpps

#undef HTTPPS_INTEGRITY_EXPORT
#endif  // NET_HTTPPS_INTEGRITY_ONLY_H_
