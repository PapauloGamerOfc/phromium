// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTPPS_TRANSPARENCY_H_
#define NET_HTTPPS_TRANSPARENCY_H_

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "net/httpps/portable.h"
#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_CT_EXPORT
#else
#include "net/base/net_export.h"
#define HTTPPS_CT_EXPORT NET_EXPORT_PRIVATE
#endif

namespace net::httpps {

using CTBytes = std::vector<uint8_t>;
enum class CTHash { kSHA256, kSHA384, kSHA512 };

struct HTTPPS_CT_EXPORT CTLog {
  // RFC 9162 LogID: DER OBJECT IDENTIFIER value octets, not an SPKI hash.
  CTBytes id;
  CTBytes public_key_spki;
  uint16_t signature_scheme = 0x0403;
  CTHash hash = CTHash::kSHA256;
  uint64_t valid_from_ms = 0;
  uint64_t valid_until_ms = UINT64_MAX;
  uint64_t maximum_merge_delay_seconds = 86400;
};

struct HTTPPS_CT_EXPORT CTTreeHead {
  uint64_t size = 0;
  uint64_t timestamp_ms = 0;
  CTBytes root;
};

struct HTTPPS_CT_EXPORT CTVerifiedSCT {
  CTBytes log_id;
  uint64_t timestamp_ms = 0;
  CTBytes leaf_hash;
  bool included = false;
};

// Explicit HTTPPS policy, independent of HTTPS's CT v1 log list. Configuration
// must come from the application, never the server. SCTs authenticate a log's
// promise, not a server identity; callers must ALSO validate current PKIX/name
// and possession. No network requests or automatic tree-state updates occur.
struct HTTPPS_CT_EXPORT CTv2Policy {
  std::vector<CTLog> logs;
  size_t minimum_logs = 1;
  bool require_inclusion = false;
  // Optional stricter policy: after a log's MMD, a promise alone is insufficient.
  bool require_inclusion_after_mmd = false;
  std::map<CTBytes, CTTreeHead> trusted_tree_heads;

  bool IsValid() const;
  CTBytes Context() const;
  // All three RFC 9162 delivery mechanisms are supported. |issuer_der| MUST be
  // the leaf's issuer in the CURRENT validated path, not an unchecked peer
  // certificate. |stapled_ocsp_der| is only an evidence carrier here: these
  // routines do not claim OCSP GOOD/revocation validation. Matching SingleResponse
  // entries are selected, and each extracted SCT is independently log-verified.
  // Both CH status_request(5) and transparency_info(52) must have been offered.
  std::optional<std::vector<CTVerifiedSCT>> Verify(
      ByteSpan certificate_der, ByteSpan issuer_der, ByteSpan tls_evidence,
      ByteSpan stapled_ocsp_der, uint64_t now_ms,
      std::string* error = nullptr) const;
};

HTTPPS_CT_EXPORT bool VerifyCTInclusion(CTHash hash, ByteSpan leaf,
    uint64_t index, uint64_t size, const std::vector<CTBytes>& path,
    ByteSpan root);
HTTPPS_CT_EXPORT bool VerifyCTConsistency(CTHash hash, uint64_t old_size,
    uint64_t new_size, ByteSpan old_root, ByteSpan new_root,
    const std::vector<CTBytes>& path);

}  // namespace net::httpps
#undef HTTPPS_CT_EXPORT
#endif  // NET_HTTPPS_TRANSPARENCY_H_
