// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_HTTPPS_ITS_CREDENTIALS_H_
#define NET_HTTPPS_ITS_CREDENTIALS_H_

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "net/httpps/portable.h"
#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_ITS_EXPORT
#else
#include "net/base/net_export.h"
#define HTTPPS_ITS_EXPORT NET_EXPORT_PRIVATE
#endif

namespace net::httpps {
using ITSBytes = std::vector<uint8_t>;
struct ITSPolicy;
struct HTTPPS_ITS_EXPORT ITSAuthorization {
  std::array<uint8_t, 32> public_key{};
  std::array<uint8_t, 32> leaf_sha256{};
  int64_t expires_unix_milliseconds = 0;
};

// Explicit optional provider; never creates trust roots or discovers a DLL.
// The ABI authenticates an offline grant. Callers MUST still validate X25519
// agreement, the live role-specific MAC and Finished before authenticating peers.
class HTTPPS_ITS_EXPORT ITSProvider {
 public:
  static std::shared_ptr<ITSProvider> Load(std::string_view absolute_path);
  ~ITSProvider();
  const std::string& path() const { return path_; }
 private:
  friend struct ITSPolicy;
  ITSProvider();
  struct Impl;
  std::unique_ptr<Impl> impl_;
  std::string path_;
};

// Trusted application configuration, not fields taken from a peer. A certificate
// pseudonym alone is not a Web PKI identity: authorized leaf hashes explicitly
// bind one service/role and the PSID owner's permission to delegate to TLS20.
struct HTTPPS_ITS_EXPORT ITSPolicy {
  std::shared_ptr<ITSProvider> provider;
  std::string identity;
  uint8_t role = 0;  // server=0, client=1
  uint64_t psid = 0;
  ITSBytes application_scope;
  ITSBytes ssp_coer;
  std::vector<ITSBytes> trust_roots;
  std::vector<ITSBytes> authorized_leaves;
  std::vector<ITSBytes> revoked;
  std::vector<ITSBytes> allowed_regions;
  // Exact COER (parent, child) region pairs authenticated by a locally trusted
  // geometry authority. Not peer data or trust on first use. Bound into tickets.
  std::vector<std::pair<ITSBytes, ITSBytes>> geographic_containment;
  uint64_t inventory_valid_until = 0;  // IEEE Time64, NOT Unix time
  uint64_t max_grant_lifetime_microseconds = 0;
  // Explicit deployment-maintained time offset; no implicit leap-second guess.
  uint8_t tai_utc_offset = 255;  // invalid until explicitly configured

  bool IsValid() const;
  ITSBytes Context() const;
  std::optional<ITSAuthorization> Verify(ByteSpan grant, uint8_t expected_role,
      std::string_view expected_identity, int64_t now_unix_milliseconds,
      std::string* error = nullptr) const;
};
}  // namespace net::httpps
#undef HTTPPS_ITS_EXPORT
#endif  // NET_HTTPPS_ITS_CREDENTIALS_H_
