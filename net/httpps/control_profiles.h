// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTPPS_CONTROL_PROFILES_H_
#define NET_HTTPPS_CONTROL_PROFILES_H_

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "net/httpps/portable.h"

#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_CONTROL_EXPORT
#else
#include "net/base/net_export.h"
#define HTTPPS_CONTROL_EXPORT NET_EXPORT_PRIVATE
#endif

namespace net::httpps {

struct HTTPPS_CONTROL_EXPORT TicketRequest {
  uint8_t new_session_count = 1;
  uint8_t resumption_count = 1;
  std::vector<uint8_t> Encode() const;
  // A server hint is not a promise; zero and absence are distinct.
  static bool ParseHint(ByteSpan wire, uint8_t* count);
};

// An application supplies hashes/session IDs ONLY after independently checking
// its external signaling identity and credential fingerprint. Empty hash means
// no asserted identity; it is not an authenticated peer. Never learn expected
// values from the TLS peer or treat mere token decoding as signaling trust.
struct HTTPPS_CONTROL_EXPORT SignalingBinding {
  std::vector<uint8_t> local_hash;
  std::vector<uint8_t> peer_hash;
  std::vector<uint8_t> local_session_id;
  std::vector<uint8_t> peer_session_id;
  bool required = true;

  bool IsValid() const;
  std::map<uint16_t, std::vector<uint8_t>> Offers() const;
  bool Validate(const std::map<uint16_t, std::vector<uint8_t>>& response) const;
  std::array<uint8_t, 32> Context() const;
};

}  // namespace net::httpps
#undef HTTPPS_CONTROL_EXPORT
#endif  // NET_HTTPPS_CONTROL_PROFILES_H_
