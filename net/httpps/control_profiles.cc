// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/control_profiles.h"

#include <algorithm>

#include "net/httpps/draft01.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net::httpps {
namespace {

Bytes Vector8(ByteSpan value) {
  Bytes result{static_cast<uint8_t>(value.size())};
  result.insert(result.end(), value.begin(), value.end());
  return result;
}

bool SessionId(ByteSpan value) {
  return value.size() >= 20 && value.size() <= 255 &&
      std::all_of(value.begin(), value.end(), [](uint8_t ch) {
        return ch >= 33 && ch <= 126;
      });
}

bool SameVector(ByteSpan encoded, ByteSpan expected) {
  return encoded.size() == expected.size() + 1 && encoded[0] == expected.size() &&
      (expected.empty() || CRYPTO_memcmp(encoded.subspan(1u).data(),
                                        expected.data(), expected.size()) == 0);
}

}  // namespace

Bytes TicketRequest::Encode() const {
  return {new_session_count, resumption_count};
}

bool TicketRequest::ParseHint(ByteSpan wire, uint8_t* count) {
  if (!count || wire.size() != 1)
    return false;
  *count = wire[0];
  return true;
}

bool SignalingBinding::IsValid() const {
  return (local_hash.empty() || local_hash.size() == 32) &&
      (peer_hash.empty() || peer_hash.size() == 32) &&
      SessionId(local_session_id) && SessionId(peer_session_id);
}

std::map<uint16_t, Bytes> SignalingBinding::Offers() const {
  if (!IsValid())
    return {};
  return {{55, Vector8(local_hash)}, {56, Vector8(local_session_id)}};
}

bool SignalingBinding::Validate(const std::map<uint16_t, Bytes>& response) const {
  if (!IsValid())
    return false;
  const auto hash = response.find(55);
  const auto session = response.find(56);
  return (hash == response.end() ? !required : SameVector(hash->second, peer_hash)) &&
      (session == response.end() ? !required : SameVector(session->second, peer_session_id));
}

std::array<uint8_t, 32> SignalingBinding::Context() const {
  if (!IsValid())
    return {};
  // Matches the reference implementation, with explicit lengths and direction.
  constexpr uint8_t domain[] = {'T','L','S','2','0',' ','s','i','g','n','a','l','i','n','g',0};
  Bytes value(std::begin(domain), std::end(domain));
  value.push_back(required ? 1 : 0);
  for (const auto* item : {&local_hash, &peer_hash, &local_session_id, &peer_session_id}) {
    auto encoded = Vector8(*item);
    value.insert(value.end(), encoded.begin(), encoded.end());
  }
  return Hash(value);
}

}  // namespace net::httpps
