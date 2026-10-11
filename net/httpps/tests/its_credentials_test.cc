// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/httpps/its_credentials.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include "third_party/boringssl/src/include/openssl/sha.h"

namespace {
using namespace net::httpps;
size_t checks = 0;
void Check(bool condition, const char* message) {
  ++checks;
  if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}
ITSBytes Read(const std::filesystem::path& name) {
  std::ifstream file(name, std::ios::binary);
  Check(file.good(), "fixture unavailable");
  return ITSBytes(std::istreambuf_iterator<char>(file), {});
}
struct Cursor {
  ByteSpan bytes;
  uint64_t Number(size_t width) {
    Check(bytes.size() >= width, "truncated fixture number");
    uint64_t n = 0;
    for (auto b : bytes.first(width)) n = (n << 8) | b;
    bytes = bytes.subspan(width);
    return n;
  }
  ITSBytes Vector(size_t width) {
    const auto n = Number(width);
    Check(n <= bytes.size(), "truncated fixture vector");
    const auto value = bytes.first(n);
    bytes = bytes.subspan(n);
    return ITSBytes(value.begin(), value.end());
  }
};
}

int main(int argc, char** argv) {
  using namespace net::httpps;
  ITSPolicy invalid;
  Check(!invalid.IsValid() && invalid.Context().empty(), "no implicit ITS policy");
  Check(!ITSProvider::Load("tls20_its.dll"), "no implicit provider discovery");
  Check(!invalid.Verify(ITSBytes{1}, 0, "example.test", 0), "no trust from parsing");
  if (argc == 1) {
    std::cout << checks << " ITS fail-closed configuration checks passed\n";
    return 0;
  }
  Check(argc == 3, "usage: httpps_its_test absolute_library fixture_directory");
  auto provider = ITSProvider::Load(argv[1]);
  Check(provider != nullptr, "explicit ITS library unavailable");
  const std::filesystem::path directory(argv[2]);
  const auto grant = Read(directory / "grant.bin");
  const auto wire = Read(directory / "policy.bin");
  Check(wire.size() >= 4 && std::string(wire.begin(), wire.begin() + 4) == "ITS1", "policy magic");
  Cursor cursor{ByteSpan(wire).subspan(4)};
  ITSPolicy policy;
  policy.provider = provider; policy.identity = "example.test"; policy.tai_utc_offset = 37;
  const auto now_time64 = cursor.Number(8);
  policy.inventory_valid_until = cursor.Number(8);
  policy.max_grant_lifetime_microseconds = cursor.Number(8);
  policy.role = static_cast<uint8_t>(cursor.Number(1));
  policy.psid = cursor.Number(8);
  policy.application_scope = cursor.Vector(2); policy.ssp_coer = cursor.Vector(2);
  const auto roots = cursor.Vector(3);
  Cursor root_cursor{roots};
  while (!root_cursor.bytes.empty()) policy.trust_roots.push_back(root_cursor.Vector(3));
  const auto leaves = cursor.Vector(3), revoked = cursor.Vector(3), regions = cursor.Vector(3);
  for (const auto* source : {&leaves, &revoked}) {
    Check(source->size() % 32 == 0, "inventory fingerprint framing");
    auto& target = source == &leaves ? policy.authorized_leaves : policy.revoked;
    auto bytes = ByteSpan(*source);
    while (!bytes.empty()) { const auto hash = bytes.first(32); target.emplace_back(hash.begin(), hash.end()); bytes = bytes.subspan(32); }
  }
  Cursor region_cursor{regions};
  while (!region_cursor.bytes.empty()) policy.allowed_regions.push_back(region_cursor.Vector(3));
  if (!cursor.bytes.empty()) {
    Check(cursor.Number(4) == 0x47454f31, "GEO1 containment framing");
    const auto pairs = cursor.Vector(3);
    Cursor pair_cursor{pairs};
    while (!pair_cursor.bytes.empty()) {
      auto parent = pair_cursor.Vector(3);
      auto child = pair_cursor.Vector(3);
      policy.geographic_containment.emplace_back(std::move(parent), std::move(child));
    }
  }
  Check(cursor.bytes.empty() && policy.IsValid(), "valid explicit fixture policy");
  const int64_t now_ms = static_cast<int64_t>(now_time64 / 1000) + (1072915200LL - 37) * 1000;
  auto authorization = policy.Verify(grant, 0, "example.test", now_ms);
  Check(authorization.has_value(), "real COER/path/permission/grant validation");
  const std::array<uint8_t, 32> expected{0x57,0xdb,0x4b,0x35,0x9f,0x23,0xae,0x5e,0x14,0x6e,0x4e,0x25,0x12,0x05,0x67,0x04,0x72,0x25,0x06,0x34,0x8c,0x15,0x0c,0x14,0x75,0x3d,0x0c,0x93,0x3d,0x04,0xd4,0x21};
  Check(authorization->public_key == expected, "grant X25519 key exact");
  Check(authorization->expires_unix_milliseconds == static_cast<int64_t>(policy.inventory_valid_until / 1000) + (1072915200LL - 37) * 1000, "expiry cannot exceed inventory deadline");
  Check(!policy.Verify(grant, 1, "example.test", now_ms), "role mismatch rejected");
  Check(!policy.Verify(grant, 0, "other.test", now_ms), "service mismatch rejected");
  Check(!policy.Verify(grant, 0, "example.test", std::numeric_limits<int64_t>::max()), "clock overflow rejected");
  Check(!policy.Verify(grant, 0, "example.test", authorization->expires_unix_milliseconds), "expired inventory rejected");
  const auto context = policy.Context();
  Check(context.size() == 32, "ticket policy context");
  auto changed = policy;
  if (!policy.geographic_containment.empty()) {
    changed.geographic_containment.clear();
    Check(!changed.Verify(grant, 0, "example.test", now_ms), "geography requires local authority");
    changed = policy;
    std::swap(changed.geographic_containment.front().first, changed.geographic_containment.front().second);
    Check(changed.Context() != context && !changed.Verify(grant, 0, "example.test", now_ms),
          "reversed local containment never grants authority");
    changed = policy;
    changed.geographic_containment.front().second = changed.geographic_containment.front().first;
    Check(!changed.Verify(grant, 0, "example.test", now_ms), "different child is not the certified region");
    changed = policy;
  }
  changed.revoked = policy.authorized_leaves;
  Check(changed.Context() != context && !changed.Verify(grant, 0, "example.test", now_ms), "revocation binds tickets and fresh authorization");
  changed = policy; changed.authorized_leaves = {ITSBytes(32,1), ITSBytes(32,2)}; changed.revoked = {ITSBytes(32,3)};
  const auto first = changed.Context();
  changed.authorized_leaves.pop_back(); changed.revoked.insert(changed.revoked.begin(), ITSBytes(32,2));
  Check(first != changed.Context(), "context preserves allow/revoke category boundaries");
  changed = policy; changed.psid++;
  Check(!changed.Verify(grant, 0, "example.test", now_ms), "PSID authorization required");
  changed = policy; changed.application_scope.push_back(0);
  Check(!changed.Verify(grant, 0, "example.test", now_ms), "application scope authorization required");
  changed = policy; changed.trust_roots = {ITSBytes(16385, 0)};
  Check(!changed.IsValid(), "COER input bounded before FFI");
  changed = policy; changed.geographic_containment = {{ITSBytes{1}, ITSBytes{2}}};
  const auto geometry_context = changed.Context();
  Check(geometry_context != context && !changed.Verify(grant, 0, "example.test", now_ms),
        "geometry statements bind tickets and malformed COER fails closed");
  changed.geographic_containment = {{ITSBytes{2}, ITSBytes{1}}};
  Check(changed.Context() != geometry_context, "geometry authorization is directional");
  changed.geographic_containment.front().second.clear();
  Check(!changed.IsValid(), "empty geographic attestation rejected before FFI");
  for (size_t i = 0; i < grant.size(); ++i) {
    auto altered = grant; altered[i] ^= 0x80;
    Check(!policy.Verify(altered, 0, "example.test", now_ms), "altered credential rejected");
    Check(!policy.Verify(ByteSpan(grant).first(i), 0, "example.test", now_ms), "truncated credential rejected");
  }
  std::cout << checks << " ITS native provider, trust and policy checks passed\n";
  return 0;
}
