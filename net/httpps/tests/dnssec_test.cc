// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/httpps/dnssec.h"
#include <charconv>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string_view>
namespace {
using namespace net::httpps;
DNSBytes Read(const char* path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) std::exit(2);
  return DNSBytes(std::istreambuf_iterator<char>(file), {});
}
int64_t Number(std::string_view text) {
  int64_t result = -1;
  const auto parse = std::from_chars(text.data(), text.data() + text.size(), result);
  if (parse.ec != std::errc() || parse.ptr != text.data() + text.size()) std::exit(2);
  return result;
}
}
int main(int argc, char** argv) {
  using namespace net::httpps;
  if (argc == 1) {
    DANEPolicy invalid;
    if (invalid.IsValid() || !invalid.Context().empty() || DNSSECProvider::Load("relative.dll")) return 1;
    std::cout << "DNSSEC fail-closed policy tests passed\n"; return 0;
  }
  if (argc != 11) return 2;
  auto provider = DNSSECProvider::Load(argv[1]);
  if (!provider) { std::cerr << "provider unavailable\n"; return 2; }
  const auto port = Number(argv[4]), now = Number(argv[5]);
  if (port < 1 || port > 65535) return 2;
  DANEPolicy policy;
  policy.provider = provider; policy.trust_anchors = Read(argv[2]);
  policy.port = static_cast<uint16_t>(port);
  policy.allow_authenticated_denial = Number(argv[9]) != 0;
  const auto callback_mode = Number(argv[10]);
  const auto leaf = Read(argv[7]);
  if (callback_mode) {
    policy.application_policy_context = DNSBytes{1};
    // Oracle harness only: independently generated fixture paths are injected
    // by the test runner. Production must use a real current path validator.
    policy.pkix_validator = [leaf, callback_mode](const auto&) -> std::optional<std::vector<DNSBytes>> {
      if (callback_mode != 1) return {};
      return std::vector<DNSBytes>{leaf};
    };
  }
  if (!policy.IsValid() || policy.Context().size() != 32) return 2;
  std::string error;
  const auto result = policy.Verify(argv[3], {leaf}, static_cast<uint8_t>(Number(argv[8])), Read(argv[6]), now, &error);
  if (!result) { std::cerr << error << '\n'; return 1; }
  std::cout << result->usage << ' ' << result->expires_unix_seconds << ' ' << result->support_lifetime_hours << '\n';
  return 0;
}
