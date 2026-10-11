// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/transparency.h"

#include <charconv>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string_view>

namespace {
using namespace net::httpps;
void Check(bool value, const char* what) {
  if (!value) { std::cerr << what << '\n'; std::exit(2); }
}
uint64_t Number(std::string_view data, int base = 10) {
  uint64_t result = 0;
  const auto parsed = std::from_chars(data.data(), data.data() + data.size(), result, base);
  Check(parsed.ec == std::errc() && parsed.ptr == data.data() + data.size(), "invalid integer argument");
  return result;
}
CTBytes Hex(std::string_view value) {
  Check(value.size() % 2 == 0, "odd hex");
  CTBytes result;
  for (size_t i = 0; i < value.size(); i += 2) result.push_back(static_cast<uint8_t>(Number(value.substr(i, 2), 16)));
  return result;
}
CTBytes Read(const char* name) {
  if (std::string_view(name) == "-") return {};
  std::ifstream file(name, std::ios::binary); Check(file.good(), "unable to read fixture");
  return CTBytes(std::istreambuf_iterator<char>(file), {});
}
CTHash Hash(std::string_view name) {
  if (name == "sha256") return CTHash::kSHA256;
  if (name == "sha384") return CTHash::kSHA384;
  Check(name == "sha512", "unknown hash"); return CTHash::kSHA512;
}
}  // namespace

int main(int argc, char** argv) {
  using namespace net::httpps;
  if ((argc == 15 || argc == 18) && std::string_view(argv[1]) == "--verify") {
    CTv2Policy policy;
    policy.logs.push_back({Hex(argv[2]), Read(argv[3]), static_cast<uint16_t>(Number(argv[4], 16)), Hash(argv[5])});
    policy.minimum_logs = Number(argv[11]);
    if (policy.minimum_logs == 2) {
      auto second = policy.logs.front(); second.id.push_back(1); policy.logs.push_back(second);
    }
    policy.require_inclusion = Number(argv[12]) != 0;
    policy.require_inclusion_after_mmd = Number(argv[13]) != 0;
    policy.logs.front().valid_until_ms = Number(argv[14]);
    if (argc == 18)
      policy.trusted_tree_heads[policy.logs.front().id] = {Number(argv[16]), Number(argv[17]), Read(argv[15])};
    std::string error;
    const auto context = policy.Context();
    auto result = policy.Verify(Read(argv[7]), Read(argv[8]), Read(argv[9]), Read(argv[10]), Number(argv[6]), &error);
    if (!result) { std::cerr << error << '\n'; return 1; }
    Check(context.size() == 32, "valid policy has context binding");
    size_t included = 0; for (const auto& sct : *result) included += sct.included;
    std::cout << result->size() << " SCTs; " << included << " inclusion proofs\n";
    return 0;
  }
  if (argc >= 8 && std::string_view(argv[1]) == "--inclusion") {
    std::vector<CTBytes> path;
    for (int i = 8; i < argc; ++i) path.push_back(Hex(argv[i]));
    return VerifyCTInclusion(Hash(argv[2]), Hex(argv[3]), Number(argv[4]), Number(argv[5]), path, Hex(argv[6])) == (Number(argv[7]) != 0) ? 0 : 1;
  }
  if (argc >= 8 && std::string_view(argv[1]) == "--consistency") {
    std::vector<CTBytes> path;
    for (int i = 8; i < argc; ++i) path.push_back(Hex(argv[i]));
    return VerifyCTConsistency(Hash(argv[2]), Number(argv[3]), Number(argv[4]), Hex(argv[5]), Hex(argv[6]), path) == (Number(argv[7]) != 0) ? 0 : 1;
  }
  Check(argc == 1, "unknown test arguments");
  const auto empty = Hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  const auto leaf = Hex("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7");
  Check(VerifyCTInclusion(CTHash::kSHA256, leaf, 0, 1, {}, leaf), "single leaf inclusion");
  Check(!VerifyCTInclusion(CTHash::kSHA256, leaf, 1, 1, {}, leaf), "index bounds");
  Check(!VerifyCTInclusion(CTHash::kSHA256, leaf, 0, 1, {leaf}, leaf), "excess path");
  Check(VerifyCTConsistency(CTHash::kSHA256, 0, 1, empty, leaf, {}), "empty prefix");
  Check(!VerifyCTConsistency(CTHash::kSHA256, 1, 0, leaf, empty, {}), "rollback");
  Check(VerifyCTConsistency(CTHash::kSHA256, 1, 1, leaf, leaf, {}), "equal tree");
  Check(!VerifyCTConsistency(CTHash::kSHA256, 1, 1, leaf, empty, {}), "conflicting root");
  Check(!CTv2Policy{}.IsValid(), "no implicit log trust");
  std::cout << "CTv2 provider primitive checks passed\n";
}
