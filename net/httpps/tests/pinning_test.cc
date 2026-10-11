// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/pinning.h"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
using namespace net::httpps;

void Check(bool value, const char* name) {
  if (!value) {
    std::cerr << "Pinning failure: " << name << '\n';
    std::exit(1);
  }
}

Bytes Hex(std::string_view text) {
  Bytes result;
  for (size_t i = 0; i < text.size(); i += 2)
    result.push_back(static_cast<uint8_t>(std::stoul(std::string(text.substr(i, 2)), nullptr, 16)));
  return result;
}

Bytes Reply(ByteSpan proof, ByteSpan ticket, uint32_t lifetime) {
  Bytes result{static_cast<uint8_t>(proof.size())};
  result.insert(result.end(), proof.begin(), proof.end());
  result.push_back(static_cast<uint8_t>(ticket.size() >> 8));
  result.push_back(static_cast<uint8_t>(ticket.size()));
  result.insert(result.end(), ticket.begin(), ticket.end());
  for (int shift : {24, 16, 8, 0})
    result.push_back(static_cast<uint8_t>(lifetime >> shift));
  return result;
}

}  // namespace

void RunPinningTests() {
  using namespace net::httpps;
  int64_t now = 1000;
  PinningCache cache(1, [&]() { return now; });
  const auto spki = Hex("302a300506032b656e0321008f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
  const auto transcript = StringBytes("TLS20-EXPERIMENT\r\nCH SH");
  const auto transcript2 = StringBytes("TLS20-EXPERIMENT\r\nCH SH2");
  Bytes root(32), root384(48);
  for (size_t i = 0; i < root384.size(); ++i) {
    root384[i] = static_cast<uint8_t>(i);
    if (i < root.size())
      root[i] = static_cast<uint8_t>(i);
  }
  const Bytes ticket{1, 2, 3};
  auto first = cache.Begin("example.test", 343, "privacy-A/direct/policy-1");
  Check(first && first->extension().empty() && !first->had_pin(), "explicit enrollment");
  auto enroll = Reply({}, ticket, 100);
  Check(!first->Commit(), "cannot commit before authenticated verification");
  Check(first->Verify(ByteSpan(enroll), 0x1301, root, transcript, spki), "valid enrollment");
  Check(cache.Begin("example.test", 343, "privacy-A/direct/policy-1")->extension().empty(), "verification stages only");
  Check(first->Commit() && !first->Commit(), "one commit after CF");
  const auto scope = "privacy-A/direct/policy-1";
  auto previous = cache.Begin("example.test", 343, scope);
  Check(previous->had_pin() && previous->extension() == Bytes({0, 3, 1, 2, 3}), "V16 ticket");
  Check(cache.Begin("example.test", 443, scope)->extension().empty() &&
        cache.Begin("example.test", 343, "privacy-B/direct/policy-1")->extension().empty() &&
        cache.Begin("other.test", 343, scope)->extension().empty(), "host port partition isolation");
  Check(!previous->Verify(std::nullopt, 0x1301, root, transcript, spki) &&
        !previous->Verify(ByteSpan(enroll), 0x1301, root, transcript, spki), "missing proof failure is terminal");
  Check(!cache.Forget("example.test", 343, scope, false), "no implicit pin removal");
  const auto proof384 = Hex("4fc933d04cba823e5eabeb67f6660d7f66db34637acae23705114d36a13d5f9e00e1fa0fdfb3460d0c7e8c0866bb3a0d");
  auto rotate = Reply(proof384, Bytes{4, 5}, 100);
  auto bad = rotate;
  bad[1] ^= 1;
  auto corrupted = cache.Begin("example.test", 343, scope);
  Check(!corrupted->Verify(ByteSpan(bad), 0x1302, root384, transcript2, spki) && !corrupted->Commit(), "bad proof retained original");
  auto stale = cache.Begin("example.test", 343, scope);
  auto refreshed = cache.Begin("example.test", 343, scope);
  Check(refreshed->Verify(ByteSpan(rotate), 0x1302, root384, transcript2, spki) && refreshed->Commit(), "independent Python cross-hash proof vector");
  auto ramp = Reply(proof384, {}, 0);
  Check(stale->Verify(ByteSpan(ramp), 0x1302, root384, transcript2, spki) && stale->Commit(), "older parallel ramp completion");
  Check(cache.Begin("example.test", 343, scope)->extension() == Bytes({0, 2, 4, 5}), "stale ramp cannot erase newer pin");
  auto second = cache.Begin("second.test", 343, scope);
  Check(second->Verify(ByteSpan(enroll), 0x1301, root, transcript, spki) && !second->Commit(), "capacity never evicts live pin");
  for (size_t size = 0; size < rotate.size(); ++size) {
    auto attempt = cache.Begin("example.test", 343, scope);
    Check(!attempt->Verify(ByteSpan(rotate).first(size), 0x1302, root384, transcript2, spki), "truncated extension rejected");
  }
  Check(cache.Forget("example.test", 343, scope, true), "explicit trusted recovery");
  auto refill = cache.Begin("example.test", 343, scope);
  Check(refill->Verify(ByteSpan(enroll), 0x1301, root, transcript, spki) && refill->Commit(), "re-enrollment");
  auto valid_ramp = cache.Begin("example.test", 343, scope);
  Check(valid_ramp->Verify(ByteSpan(ramp), 0x1302, root384, transcript2, spki) && valid_ramp->Commit(), "authenticated ramp down");
  Check(!cache.Begin("example.test", 343, scope)->had_pin(), "ramp removed only after success");
  auto expiring = cache.Begin("example.test", 343, scope);
  Check(expiring->Verify(ByteSpan(enroll), 0x1301, root, transcript, spki) && expiring->Commit(), "expiring entry");
  now += 100000;
  Check(!cache.Begin("example.test", 343, scope)->had_pin(), "monotonic expiration");
  Check(!cache.Begin("example.test", 0, scope) && !cache.Begin("example.test", 343, ""), "explicit endpoint and partition required");
  PinningCache small(100, [&]() { return now; }, 400);
  auto fits = small.Begin("example.test", 343, scope);
  Check(fits->Verify(ByteSpan(enroll), 0x1301, root, transcript, spki) && fits->Commit(), "byte budget first pin");
  auto over = small.Begin("another.test", 343, scope);
  Check(over->Verify(ByteSpan(enroll), 0x1301, root, transcript, spki) && !over->Commit(), "byte budget preserves live pin");
  Check(small.Forget("example.test", 343, scope, true), "byte accounting explicit recovery");
  auto freed = small.Begin("another.test", 343, scope);
  Check(freed->Verify(ByteSpan(enroll), 0x1301, root, transcript, spki) && freed->Commit(), "freed byte budget reusable");
  std::cout << "Pinning vectors, scope, failure, concurrency and capacity tests passed\n";
}
