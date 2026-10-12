// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This isolated executable observes C++ buffers immediately BEFORE deallocation.
// It does not read freed memory, require an allocator-specific usable-size API,
// replace BoringSSL's allocator, or instrument the browser/interoperability binary.
#include "net/httpps/draft01.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <new>

#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/mlkem.h"

namespace {
using namespace net::httpps;

struct Allocation {
  void* pointer = nullptr;
  size_t size = 0;
  bool require_zero = false;
};
struct Pattern {
  std::array<uint8_t, 64> bytes{};
  size_t size = 0;
};
struct Counts {
  size_t frees = 0;
  size_t required_zero_frees = 0;
  size_t uncleansed = 0;
};
struct Observation {
  bool active = false;
  std::array<Allocation, 512> allocations{};
  std::array<Pattern, 4> patterns{};
  Counts counts;
};
// Fixed, non-allocating bookkeeping avoids recursion into operator new/delete.
// The calls under test are synchronous; other threads cannot affect this state.
thread_local Observation observation;

void Check(bool ok, const char* message) {
  if (!ok) {
    std::cerr << "Secret erasure regression: " << message << '\n';
    std::exit(1);
  }
}

void Register(void* pointer, size_t size, bool require_zero = false) {
  if (!observation.active || !pointer) return;
  for (auto& entry : observation.allocations) {
    if (!entry.pointer || entry.pointer == pointer) {
      entry = {pointer, size, require_zero};
      return;
    }
  }
  std::abort();  // Never silently miss a buffer when the test table fills.
}

void Begin() {
  Check(!observation.active, "nested allocation observer");
  observation = {};
  observation.active = true;
}

void WatchPattern(ByteSpan value) {
  Check(!value.empty() && value.size() <= 64, "pattern length");
  for (auto& pattern : observation.patterns) {
    if (!pattern.size) {
      std::copy(value.begin(), value.end(), pattern.bytes.begin());
      pattern.size = value.size();
      return;
    }
  }
  std::abort();
}

Counts End() {
  observation.active = false;
  const auto counts = observation.counts;
  OPENSSL_cleanse(&observation, sizeof(observation));
  observation = {};
  return counts;
}

void* Allocate(size_t size) {
  // Initializing spare capacity makes observation well-defined even when a
  // vector is destroyed before every allocated byte has been constructed.
  void* pointer = std::calloc(size ? size : 1, 1);
  if (!pointer) throw std::bad_alloc();
  Register(pointer, size);
  return pointer;
}

void Deallocate(void* pointer) noexcept {
  if (pointer && observation.active) {
    for (auto& allocation : observation.allocations) {
      if (allocation.pointer != pointer) continue;
      const auto* bytes = static_cast<const uint8_t*>(pointer);
      ++observation.counts.frees;
      bool uncleansed = false;
      if (allocation.require_zero) {
        ++observation.counts.required_zero_frees;
        for (size_t i = 0; i < allocation.size; ++i)
          uncleansed |= bytes[i] != 0;
      }
      for (const auto& pattern : observation.patterns) {
        if (!pattern.size || pattern.size > allocation.size) continue;
        for (size_t i = 0; i <= allocation.size - pattern.size; ++i)
          uncleansed |= std::memcmp(bytes + i, pattern.bytes.data(), pattern.size) == 0;
      }
      observation.counts.uncleansed += uncleansed;
      allocation = {};
      break;
    }
  }
  std::free(pointer);
}

void ObserverSelfTest() {
  for (bool cleanse : {false, true}) {
    Begin();
    auto* bytes = static_cast<uint8_t*>(::operator new(32));
    std::memset(bytes, 0x6a, 32);
    Register(bytes, 32, true);
    WatchPattern(ByteSpan(bytes, 32));
    if (cleanse) OPENSSL_cleanse(bytes, 32);
    ::operator delete(bytes);
    const auto counts = End();
    Check(counts.required_zero_frees == 1 && counts.uncleansed == (cleanse ? 0u : 1u),
          "observer detects a live secret and accepts its wiped buffer");
  }
}
}  // namespace

// std::vector<uint8_t> uses ordinary (not over-aligned) allocations. Replacing
// both scalar/array and sized/unsized forms keeps this driver portable across
// Windows, Linux and macOS standard libraries. Other executables are unaffected.
void* operator new(size_t size) { return Allocate(size); }
void* operator new[](size_t size) { return Allocate(size); }
void operator delete(void* pointer) noexcept { Deallocate(pointer); }
void operator delete(void* pointer, size_t) noexcept { Deallocate(pointer); }
void operator delete[](void* pointer) noexcept { Deallocate(pointer); }
void operator delete[](void* pointer, size_t) noexcept { Deallocate(pointer); }

namespace net::httpps {
class ProtocolRegressionPeer {
 public:
  static void Derivation(uint16_t suite, bool aliases, bool invalid) {
    Client client("example.test", {});
    client.suite_ = suite;
    Bytes original(SuiteHashLength(suite), 0x39);
    Bytes destination = original;
    const Bytes oversized_context(256, 0x12);
    const ByteSpan input = aliases ? ByteSpan(destination) : ByteSpan(original);
    const ByteSpan context = invalid ? ByteSpan(oversized_context)
                                    : ByteSpan(destination);
    const auto expected = SuiteLabel(suite, input, "traffic upd", context,
                                    SuiteHashLength(suite));
    Begin();
    Register(destination.data(), destination.size(), true);
    const bool ok = client.DeriveSecret(input, "traffic upd", context, &destination);
    // The failed derivation may retain its wiped allocation with size zero.
    OPENSSL_cleanse(destination.data(), destination.size());
    Bytes().swap(destination);
    const auto counts = End();
    Check(ok == !invalid && counts.required_zero_frees == 1 && !counts.uncleansed,
          "derivation wipes replaced storage on success and failure");
    // Repeat without disposing the result, to check aliased input/context bytes.
    destination = original;
    const ByteSpan retry_input = aliases ? ByteSpan(destination) : ByteSpan(original);
    Check(client.DeriveSecret(retry_input, "traffic upd",
                             invalid ? ByteSpan(oversized_context) : ByteSpan(destination),
                             &destination) == !invalid && destination == expected,
          "derivation reads aliased inputs before clearing the destination");
  }

  static void KeyUpdate(uint16_t suite, bool receiving) {
    Client client("example.test", {});
    client.suite_ = suite;
    client.state_ = Client::State::kEstablished;
    client.deadline_milliseconds_ = std::numeric_limits<int64_t>::max();
    const size_t length = SuiteHashLength(suite);
    client.c_app_ = Bytes(length, 0x61);
    client.s_app_ = Bytes(length, 0x73);
    client.sender_ = std::make_unique<RecordCipher>(client.c_app_, suite);
    client.receiver_ = std::make_unique<RecordCipher>(client.s_app_, suite);
    auto& traffic = receiving ? client.s_app_ : client.c_app_;
    const auto expected = SuiteLabel(suite, traffic, "traffic upd", {}, length);
    Bytes record, application;
    if (receiving) {
      RecordCipher peer(client.s_app_, suite);
      Check(peer.Seal(Bytes{24, 0, 0, 1, 0}, 22, &record), "encode peer KeyUpdate");
    }
    Begin();
    Register(traffic.data(), traffic.size(), true);
    WatchPattern(traffic);
    const bool ok = receiving ? client.Receive(record, &application)
                              : client.RequestKeyUpdate(false, &record);
    const auto counts = End();
    Check(ok && traffic == expected && application.empty(),
          "KeyUpdate installs the correct next-generation secret");
    Check(counts.required_zero_frees == 1 && !counts.uncleansed,
          "both KeyUpdate directions erase old traffic storage before release");
  }

  static void Hybrid(uint16_t group, int failure) {
    const uint16_t classical = group == 4588 ? 29 : group == 4587 ? 23 : 24;
    const size_t classical_size = classical == 29 ? 32 : classical == 23 ? 65 : 97;
    const size_t ciphertext_size = group == 4589 ? MLKEM1024_CIPHERTEXT_BYTES
                                                : MLKEM768_CIPHERTEXT_BYTES;
    Client client("example.test", {}), peer("example.test", {});
    uint8_t auth_private[32];
    X25519_keypair(client.A_.data(), auth_private);
    OPENSSL_cleanse(auth_private, sizeof(auth_private));
    Bytes client_share, peer_share;
    Check(client.GenerateTrafficShare(group, &client_share) &&
              peer.GenerateTrafficShare(classical, &peer_share), "hybrid key generation");
    const ByteSpan own = group == 4588 ? ByteSpan(client_share).last(classical_size)
                                      : ByteSpan(client_share).first(classical_size);
    Bytes expected_classical;
    Check(peer.TrafficAgreement(classical, own, &expected_classical), "peer agreement oracle");
    const ByteSpan kem_public = group == 4588 ? ByteSpan(client_share).first(client_share.size() - classical_size)
                                             : ByteSpan(client_share).subspan(classical_size);
    Bytes server_share(classical_size + ciphertext_size);
    uint8_t* ciphertext = server_share.data() + (group == 4588 ? 0 : classical_size);
    uint8_t* classical_output = server_share.data() + (group == 4588 ? ciphertext_size : 0);
    std::copy(peer_share.begin(), peer_share.end(), classical_output);
    std::array<uint8_t, MLKEM_SHARED_SECRET_BYTES> expected_kem{};
    CBS reader;
    CBS_init(&reader, kem_public.data(), kem_public.size());
    if (group == 4589) {
      MLKEM1024_public_key key;
      Check(MLKEM1024_parse_public_key(&key, &reader), "ML-KEM-1024 public share");
      MLKEM1024_encap(ciphertext, expected_kem.data(), &key);
    } else {
      MLKEM768_public_key key;
      Check(MLKEM768_parse_public_key(&key, &reader), "ML-KEM-768 public share");
      MLKEM768_encap(ciphertext, expected_kem.data(), &key);
    }
    if (failure == 1) {  // Decapsulation succeeds, but the classical point is invalid.
      std::fill(classical_output, classical_output + classical_size, 0);
      if (classical != 29) classical_output[0] = 4;
    } else if (failure == 2) {
      std::copy(client.B_.begin(), client.B_.end(), classical_output);
    } else if (failure == 3) {
      std::copy(client.A_.begin(), client.A_.end(), classical_output);
    } else if (failure == 4) {
      server_share.pop_back();
    } else if (failure == 5) {
      OPENSSL_cleanse(client.kem_seed_.data(), client.kem_seed_.size());
      client.kem_seed_.clear();
    }
    Bytes shared(64, 0xa9);
    Begin();
    Register(shared.data(), shared.size(), true);
    WatchPattern(expected_kem);
    WatchPattern(expected_classical);
    const bool ok = client.TrafficAgreement(group, server_share, &shared);
    const auto counts = End();
    Check(ok == (failure == 0) && counts.frees != 0 && !counts.uncleansed,
          "hybrid temporaries are erased on success and all rejection paths");
    Check(counts.required_zero_frees == (ok ? 1u : 0u),
          "successful hybrid replacement wipes the previous output allocation");
    if (ok) {
      Bytes expected;
      if (group == 4588) expected.assign(expected_kem.begin(), expected_kem.end());
      expected.insert(expected.end(), expected_classical.begin(), expected_classical.end());
      if (group != 4588) expected.insert(expected.end(), expected_kem.begin(), expected_kem.end());
      Check(shared == expected, "hybrid concatenation preserves each group's defined order");
      OPENSSL_cleanse(expected.data(), expected.size());
    }
    OPENSSL_cleanse(expected_kem.data(), expected_kem.size());
    OPENSSL_cleanse(expected_classical.data(), expected_classical.size());
    OPENSSL_cleanse(shared.data(), shared.size());
  }
};
}  // namespace net::httpps

int main() {
  ObserverSelfTest();
  for (uint16_t suite : {0x1301, 0x1302, 0x1303}) {
    for (bool alias : {false, true})
      for (bool invalid : {false, true})
        ProtocolRegressionPeer::Derivation(suite, alias, invalid);
    for (bool receiving : {false, true})
      ProtocolRegressionPeer::KeyUpdate(suite, receiving);
  }
  for (uint16_t group : {4587, 4588, 4589}) {
    for (int failure : {0, 1, 4, 5})
      ProtocolRegressionPeer::Hybrid(group, failure);
    if (group == 4588)
      for (int failure : {2, 3}) ProtocolRegressionPeer::Hybrid(group, failure);
  }
  std::cout << "32 derivation, KeyUpdate and hybrid erasure regressions passed\n";
}
