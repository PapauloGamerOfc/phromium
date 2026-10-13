// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This isolated executable observes C++ buffers immediately BEFORE deallocation.
// It does not read freed memory, require an allocator-specific usable-size API,
// replace BoringSSL's allocator, or instrument the browser/interoperability binary.
#include "net/httpps/draft01.h"
#include "net/httpps/native_provider.h"
#include "net/httpps/pinning.h"

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

void PasswordPreparationErasure() {
  // The normalizer's successful password result is itself a secret, even if
  // normalization of the independent username failed. Exercise both inline-
  // sized and heap-sized strings without inspecting stack storage after its
  // lifetime. The observer examines only live allocations before release.
  for (size_t length : {8u, 48u}) {
    for (int rejection : {0, 1, 2, 3}) {
      auto credential = std::make_shared<PasswordCredential>();
      credential->service = "example.test";
      credential->username = "user";
      credential->password = "unprepared password";
      size_t calls = 0;
      credential->prepare_text = [length, rejection, &calls](std::string_view value)
          -> std::optional<std::string> {
        ++calls;
        if (value == "user") {
          if (rejection == 1) return std::nullopt;
          return "user";
        }
        if (rejection == 2) return std::nullopt;
        if (rejection == 3) return std::string{};
        std::string normalized(length, 'P');  // Public synthetic test secret.
        WatchPattern(StringBytes(normalized));
        return normalized;
      };
      ClientOptions options;
      options.password = credential;
      Begin();
      {
        Client client("example.test", {}, true, options);
        // Route 0 normalizes both values successfully, then fails the missing
        // provider check. Routes 1/2/3 reject username/password/empty password.
        // None may leak a normalized copy or emit an unauthenticated hello.
        Check(!client.Start() && client.TakeOutput().empty(),
              "invalid password configuration rejects before ClientHello");
      }
      const auto counts = End();
      Check(calls == 2 && counts.frees && !counts.uncleansed,
            "normalized passwords are wiped on username and later configuration failures");
    }
  }
  std::cout << "8 password preparation erasure/rejection controls passed\n";
}

Bytes RetryRecord(uint16_t group) {
  Bytes body{3, 3,
      0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,
      0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
      0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,
      0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c,
      0, 0x13, 1, 0};
  Bytes extensions{0,43,0,2,4,0};
  if (group)
    extensions.insert(extensions.end(), {0,51,0,2,
        static_cast<uint8_t>(group >> 8), static_cast<uint8_t>(group)});
  else
    extensions.insert(extensions.end(), {0,44,0,3,0,1,7});
  body.push_back(0);
  body.push_back(static_cast<uint8_t>(extensions.size()));
  body.insert(body.end(), extensions.begin(), extensions.end());
  Bytes record{22,3,3,0,static_cast<uint8_t>(body.size()+4),
               2,0,0,static_cast<uint8_t>(body.size())};
  record.insert(record.end(), body.begin(), body.end());
  return record;
}

void PinningErasure(uint16_t suite, bool valid) {
  const size_t length = SuiteHashLength(suite);
  PinningCache cache(4, [] { return int64_t{1000}; });
  Bytes root(length, 0x73), transcript{1, 2, 3, 4};
  Secret private_key{}, public_key{};
  private_key.fill(0x41);
  X25519_public_from_private(public_key.data(), private_key.data());
  OPENSSL_cleanse(private_key.data(), private_key.size());
  Bytes spki{0x30,0x2a,0x30,5,6,3,0x2b,0x65,0x6e,3,0x21,0};
  spki.insert(spki.end(), public_key.begin(), public_key.end());
  auto first = cache.Begin("example.test", 343, "isolation");
  const Bytes enrollment{0, 0,1,7, 0,0,2,88};
  Check(first->Verify(enrollment, suite, root, transcript, spki) && first->Commit(),
        "pinning enrollment fixture");
  auto next = cache.Begin("example.test", 343, "isolation");
  auto previous = SuiteLabel(suite, root, "pinning secret", SuiteHash(suite, transcript), length);
  root.assign(length, 0x72);
  auto derived = SuiteLabel(suite, root, "pinning proof 1", SuiteHash(suite, transcript), length);
  auto label = StringBytes("pinning proof 2");
  auto digest = SuiteHash(suite, spki);
  Bytes proof_input;
  proof_input.reserve(label.size() + derived.size() + digest.size());
  proof_input.insert(proof_input.end(), label.begin(), label.end());
  proof_input.insert(proof_input.end(), derived.begin(), derived.end());
  proof_input.insert(proof_input.end(), digest.begin(), digest.end());
  auto proof = SuiteMac(suite, previous, proof_input);
  if (!valid) proof[0] ^= 1;
  Bytes response{static_cast<uint8_t>(length)};
  response.insert(response.end(), proof.begin(), proof.end());
  response.insert(response.end(), enrollment.begin() + 1, enrollment.end());
  Begin();
  WatchPattern(derived);
  const bool accepted = next->Verify(response, suite, root, transcript, spki);
  const auto counts = End();
  Check(accepted == valid && counts.frees && !counts.uncleansed,
        "pinning accepts only valid proofs and releases no copy of their derived secret");
  for (auto* value : {&root, &previous, &derived, &proof_input, &proof})
    OPENSSL_cleanse(value->data(), value->size());
}

void GostExpansionErasure(std::string_view library, std::string_view module) {
  const auto provider = NativeProvider::Load(library, module);
  Check(provider && provider->SupportsGost(), "explicit GOST provider fixture");
  const Bytes secret(32, 0x35);
  for (size_t info_length : {0u, 4u, 64u, 1024u}) {
    const Bytes info(info_length, 0x12);
    for (size_t length : {0u, 1u, 31u, 32u, 33u, 63u, 64u, 65u, 96u, 8160u}) {
      // Independent HKDF expansion recurrence; no call to GostExpand for the
      // oracle. Include a full first block even for a short requested output.
      Bytes expected, previous;
      expected.reserve(std::max<size_t>(length, 32));
      for (size_t counter = 1; expected.size() < std::max<size_t>(length, 32); ++counter) {
        Bytes input;
        input.reserve(previous.size() + info.size() + 1);
        input.insert(input.end(), previous.begin(), previous.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(static_cast<uint8_t>(counter));
        auto block = provider->GostMac(secret, input);
        Check(block.size() == 32, "GOST oracle HMAC");
        OPENSSL_cleanse(previous.data(), previous.size());
        previous = std::move(block);
        const size_t count = std::min(previous.size(), std::max<size_t>(length, 32) - expected.size());
        expected.insert(expected.end(), previous.begin(), previous.begin() + count);
        OPENSSL_cleanse(input.data(), input.size());
      }
      Begin();
      WatchPattern(ByteSpan(expected).first(32));
      auto actual = provider->GostExpand(secret, info, length);
      const auto counts = End();
      Check(actual.size() == length &&
                std::equal(actual.begin(), actual.end(), expected.begin()) &&
                (!length || counts.frees) && !counts.uncleansed,
            "GOST expansion matches the recurrence and wipes all temporary block copies");
      for (auto* value : {&actual, &expected, &previous})
        OPENSSL_cleanse(value->data(), value->size());
    }
  }
  Check(provider->GostExpand(secret, {}, 8161).empty(), "GOST HKDF length bound");
  const auto no_gost = NativeProvider::Load(library);
  Check(no_gost && !no_gost->SupportsGost() && no_gost->GostExpand(secret, {}, 64).empty(),
        "absent optional GOST provider cannot produce a derived secret");
  std::cout << "40 GOST expansion erasure cases and 2 rejection controls passed\n";
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
  static void Diagnostics() {
    for (size_t length : {32u, 48u, 64u}) {
      for (bool exporter : {false, true}) {
        for (int failure : {0, 1, 2}) {
          Bytes secret(length, 0xb7);  // Public synthetic test secret.
          const std::string pattern = "b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7";
          size_t calls = 0;
          ClientOptions options;
          options.authorize_test_diagnostics = true;
          options.authorize_exporter_diagnostics = exporter;
          options.diagnostic_sink = [&](std::string_view entry) {
            ++calls;
            Register(const_cast<char*>(entry.data()), entry.size(), true);
            Check(entry.ends_with('\n') && entry.find(pattern) != std::string_view::npos,
                  "authorized diagnostic contains the original synthetic secret");
            if (failure == 2)
              throw std::ios_base::failure("synthetic diagnostic sink unavailable");
            return failure == 0;
          };
          Client client("example.test", {}, true, options);
          const auto label = exporter ? "TLS20_EXPORTER_SECRET" :
              "TLS20_CLIENT_HANDSHAKE_TRAFFIC_SECRET";
          Begin();
          WatchPattern(StringBytes(pattern));
          bool escaped = false;
          try {
            client.Diagnostic(label, secret, exporter);
            client.Diagnostic(label, secret, exporter);
          } catch (const std::ios_base::failure&) {
            escaped = true;
          }
          const auto counts = End();
          Check(!escaped && calls == (failure ? 1u : 2u) &&
                    client.diagnostic_failed() == (failure != 0) &&
                    client.state_ == Client::State::kNew &&
                    client.error() == Client::Error::kNone &&
                    client.TakeOutput().empty(),
                "false and throwing sinks disable only diagnostics and report a local flag");
          Check(counts.required_zero_frees == calls && !counts.uncleansed,
                "diagnostic entries have no uncleansed reallocation or final release");
        }
      }
    }
    for (bool authorize : {false, true}) {
      size_t calls = 0;
      ClientOptions options;
      options.authorize_test_diagnostics = authorize;
      options.diagnostic_sink = [&](std::string_view) { ++calls; return true; };
      Client client("example.test", {}, true, options);
      const Bytes secret(32, 0xb7);
      Begin();
      client.Diagnostic("TLS20_EXPORTER_SECRET", secret, true);
      if (!authorize)
        client.Diagnostic("TLS20_CLIENT_HANDSHAKE_TRAFFIC_SECRET", secret);
      const auto counts = End();
      Check(!calls && !counts.frees && !client.diagnostic_failed(),
            "disabled diagnostics and exporter category do not construct entries");
    }
    std::cout << "18 diagnostic erasure/failure cases and 2 authorization controls passed\n";
  }

  static void RetrySecrets(uint16_t first, uint16_t next) {
    size_t old_allocations = 0;
    bool accepted, refreshed;
    const bool allowed = next != first && next != 0xffff;
    {
      ClientOptions options;
      options.groups = {first};
      if (next && next != first && next != 0xffff) options.groups.push_back(next);
      Client client("example.test", {}, true, options);
      Check(client.Start(), "initial traffic share before retry");
      client.TakeOutput();
      auto old_scalar = client.ec_private_;
      auto old_seed = client.kem_seed_;
      auto old_x = client.b_;
      Begin();
      for (auto* secret : {&client.ec_private_, &client.kem_seed_}) {
        if (secret->empty()) continue;
        ++old_allocations;
        Register(secret->data(), secret->size(), true);
        // FFDHE scalars are padded; watch the random suffix, not leading zeros.
        WatchPattern(ByteSpan(*secret).last(std::min<size_t>(32, secret->size())));
      }
      Bytes application;
      accepted = client.Receive(RetryRecord(next), &application);
      if (next == 0) {
        refreshed = client.ec_private_ == old_scalar && client.kem_seed_ == old_seed && client.b_ == old_x;
      } else if (accepted) {
        const bool next_x = next == 29 || next == 4588;
        const bool next_kem = next >= 4587 && next <= 4589;
        refreshed = (next_x || client.b_ == Secret{}) &&
                    (next_kem || client.kem_seed_.empty()) &&
                    (!next_x || client.ec_private_.empty()) &&
                    !client.TakeOutput().empty();
      } else {
        refreshed = client.error() == Client::Error::kProtocol;
      }
      for (auto* bytes : {&old_scalar, &old_seed}) OPENSSL_cleanse(bytes->data(), bytes->size());
      OPENSSL_cleanse(old_x.data(), old_x.size());
      // Keep observing through destruction: shrinking a scalar must not leave
      // the tail of the old key beyond vector::size() in its eventual free.
    }
    const auto counts = End();
    Check(accepted == allowed && refreshed && counts.required_zero_frees == old_allocations &&
              !counts.uncleansed, "HRR growth/shrink/family change and rejection erase old keys");
  }

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

int main(int argc, char** argv) {
  ObserverSelfTest();
  if (argc == 2 && std::string_view(argv[1]) == "--diagnostics") {
    ProtocolRegressionPeer::Diagnostics();
    return 0;
  }
  if (argc == 2 && std::string_view(argv[1]) == "--password-preparation") {
    PasswordPreparationErasure();
    return 0;
  }
  if (argc == 4 && std::string_view(argv[1]) == "--gost") {
    GostExpansionErasure(argv[2], argv[3]);
    return 0;
  }
  Check(argc == 1, "unexpected erasure test arguments");
  ProtocolRegressionPeer::Diagnostics();
  PasswordPreparationErasure();
  for (uint16_t suite : {0x1301, 0x1302, 0x1303}) {
    for (bool alias : {false, true})
      for (bool invalid : {false, true})
        ProtocolRegressionPeer::Derivation(suite, alias, invalid);
    for (bool receiving : {false, true})
      ProtocolRegressionPeer::KeyUpdate(suite, receiving);
    for (bool valid : {false, true}) PinningErasure(suite, valid);
  }
  for (uint16_t group : {4587, 4588, 4589}) {
    for (int failure : {0, 1, 4, 5})
      ProtocolRegressionPeer::Hybrid(group, failure);
    if (group == 4588)
      for (int failure : {2, 3}) ProtocolRegressionPeer::Hybrid(group, failure);
  }
  for (auto [first, next] : {std::pair<uint16_t, uint16_t>{23,24}, {24,23},
       {23,25}, {25,23}, {23,256}, {256,23}, {24,29}, {29,24},
       {4587,4589}, {4589,4587}, {4588,23}, {23,4588}, {23,0}, {23,23}, {23,0xffff}})
    ProtocolRegressionPeer::RetrySecrets(first, next);
  std::cout << "53 derivation, KeyUpdate, hybrid, HRR and pinning erasure regressions passed\n";
  return 0;
}
