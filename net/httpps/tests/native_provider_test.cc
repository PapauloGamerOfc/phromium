// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/httpps/native_provider.h"

#include <cstdlib>
#include <iostream>
#include <barrier>
#include <thread>
#include <chrono>
#include <filesystem>

void RunNativeStageLifecycleTests(const std::shared_ptr<net::httpps::NativeProvider>& provider);

namespace {
using namespace net::httpps;
void Check(bool value, const char* message) {
  if (!value) {
    std::cerr << "Native provider failure: " << message << '\n';
    std::exit(1);
  }
}
Bytes Hex(std::string_view input) {
  constexpr std::string_view alphabet = "0123456789abcdef";
  Bytes result;
  for (size_t i = 0; i < input.size(); i += 2) {
    auto high = alphabet.find(input[i]), low = alphabet.find(input[i + 1]);
    Check(high < 16 && low < 16, "fixture encoding");
    result.push_back(static_cast<uint8_t>((high << 4) | low));
  }
  return result;
}

void PersistentWorkerLifetimes(std::string_view library, std::string_view helper) {
  // Creator/consumer workers remain alive while a different thread destroys
  // their provider and keys. In particular, thread exit must not visit TLS
  // handlers carrying the already-freed OSSL_LIB_CTX.
  constexpr size_t kWorkers = 4;
  constexpr size_t kRounds = 16;
  std::barrier phases(static_cast<std::ptrdiff_t>(kWorkers + 1));
  std::shared_ptr<NativeProvider> provider;
  std::array<std::unique_ptr<NativeTrafficKey>, kWorkers> transferred;
  std::array<std::unique_ptr<NativePasswordState>, kWorkers> passwords;
  std::array<Bytes, kWorkers> commitments;
  std::vector<std::thread> workers;
  for (size_t index = 0; index < kWorkers; ++index) {
    workers.emplace_back([&, index] {
      for (size_t round = 0; round < kRounds; ++round) {
        if (index == 0) {
          Check(!NativeProvider::Load(library, std::string(library) + ".missing-test-provider"),
                "worker partial initialization cleans context and TLS");
          provider = NativeProvider::Load(library);
          Check(provider != nullptr, "worker creates private context");
        }
        phases.arrive_and_wait();
        {
          const auto owned = provider;
          Check(owned->Sm3(Bytes{1, 2, 3}).size() == 32, "shared provider worker hash");
          Bytes public_key, peer_key, shared;
          transferred[index] = owned->Generate(31, &public_key);
          const auto peer = owned->Generate(31, &peer_key);
          Check(transferred[index] && peer && transferred[index]->Agree(peer_key, &shared),
                "worker key and random state");
          Check(!owned->VerifyPublicSignature(Bytes{0x30, 0}, Bytes{1}, Bytes{1}, 0x0808),
                "error return cleans foreign thread state");
          if (!helper.empty()) {
            passwords[index] = owned->PasswordExchange(helper, Bytes(32, 1), Bytes(32, 2), 23, 256);
            Check(passwords[index] && passwords[index]->Commit(&commitments[index]),
                  "worker PAKE create and commit");
          }
        }
        phases.arrive_and_wait();
        // Main frees transferred keys + final shared_ptr before releasing us.
        phases.arrive_and_wait();
      }
    });
  }
  for (size_t round = 0; round < kRounds; ++round) {
    phases.arrive_and_wait();
    phases.arrive_and_wait();
    if (!helper.empty()) {
      for (size_t index = 0; index < kWorkers; ++index) {
        if (round % 2) {
          Bytes secret;
          Check(passwords[index]->Finish(commitments[(index + 1) % kWorkers], &secret),
                "cross-thread PAKE finish");
        }
        // Even rounds also exercise destruction of unfinished helper state.
        passwords[index].reset();
      }
    }
    for (auto& key : transferred) key.reset();
    provider.reset();
    phases.arrive_and_wait();
  }
  for (auto& worker : workers) worker.join();
  std::cout << "64 persistent-worker context lifetimes and cross-thread key destruction passed; PAKE="
            << !helper.empty() << '\n';
}
}

void RunNativeProviderTests(std::string_view library, std::string_view helper) {
  using namespace net::httpps;
  PersistentWorkerLifetimes(library, helper);
  Check(!NativeProvider::Load("") && !NativeProvider::Load("libcrypto.so"), "no discovery or relative loading");
  auto provider = NativeProvider::Load(library);
  Check(provider && provider->SupportsSM(), "explicit provider and SM capability");
  RunNativeStageLifecycleTests(provider);
  Check(provider->Sm3(Bytes{'a','b','c'}) == Hex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"), "published SM3 abc vector");
  const auto key = Hex("0123456789abcdeffedcba9876543210");
  const auto nonce = Hex("00001234567800000000abcd");
  const auto aad = Hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
  const auto plain = Hex("aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd"
                         "eeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa");
  // RFC 8998 Appendix A, not computed using this implementation or server.
  for (uint16_t suite : {0x00c6, 0x00c7}) {
    const auto expected = suite == 0x00c6
        ? Hex("17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735"
              "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d"
              "83de3541e4c2b58177e065a9bf7b62ec")
        : Hex("48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094"
              "fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b"
              "16842d4fa186f56ab33256971fa110f4");
    Bytes output;
    Check(provider->Sm4(true, suite, key, nonce, aad, plain, &output) && output == expected, "published SM4 AEAD vector");
    Check(provider->Sm4(false, suite, key, nonce, aad, expected, &output) && output == plain, "published SM4 decrypt");
    for (size_t i = 0; i < expected.size(); ++i) {
      auto modified = expected;
      modified[i] ^= 1;
      output = Bytes{99};
      Check(!provider->Sm4(false, suite, key, nonce, aad, modified, &output) && output.empty(), "every corrupt byte fails without plaintext");
    }
    Check(provider->Sm4(true, suite, key, nonce, {}, {}, &output), "empty AEAD plaintext");
    const auto empty_ciphertext = output;
    Check(provider->Sm4(false, suite, key, nonce, {}, empty_ciphertext, &output) && output.empty(), "empty AEAD roundtrip");
    ClientOptions options;
    options.cipher_suites = {suite};
    Client missing("localhost", {}, true, options);
    Check(!missing.Start(), "SM cannot be advertised without actual provider");
    Check(SuiteHashId(suite) != SuiteHashId(0x1301), "SM3 is not SHA256 despite equal size");
  }
  for (uint16_t group : {30, 31, 32, 33, 41}) {
    Bytes A, B, one, two;
    auto left = provider->Generate(group, &A), right = provider->Generate(group, &B);
    Check(left && right && left->Agree(B, &one) && right->Agree(A, &two) && one == two && !one.empty(), "native agreement symmetry");
    Check(!left->Agree({}, &one) && !left->Agree(Bytes(B.size()), &one), "empty, invalid and low-order shares rejected");
    B.pop_back();
    Check(!left->Agree(B, &one), "truncated shares rejected");
  }
  std::cout << "Native provider RFC 8998 vectors, tampering, group agreement and opt-in tests passed\n";
}

void RunGostProviderTests(std::string_view library, std::string_view module) {
  using namespace net::httpps;
  auto provider = NativeProvider::Load(library, module);
  Check(provider && provider->SupportsGost(), "explicit GOST capability");
  RunNativeStageLifecycleTests(provider);
#if defined(_WIN32)
  // A trusted JSON profile encodes paths as UTF-8, including characters outside
  // the current Windows ANSI code page. This is intentionally constructed here
  // rather than passed through the test driver's narrow main(argc, argv).
  auto copied_module = std::filesystem::temp_directory_path() /
      (std::filesystem::path(u8"httpps-gost-\u6d4b\u8bd5-\u00e7-").native() +
       std::to_wstring(std::chrono::steady_clock::now().time_since_epoch().count()) + L".dll");
  Check(std::filesystem::copy_file(std::filesystem::u8path(module), copied_module),
        "copy explicitly selected Unicode GOST fixture");
  const auto utf8 = copied_module.u8string();
  {
    const auto unicode_provider = NativeProvider::Load(library,
        std::string_view(reinterpret_cast<const char*>(utf8.data()), utf8.size()));
    Check(unicode_provider && unicode_provider->SupportsGost() &&
          unicode_provider->GostHash({}) == provider->GostHash({}),
          "Unicode GOST module exact load and private-context hashing");
  }
  Check(std::filesystem::remove(copied_module), "Unicode GOST fixture releases DLL before cleanup");
#endif
  Bytes key(32); for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i);
  const auto message = Hex("0126bdb87800af214341456563780100");
  Check(provider->GostMac(key, message) == Hex("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"), "RFC7836 Streebog256 HMAC");
  Check(provider->GostMac(key, message, true) == Hex("a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"), "RFC7836 Streebog512 HMAC");
  Check(provider->GostHash({}) == Hex("3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb"), "published Streebog empty input");
  struct Vector { uint16_t suite; std::string_view key, nonce, aad, plain, encrypted; };
  for (const auto& v : {
      Vector{0xc103, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", "1122334455667700ffeeddccbbaa9988",
        "0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505",
        "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011aabbcc",
        "a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb2c7552cf5d656f40c34f5c46e8bb0e29fcdb4c"},
      Vector{0xc104, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "12def06b3c130a59",
        "01010101010101010202020202020202030303030303030304040404040404040505050505050505ea",
        "ffeeddccbbaa998811223344556677008899aabbcceeff0a001122334455667799aabbcceeff0a001122334455667788aabbcceeff0a00112233445566778899aabbcc",
        "c795066c5f9ea03b85113342459185ae1f2e00d6bf2b785d940470b8bb9c8e7d9a5dd3731f7ddc70ec27cb0ace6fa57670f65c646abb75d547aa37c3bcb5c34e03bb9ca7928069aa10fd10"}}) {
    Bytes output;
    Check(provider->GostMgm(true, v.suite, Hex(v.key), Hex(v.nonce), Hex(v.aad), Hex(v.plain), &output) && output == Hex(v.encrypted), "RFC9058 MGM encryption");
    Check(provider->GostMgm(false, v.suite, Hex(v.key), Hex(v.nonce), Hex(v.aad), Hex(v.encrypted), &output) && output == Hex(v.plain), "RFC9058 MGM decryption");
    auto expected = Hex(v.encrypted);
    for (size_t i = 0; i < expected.size(); ++i) {
      auto changed = expected; changed[i] ^= 1;
      Check(!provider->GostMgm(false, v.suite, Hex(v.key), Hex(v.nonce), Hex(v.aad), changed, &output) && output.empty(), "MGM all tampered bytes rejected");
    }
  }
  for (uint16_t group = 34; group <= 40; ++group) {
    Bytes A, B, one, two;
    auto left = provider->Generate(group, &A), right = provider->Generate(group, &B);
    Check(left && right && left->Agree(B, &one) && right->Agree(A, &two) && one == two, "GOST native group agreement");
    Check(!left->Agree(Bytes(B.size()), &one) && !left->Agree(Bytes(B.size(), 255), &one), "invalid GOST points rejected");
  }
  for (auto suite : {0xc104, 0xc105}) {
    auto root = Hex(suite == 0xc105 ? "475e4c514cc6318c3a5f000f1265bd1ab5f0de1af357ed0079ec5ff0afbd030c" :
                                                    "15d92c5147b21310ededf55b3d7ab776817d6fe2fcf230d7e3f29275f6e241ec");
    NativeGostRecord record(provider, suite, root);
    const unsigned boundary = suite == 0xc105 ? 8 : 128;
    for (unsigned i = 0; i <= boundary; ++i) {
      Bytes nonce(GostTagLength(suite)), actual, expected;
      nonce.back() = static_cast<uint8_t>(i);
      Check(record.Crypt(true, i, nonce, { }, message, &actual), "sequential TLSTREE records");
      if (i == boundary) {
        auto derived = Hex(suite == 0xc105 ? "d3cd87d5687407823978344c06b928a85898b739a31d3de5ff2b788ef39196ed" :
                                          "93d5d6e1036fdfb3efbf31e6da5eece685171c977ff9cd6c3a3f67c0224ab6eb");
        Check(provider->GostMgm(true, suite, derived, nonce, {}, message, &expected) && actual == expected, "RFC9367 TLSTREE rollover key");
      }
    }
    Bytes output;
    Check(!record.Crypt(true, 0, Bytes(GostTagLength(suite)), {}, message, &output), "TLSTREE cannot rewind nonce or epoch");
  }
  Check(SuiteHashId(0xc103) != SuiteHashId(0x1301) && SuiteHashId(0xc103) != SuiteHashId(0xc6), "three distinct 32-byte hashes");
  std::cout << "GOST published RFC7836/9058/9367 vectors, tampering, agreement and cached TLSTREE passed\n";
}
