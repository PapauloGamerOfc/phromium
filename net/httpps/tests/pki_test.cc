// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/input.h"
#include "third_party/boringssl/src/pki/simple_path_builder_delegate.h"
#include "third_party/boringssl/src/pki/verify_signed_data.h"

namespace {
void Require(bool condition, const char* description) {
  if (!condition) {
    std::cerr << "FAIL: " << description << '\n';
    std::exit(1);
  }
}
}  // namespace

int main() {
  std::array<uint8_t, 32> private_key{}, public_key{};
  X25519_keypair(public_key.data(), private_key.data());
  std::vector<uint8_t> spki{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
                            0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};
  spki.insert(spki.end(), public_key.begin(), public_key.end());
  bssl::UniquePtr<EVP_PKEY> parsed;
  Require(bssl::ParsePublicKey(bssl::der::Input(spki), &parsed),
          "patched PKI parser accepts canonical X25519 SPKI");
  Require(EVP_PKEY_id(parsed.get()) == EVP_PKEY_X25519, "key type preserved");
  bssl::SimplePathBuilderDelegate ordinary_https(
      2048, bssl::SimplePathBuilderDelegate::DigestPolicy::kStrong);
  bssl::CertErrors errors;
  Require(!ordinary_https.IsPublicKeyAcceptable(parsed.get(), &errors),
          "ordinary HTTPS key policy still rejects X25519");
  // A NULL AlgorithmIdentifier parameter is forbidden for X25519.
  auto parameters = spki;
  parameters[1] += 2;
  parameters[3] += 2;
  parameters.insert(parameters.begin() + 9, {0x05, 0x00});
  Require(!bssl::ParsePublicKey(bssl::der::Input(parameters), &parsed),
          "X25519 parameters rejected");
  auto truncated = spki;
  truncated.pop_back();
  --truncated[1];
  --truncated[10];
  Require(!bssl::ParsePublicKey(bssl::der::Input(truncated), &parsed),
          "short X25519 key rejected");
  std::cout << "HTTPPS PKI parser and default HTTPS policy tests passed\n";
}
