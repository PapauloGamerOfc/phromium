// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/integrity_only.h"

#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net::httpps {
namespace {

bool Validate(uint16_t suite, ByteSpan key, ByteSpan nonce, ByteSpan header,
              size_t length) {
  const size_t size = IntegrityTagLength(suite);
  return size && key.size() == size && nonce.size() == size &&
         header.size() == 5 && header[0] == 23 && header[1] == 3 &&
         header[2] == 3 && length <= 65535 &&
         ((size_t{header[3]} << 8) | header[4]) == length;
}

Bytes Tag(uint16_t suite, ByteSpan key, ByteSpan nonce, ByteSpan header,
          ByteSpan plaintext) {
  Bytes input;
  input.reserve(nonce.size() + header.size() + plaintext.size());
  input.insert(input.end(), nonce.begin(), nonce.end());
  input.insert(input.end(), header.begin(), header.end());
  input.insert(input.end(), plaintext.begin(), plaintext.end());
  // Reuse the provider-backed SHA-256/SHA-384 HMAC, not an AEAD cipher. The
  // calling record layer still selects c0b4/c0b5 for the complete key schedule.
  return SuiteMac(suite == 0xc0b4 ? 0x1301 : 0x1302, key, input);
}

}  // namespace

size_t IntegrityTagLength(uint16_t suite) {
  return suite == 0xc0b4 ? 32 : suite == 0xc0b5 ? 48 : 0;
}

bool IntegrityProtect(uint16_t suite, ByteSpan key, ByteSpan nonce,
                      ByteSpan header, ByteSpan plaintext, Bytes* output) {
  if (!output)
    return false;
  output->clear();
  const size_t size = IntegrityTagLength(suite);
  if (plaintext.size() > 65535 - size ||
      !Validate(suite, key, nonce, header, plaintext.size() + size))
    return false;
  auto tag = Tag(suite, key, nonce, header, plaintext);
  if (tag.size() != size)
    return false;
  output->assign(plaintext.begin(), plaintext.end());
  output->insert(output->end(), tag.begin(), tag.end());
  return true;
}

bool IntegrityUnprotect(uint16_t suite, ByteSpan key, ByteSpan nonce,
                        ByteSpan header, ByteSpan protected_data, Bytes* output) {
  if (!output)
    return false;
  output->clear();
  const size_t size = IntegrityTagLength(suite);
  if (!Validate(suite, key, nonce, header, protected_data.size()) ||
      protected_data.size() < size)
    return false;
  const auto plaintext = protected_data.first(protected_data.size() - size);
  const auto received = protected_data.last(size);
  const auto expected = Tag(suite, key, nonce, header, plaintext);
  if (expected.size() != size ||
      CRYPTO_memcmp(expected.data(), received.data(), size) != 0)
    return false;
  output->assign(plaintext.begin(), plaintext.end());
  return true;
}

}  // namespace net::httpps
