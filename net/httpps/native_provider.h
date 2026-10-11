// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_HTTPPS_NATIVE_PROVIDER_H_
#define NET_HTTPPS_NATIVE_PROVIDER_H_

#include "net/httpps/draft01.h"

#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_NATIVE_EXPORT
#define HTTPPS_FOREIGN_HANDLE
#else
#include "base/memory/raw_ptr_exclusion.h"
#define HTTPPS_NATIVE_EXPORT NET_EXPORT_PRIVATE
#define HTTPPS_FOREIGN_HANDLE RAW_PTR_EXCLUSION
#endif

namespace net::httpps {
class NativeTrafficKey;
class NativePasswordState;
class NativeGostRecord;
// No discovery, environment activation or global OpenSSL configuration. The
// application owns selection, provenance and maintenance of this native code.
// Public C ABI handles never cross into BoringSSL or another provider instance.
class HTTPPS_NATIVE_EXPORT NativeProvider : public std::enable_shared_from_this<NativeProvider> {
 public:
  static std::shared_ptr<NativeProvider> Load(std::string_view absolute_path,
                                             std::string_view gost_module = {});
  ~NativeProvider();
  bool SupportsGroup(uint16_t group) const;
  bool SupportsSM() const;
  bool SupportsGost() const;
  Bytes GostHash(ByteSpan input, bool wide = false) const;
  Bytes GostMac(ByteSpan key, ByteSpan input, bool wide = false) const;
  Bytes GostExpand(ByteSpan secret, ByteSpan info, size_t length) const;
  bool GostMgm(bool encrypt, uint16_t suite, ByteSpan key, ByteSpan nonce,
                ByteSpan aad, ByteSpan input, Bytes* output) const;
  bool SupportsPasswordAead() const;
  bool PasswordAead(bool encrypt, ByteSpan key, ByteSpan nonce,
                    ByteSpan aad, ByteSpan input, Bytes* output) const;
  bool ProtectUsername(ByteSpan spki, ByteSpan prepared_username, Bytes* output) const;
  Bytes Sm3(ByteSpan input) const;
  Bytes Sm3Mac(ByteSpan key, ByteSpan input) const;
  Bytes Sm3Expand(ByteSpan secret, ByteSpan info, size_t length) const;
  bool Sm4(bool encrypt, uint16_t suite, ByteSpan key, ByteSpan nonce,
           ByteSpan aad, ByteSpan input, Bytes* output) const;
  bool VerifySm2Signature(ByteSpan spki, ByteSpan message, ByteSpan signature,
                          std::string_view identifier) const;
  bool VerifyPublicSignature(ByteSpan spki, ByteSpan message, ByteSpan signature,
                              uint16_t scheme, bool certificate_encoding = false) const;
  // Returns the actual independently validated path. Explicit roots only;
  // no default/system store or certificate URL fetching is installed.
  std::optional<std::vector<std::string>> VerifyCertificatePath(
      const std::vector<std::string>& chain, const std::vector<std::string>& roots,
      std::string_view hostname, bool server = true, bool partial_chain = false) const;
  std::unique_ptr<NativeTrafficKey> Generate(uint16_t group, Bytes* public_key);
  std::unique_ptr<NativePasswordState> PasswordExchange(std::string_view absolute_helper,
      ByteSpan base, ByteSpan client_random, uint16_t group, unsigned hash_bits);
 private:
  bool CipherAead(bool encrypt, uint16_t suite, ByteSpan key, ByteSpan nonce,
                  ByteSpan aad, ByteSpan input, Bytes* output) const;
  struct Impl;
  NativeProvider();
  std::unique_ptr<Impl> impl_;
  friend class NativeTrafficKey;
  friend class NativePasswordState;
};

// One traffic epoch/direction. TLSTREE caches are never shared or rewound.
class HTTPPS_NATIVE_EXPORT NativeGostRecord {
 public:
  NativeGostRecord(std::shared_ptr<NativeProvider> provider, uint16_t suite, ByteSpan key);
  ~NativeGostRecord();
  NativeGostRecord(const NativeGostRecord&) = delete;
  NativeGostRecord& operator=(const NativeGostRecord&) = delete;
  bool Crypt(bool encrypt, uint64_t sequence, ByteSpan nonce, ByteSpan aad,
              ByteSpan input, Bytes* output);
 private:
  std::shared_ptr<NativeProvider> provider_;
  uint16_t suite_;
  Bytes root_;
  std::array<Bytes, 3> keys_;
  std::array<uint64_t, 3> values_{};
  bool initialized_ = false;
  uint64_t next_sequence_ = 0;
  bool failed_ = false;
};
HTTPPS_NATIVE_EXPORT size_t GostTagLength(uint16_t suite);
HTTPPS_NATIVE_EXPORT uint64_t GostSequenceLimit(uint16_t suite);

// The separately selected original MIT helper uses the SAME provider's public
// ABI and private context. Test-only helper builds are never accepted here.
class HTTPPS_NATIVE_EXPORT NativePasswordState {
 public:
  ~NativePasswordState();
  NativePasswordState(const NativePasswordState&) = delete;
  NativePasswordState& operator=(const NativePasswordState&) = delete;
  bool Commit(Bytes* public_share);
  bool Finish(ByteSpan peer, Bytes* shared_secret);
 private:
  NativePasswordState();
  struct Impl;
  std::unique_ptr<Impl> impl_;
  friend class NativeProvider;
};

class HTTPPS_NATIVE_EXPORT NativeTrafficKey {
 public:
  ~NativeTrafficKey();
  NativeTrafficKey(const NativeTrafficKey&) = delete;
  NativeTrafficKey& operator=(const NativeTrafficKey&) = delete;
  bool Agree(ByteSpan peer, Bytes* shared);
 private:
  NativeTrafficKey(std::shared_ptr<NativeProvider> provider, uint16_t group, void* key);
  std::shared_ptr<NativeProvider> provider_;
  uint16_t group_;
  // Allocated by a separately loaded OpenSSL instance, not PartitionAlloc.
  HTTPPS_FOREIGN_HANDLE void* key_;
  friend class NativeProvider;
};
}  // namespace net::httpps
#undef HTTPPS_NATIVE_EXPORT
#undef HTTPPS_FOREIGN_HANDLE
#endif
