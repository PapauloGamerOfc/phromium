// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTPPS_PINNING_H_
#define NET_HTTPPS_PINNING_H_

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "net/httpps/draft01.h"

#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_PIN_EXPORT
#else
#define HTTPPS_PIN_EXPORT NET_EXPORT
#endif

namespace net::httpps {

struct PinStore;
struct PinEntry;

// A one-use exchange snapshot. The engine verifies after authenticating server
// Finished, before disclosing a client identity, and commits only after its own
// Finished is flushed. Failure/destruction never removes an outstanding pin.
class HTTPPS_PIN_EXPORT PinAttempt {
 public:
  ~PinAttempt();
  PinAttempt(const PinAttempt&) = delete;
  PinAttempt& operator=(const PinAttempt&) = delete;
  Bytes extension() const;
  bool had_pin() const;
  bool Verify(std::optional<ByteSpan> server_extension, uint16_t suite,
              ByteSpan handshake_secret, ByteSpan transcript_through_sh,
              ByteSpan effective_spki, const NativeProvider* provider = nullptr);
  bool Commit();

 private:
  friend class PinningCache;
  PinAttempt(std::shared_ptr<PinStore> store, std::string key,
             std::shared_ptr<const PinEntry> previous);
  std::shared_ptr<PinStore> store_;
  std::string key_;
  std::shared_ptr<const PinEntry> previous_;
  std::shared_ptr<const PinEntry> replacement_;
  bool used_ = false;
  bool verified_ = false;
  bool completed_ = false;
  bool supported_ = false;
};

// Explicit in-memory continuity policy, NOT durable browser pin storage.
// The partition must include the caller's privacy/network context, route, proxy
// role and trust policy. Pins cannot migrate between partitions or be evicted
// while live. The caller must retain this cache while promising pin continuity.
class HTTPPS_PIN_EXPORT PinningCache {
 public:
  explicit PinningCache(size_t capacity = 4096,
      std::function<int64_t()> clock = MonotonicMilliseconds,
      size_t max_bytes = 16 * 1024 * 1024);
  ~PinningCache();
  std::shared_ptr<PinAttempt> Begin(std::string hostname, uint16_t port,
                                  std::string partition);
  bool Forget(std::string hostname, uint16_t port, std::string partition,
              bool trusted_recovery);

 private:
  std::shared_ptr<PinStore> store_;
};

}  // namespace net::httpps

#undef HTTPPS_PIN_EXPORT
#endif  // NET_HTTPPS_PINNING_H_
