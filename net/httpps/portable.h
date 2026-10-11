// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTPPS_PORTABLE_H_
#define NET_HTTPPS_PORTABLE_H_

#include <cstdint>
#include <string_view>

#if defined(PHROMIUM_HTTPPS_STANDALONE)
#include <chrono>
#include <span>
#else
#include "base/containers/span.h"
#include "base/time/time.h"
#endif

namespace net::httpps {

// The isolated conformance harness has no Chromium //base dependency. Browser
// production builds always use the checked Chromium span implementation.
#if defined(PHROMIUM_HTTPPS_STANDALONE)
using ByteSpan = std::span<const uint8_t>;
using MutableByteSpan = std::span<uint8_t>;
#else
using ByteSpan = base::span<const uint8_t>;
using MutableByteSpan = base::span<uint8_t>;
#endif

inline ByteSpan StringBytes(std::string_view value) {
#if defined(PHROMIUM_HTTPPS_STANDALONE)
  return {reinterpret_cast<const uint8_t*>(value.data()), value.size()};
#else
  return base::as_byte_span(value);
#endif
}

inline int64_t MonotonicMilliseconds() {
#if defined(PHROMIUM_HTTPPS_STANDALONE)
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
#else
  // Use Chromium's clock so the handshake deadline also respects mock time.
  return base::TimeTicks::Now().since_origin().InMilliseconds();
#endif
}

}  // namespace net::httpps

#endif  // NET_HTTPPS_PORTABLE_H_
