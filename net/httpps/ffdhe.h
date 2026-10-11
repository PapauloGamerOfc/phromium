// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_HTTPPS_FFDHE_H_
#define NET_HTTPPS_FFDHE_H_
#include "net/httpps/draft01.h"
namespace net::httpps {
Bytes FfdhePrime(uint16_t group);
bool FfdheKeypair(uint16_t group, Bytes* private_key, Bytes* public_key);
bool FfdheAgreement(uint16_t group, ByteSpan private_key, ByteSpan peer, Bytes* shared);
}
#endif
