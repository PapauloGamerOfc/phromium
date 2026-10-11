// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/control_profiles.h"
#include "net/httpps/draft01.h"

#include <cstdlib>
#include <iostream>

namespace {
void Check(bool value, const char* what) {
  if (!value) {
    std::cerr << "Control profile failure: " << what << '\n';
    std::exit(1);
  }
}
}  // namespace

void RunControlProfileTests() {
  using namespace net::httpps;
  TicketRequest request{0, 255};
  Check(request.Encode() == Bytes({0, 255}), "zero and uint8 maximum allowed");
  uint8_t hint = 99;
  Check(TicketRequest::ParseHint(Bytes{0}, &hint) && hint == 0, "zero server hint");
  Check(!TicketRequest::ParseHint({}, &hint) &&
        !TicketRequest::ParseHint(Bytes{1, 2}, &hint), "hint exact format");
  const auto client = StringBytes("client-0123456789012345");
  const auto server = StringBytes("server-0123456789012345");
  SignalingBinding local{Bytes(32, 0x11), Bytes(32, 0x22),
                        Bytes(client.begin(), client.end()),
                        Bytes(server.begin(), server.end()), true};
  auto peer = local;
  std::swap(peer.local_hash, peer.peer_hash);
  std::swap(peer.local_session_id, peer.peer_session_id);
  Check(local.IsValid() && local.Validate(peer.Offers()), "independent signaling matches");
  const Secret expected{0x47,0x58,0xb4,0x77,0x6a,0x7d,0x0a,0x77,
      0x31,0x55,0x45,0x25,0x23,0x45,0xa5,0xf2,0xb5,0xaa,0xa0,0x93,
      0x6b,0xe0,0x07,0x4c,0x8d,0x04,0xda,0x24,0x76,0xa3,0x77,0x2b};
  Check(local.Context() == expected, "independent Python policy context vector");
  Check(peer.Context() != local.Context(), "policy context directional");
  Check(!local.Validate(local.Offers()) && !local.Validate({}), "wrong and absent required binding rejected");
  auto response = peer.Offers();
  response[55][1] ^= 1;
  Check(!local.Validate(response), "identity assertion mismatch rejected");
  response = peer.Offers();
  response[56].pop_back();
  Check(!local.Validate(response), "session framing mismatch rejected");
  local.required = false;
  Check(local.Validate({}) && !local.Validate(response), "optional absent allowed, supplied mismatch rejected");
  Check(local.Context() != expected, "required policy bound to tickets");
  local.local_hash.resize(31);
  Check(!local.IsValid() && local.Offers().empty(), "invalid hash not advertised");
  local.local_hash.clear();
  local.peer_hash.clear();
  peer.local_hash.clear();
  peer.peer_hash.clear();
  Check(local.Validate(peer.Offers()), "empty assertion is syntactically allowed");
  local.local_session_id[0] = ' ';
  Check(!local.IsValid(), "tls-id exact printable token");
  std::cout << "Ticket and external signaling profile tests passed\n";
}
