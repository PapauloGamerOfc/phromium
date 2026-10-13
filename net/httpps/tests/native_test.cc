// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Portable test driver for the exact engine used by HttppsClientSocket. The
// optional network mode connects ONLY to loopback; it is not a browser proxy.
#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <iterator>

#include "net/httpps/draft01.h"
#include "net/httpps/pinning.h"
#include "net/httpps/native_provider.h"
#include "net/httpps/transparency.h"
#include "net/httpps/dnssec.h"
#include "net/httpps/its_credentials.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>

#include <fcntl.h>
#include <io.h>
using SocketHandle = SOCKET;
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
#endif

void RunPinningTests();
void TlsFeaturesTests();
void RunControlProfileTests();
void RunProtocolRegressionTests();
void RunIntegrityOnlyTests();
void RunNativeProviderTests(std::string_view library, std::string_view helper);
void RunGostProviderTests(std::string_view library, std::string_view module);
net::httpps::Bytes HandshakeSendingSecretForTest(const net::httpps::Client& client);

namespace {
using net::httpps::Bytes;

enum class ChainRejection { kNone, kSendAlert, kReset };

void Require(bool condition, const char* description) {
  if (!condition) {
    std::cerr << "FAIL: " << description << '\n';
    std::exit(1);
  }
}

unsigned ParseUnsigned(std::string_view value, int base = 10) {
  unsigned result = 0;
  auto parsed =
      std::from_chars(value.data(), value.data() + value.size(), result, base);
  Require(parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size(),
          "complete unsigned integer");
  return result;
}

Bytes Unhex(std::string_view value) {
  Require(value.size() % 2 == 0, "even hexadecimal length");
  Bytes out;
  for (size_t i = 0; i < value.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(ParseUnsigned(value.substr(i, 2), 16)));
  }
  return out;
}

std::string ReadFile(const char* path) {
  std::ifstream file(path, std::ios::binary);
  Require(file.good(), "open DER fixture");
  return std::string(std::istreambuf_iterator<char>(file), {});
}

void Send(SocketHandle socket, const Bytes& bytes) {
  size_t offset = 0;
  while (offset < bytes.size()) {
    int sent =
        send(socket, reinterpret_cast<const char*>(bytes.data() + offset),
             static_cast<int>(bytes.size() - offset), 0);
    Require(sent > 0, "socket write");
    offset += sent;
  }
}

void Receive(SocketHandle socket, Bytes* bytes, size_t length) {
  size_t offset = bytes->size();
  bytes->resize(offset + length);
  while (length) {
    int count = recv(socket, reinterpret_cast<char*>(bytes->data() + offset),
                     static_cast<int>(length), 0);
    Require(count > 0, "unexpected EOF without close_notify");
    length -= count;
    offset += count;
  }
}

Bytes Record(SocketHandle socket) {
  Bytes bytes;
  Receive(socket, &bytes, 5);
  size_t length = (size_t(bytes[3]) << 8) | bytes[4];
  Require(length <= net::httpps::kMaxRecord - 5 && length > 0,
          "bounded record header");
  Receive(socket, &bytes, length);
  return bytes;
}

void AuthenticatorTest(SocketHandle socket, net::httpps::Client& client,
                       const std::vector<std::string>& anchors,
                       const char* leaf, const char* key, const char* grant = nullptr,
                       const net::httpps::ClientCredential* evidence_credential = nullptr) {
  Bytes buffered;
  auto receive = [&]() {
    while (true) {
      if (buffered.size() >= 4) {
        size_t size = 0;
        for (size_t i = 0; i < 4; ++i)
          size = (size << 8) | buffered[i];
        Require(size <= 1048576, "bounded application authenticator frame");
        if (buffered.size() >= size + 4) {
          Bytes result(buffered.begin() + 4, buffered.begin() + 4 + size);
          buffered.erase(buffered.begin(), buffered.begin() + 4 + size);
          return result;
        }
      }
      Bytes data;
      Require(client.Receive(Record(socket), &data) && !client.closed(), "authenticator application record");
      buffered.insert(buffered.end(), data.begin(), data.end());
      auto controls = client.TakeOutput();
      if (!controls.empty())
        Send(socket, controls);
    }
  };
  auto send_frame = [&](const Bytes& data) {
    Bytes framed;
    for (int shift : {24, 16, 8, 0})
      framed.push_back(static_cast<uint8_t>(data.size() >> shift));
    framed.insert(framed.end(), data.begin(), data.end());
    Bytes records;
    Require(client.Send(framed, &records), "authenticator application encrypt");
    Send(socket, records);
  };
  if (evidence_credential) {
    for (size_t index = 0; index < 2; ++index) {
      const auto request = receive();
      Bytes response;
      Require(client.AuthenticateClient(request, evidence_credential, &response),
              "EA client evidence follows the current request");
      send_frame(response);
    }
    return;
  }
  std::optional<net::httpps::ClientCredential> credential;
  if (leaf && key) {
    credential.emplace();
    credential->certificates = {ReadFile(leaf)};
    auto raw = ReadFile(key);
    Require(raw.size() == 32, "EA selected key size");
    std::copy(raw.begin(), raw.end(), credential->private_key.begin());
    OPENSSL_cleanse(raw.data(), raw.size());
    if (grant) {
      const auto value = ReadFile(grant);
      credential->delegation.assign(value.begin(), value.end());
    }
  }
  Bytes request, response;
  if (grant) {
    for (bool offered : {true, false}) {
      request = receive();
      Require(client.AuthenticateClient(request, &*credential, &response),
              "EA client delegation uses its own request, not server grant offers");
      Require(!response.empty() && response[0] == (offered ? 11 : 20),
              "EA unoffered client grant produces authenticated refusal");
      send_frame(response);
    }
    send_frame(Bytes{'O', 'K'});
    return;
  }
  for (size_t i = 0; i < 4; ++i) {
    if (i == 0) {
      // Kept in sync with selection_request_cases() in the Python peer. All
      // malformed requests reuse the valid request's context, including when
      // no credential is selected and the eventual result is a refusal.
      for (size_t invalid = 0; invalid < 42; ++invalid) {
        request = receive();
        Require(!client.AuthenticateClient(request, credential ? &*credential : nullptr, &response),
                "EA client request rejects malformed selection/OCSP/CT before claiming its context");
        Require(client.established() && !client.closed() && client.TakeFatalAlert().empty() &&
                    client.TakeOutput().empty(),
                "EA request syntax failure leaves the underlying TLS connection usable");
      }
    }
    request = receive();
    Require(client.AuthenticateClient(request, credential ? &*credential : nullptr, &response),
            "EA direct client identity/refusal accepts unsupported delegation offers");
    Require(!response.empty() && response[0] == (credential ? 11 : 20),
            "EA direct identity or authenticated refusal selected");
    send_frame(response);
    Require(!client.AuthenticateClient(request, credential ? &*credential : nullptr, &response),
            "EA client request replay rejected");
  }
  Bytes binding;
  Require(client.ChannelBinding(&binding) && binding.size() == 32, "named channel binding");
  send_frame(binding);
  Bytes expected_ocsp_request;
  auto validate = [&](const net::httpps::AuthenticatorIdentity& identity,
                      const std::map<uint16_t, Bytes>& offers, net::httpps::Secret* public_key) {
    // This loopback fixture explicitly authorizes localhost under its lab CA;
    // production callers must additionally check their application policy.
    return offers.count(50) && offers.count(5) && offers.at(5) == expected_ocsp_request &&
        identity.extensions.size() == identity.certificates.size() &&
        net::httpps::VerifyLabChain(identity.certificates, anchors, "localhost", public_key);
  };
  bool authenticated = false;
  const std::map<uint16_t, Bytes> unknown_delegation{
      {34, Bytes{0, 2, 0x0a, 0x0a}}, {0xff04, Bytes{0, 2, 8, 7}}};
  for (const Bytes& invalid : {Bytes{0, 0}, Bytes{0, 1, 0x0a}, Bytes{0, 2, 0x0a}}) {
    auto malformed = unknown_delegation;
    malformed[34] = invalid;
    Require(!client.RequestServerAuthenticator(Bytes{6}, malformed, &request),
            "EA malformed delegation vector still rejected");
  }
  for (const Bytes& invalid : {Bytes{1, 0, 0, 0, 0}, Bytes{1}, Bytes{0xff}}) {
    Require(!client.RequestServerAuthenticator(Bytes{10}, {{5, invalid}}, &request),
            "EA server request rejects nonempty OCSP before claiming its context");
  }
  for (uint16_t type : {18, 52}) {
    for (const Bytes& invalid : {Bytes{1}, Bytes{0, 0}, Bytes{0, 3, 0, 1, 0xff}}) {
      Require(!client.RequestServerAuthenticator(Bytes{10}, {{type, invalid}}, &request),
              "EA server request rejects nonempty CT before claiming its context");
      Require(client.established() && client.TakeFatalAlert().empty() && client.TakeOutput().empty(),
              "EA CT syntax rejection leaves the channel usable");
    }
  }
  for (const Bytes& invalid : {Bytes{}, Bytes{0}, Bytes{0, 3, 2, 6},
                              Bytes{0, 3, 0, 0, 0},
                              Bytes{0, 8, 5, 6, 3, 0x55, 0x1d, 0x25, 0, 0, 0}}) {
    Require(!client.RequestServerAuthenticator(Bytes{10}, {{48, invalid}}, &request),
            "EA server request rejects malformed OID filters before claiming its context");
  }
  for (const Bytes& invalid : {Bytes{}, Bytes{0}, Bytes{0, 0}, Bytes{0, 3, 0, 1, 0}}) {
    Require(!client.RequestServerAuthenticator(Bytes{10}, {{47, invalid}}, &request),
            "EA server request rejects malformed authority names before claiming its context");
  }
  for (const Bytes& invalid : {Bytes{}, Bytes{0, 0}, Bytes{0, 1, 0},
                              Bytes{0, 5, 0, 0, 1, 'a', 'X'},
                              Bytes{0, 8, 0, 0, 1, 'a', 0, 0, 1, 'b'},
                              Bytes{0, 4, 1, 0, 1, 'a'}}) {
    Require(!client.RequestServerAuthenticator(Bytes{10}, {{0, invalid}}, &request),
            "EA server request rejects malformed SNI before claiming its context");
    Require(client.established() && client.TakeFatalAlert().empty() && client.TakeOutput().empty(),
            "EA SNI syntax rejection does not close or write to the TLS connection");
  }
  const std::vector<std::string_view> requested_names{
      "localhost", "LoCaLhOsT", "xn--bcher-kva.example", "another.example"};
  uint8_t context = 10;
  for (const Bytes& schemes : {Bytes{0, 2, 0x0a, 0x0a}, Bytes{0, 2, 0xaa, 0xaa},
                              Bytes{0, 2, 0xfe, 1}, Bytes{0, 4, 0x0a, 0x0a, 0xfe, 0}}) {
    auto offers = unknown_delegation;
    offers[34] = schemes;
    offers[5] = {};
    offers[18] = {};
    offers[52] = {};
    // Well-formed unknown OIDs and their opaque values are still ignorable.
    offers[48] = Bytes{0, 9, 5, 6, 3, 0x2a, 3, 4, 0, 1, 0xff};
    const auto name = requested_names[context - 10];
    offers[0] = Bytes{0, static_cast<uint8_t>(name.size() + 3), 0, 0,
                      static_cast<uint8_t>(name.size())};
    offers[0].insert(offers[0].end(), name.begin(), name.end());
    Require(client.RequestServerAuthenticator(Bytes{context++}, offers, &request),
            "EA server request accepts SNI preferences, empty OCSP and unsupported delegation offers");
    send_frame(request);
    response = receive();
    Require(client.ValidateServerAuthenticator(response, validate, &authenticated, request) && authenticated,
            "EA direct server MAC and Finished with unsupported delegation offers");
    Require(!client.ValidateServerAuthenticator(response, validate, &authenticated, request),
            "EA server replay rejected");
  }
  Require(client.RequestServerAuthenticator(Bytes{2}, unknown_delegation, &request), "EA refusal request");
  send_frame(request);
  response = receive();
  Require(client.ValidateServerAuthenticator(response, validate, &authenticated, request) && !authenticated, "EA authenticated refusal is not identity");
  Require(client.RequestServerAuthenticator(Bytes{3}, {}, &request) && client.CancelAuthenticator(request), "EA cancellation consumes secret");
  Require(!client.RequestServerAuthenticator(Bytes{3}, {}, &request), "EA cancellation does not reopen context");
  response = receive();
  expected_ocsp_request = Bytes{1, 0, 0, 0, 0};
  Require(client.ValidateServerAuthenticator(response, validate, &authenticated) && authenticated,
          "spontaneous server EA retains scalar and full ClientHello OCSP request");
  Require(!client.ValidateServerAuthenticator(response, validate, &authenticated), "spontaneous EA replay rejected");
  expected_ocsp_request.clear();
  Require(client.RequestServerAuthenticator(Bytes{4}, {{5, {}}}, &request), "EA invalid response request");
  send_frame(request);
  response = receive();
  Require(!client.ValidateServerAuthenticator(response, validate, &authenticated, request) && !authenticated, "EA tampered proof rejected");
  Require(!client.RequestServerAuthenticator(Bytes{4}, {}, &request), "EA failed proof consumes context");
  // Proofs are genuine in every case. Optional evidence policy may ignore an
  // unknown SCT, but must never receive a malformed TLS evidence envelope.
  for (bool spontaneous : {false, true}) {
    for (size_t index = 0; index < (spontaneous ? 19u : 27u); ++index) {
      const bool valid = index < 4 || index == 19 || index == 20;
      const uint16_t kind = index >= 19 ? 52 : index == 3 || index >= 12 ? 5 : 18;
      const Bytes context_bytes{0x40, static_cast<uint8_t>(spontaneous), static_cast<uint8_t>(index)};
      request.clear();
      if (!spontaneous) {
        Require(client.RequestServerAuthenticator(context_bytes, {{kind, {}}}, &request),
                "EA evidence request has an actual offer and independent context");
        send_frame(request);
      }
      response = receive();
      size_t policy_calls = 0;
      auto optional_evidence = [&](const net::httpps::AuthenticatorIdentity& identity,
                                  const std::map<uint16_t, Bytes>& offers, net::httpps::Secret* public_key) {
        ++policy_calls;
        return offers.count(kind) && identity.extensions.front().count(kind) &&
            net::httpps::VerifyLabChain(identity.certificates, anchors, "localhost", public_key);
      };
      const bool accepted = client.ValidateServerAuthenticator(response, optional_evidence, &authenticated, request);
      if (accepted != valid || authenticated != valid || policy_calls != (valid ? 1u : 0u))
        std::cerr << "EA evidence case " << index << " spontaneous=" << spontaneous
                  << " accepted=" << accepted << " authenticated=" << authenticated
                  << " policy_calls=" << policy_calls << '\n';
      Require(accepted == valid &&
                  authenticated == valid && policy_calls == (valid ? 1u : 0u),
              "EA nested evidence framing is validated before optional PKIX/evidence policy");
      Require(!client.ValidateServerAuthenticator(response, optional_evidence, &authenticated, request) &&
                  !authenticated && policy_calls == (valid ? 1u : 0u),
              "EA evidence failure and success both consume the response context");
      Require(!client.CancelAuthenticator(request) && client.established() && !client.closed() &&
                  client.TakeFatalAlert().empty() && client.TakeOutput().empty(),
              "EA syntax rejection emits no TLS alert and leaves the connection usable");
      Bytes current_binding;
      Require(client.ChannelBinding(&current_binding) && current_binding == binding,
              "EA syntax rejection preserves the original channel binding");
      send_frame(Bytes{'N', 'E', 'X', 'T'});
    }
  }
  Require(client.RequestKeyUpdate(true, &response), "EA key update");
  Send(socket, response);
  Bytes after;
  Require(client.ChannelBinding(&after) && after == binding, "channel binding stable across KeyUpdate");
  send_frame(Bytes{'O', 'K'});
  client.DisableAuthenticators();
  Require(!client.RequestServerAuthenticator(Bytes{5}, {}, &request), "EA disabled erases capability");
}

int Get(const char* host,
        const char* port,
        const char* root,
        bool external_verification,
        bool resume_test = false,
        bool expect_early_acceptance = true,
        const char* client_leaf = nullptr,
        const char* client_key = nullptr,
        net::httpps::ClientOptions options = {},
        const char* client_grant = nullptr,
        bool cache_test = false,
        bool authenticator_test = false,
        bool pinning_test = false,
        const net::httpps::ClientCredential* selected_credential = nullptr,
        bool bootstrap_inventory_test = false,
        bool ocsp_request_recheck_test = false,
        ChainRejection reject_long_chain = ChainRejection::kNone,
        uint8_t expected_handshake_alert = 0,
        bool client_ocsp_authenticator_test = false,
        bool plaintext_handshake_alert = false,
        uint8_t expected_post_handshake_alert = 0) {
#if defined(_WIN32)
  WSADATA data;
  Require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "winsock init");
#endif
  std::optional<net::httpps::SessionTicket> session;
  const Bytes expected_bootstrap = bootstrap_inventory_test
      ? options.bootstraps.back().spki : Bytes{};
  net::httpps::PinningCache pins;
  for (int round = 0; round < (resume_test || cache_test || pinning_test ? 3 : 1); ++round) {
  if (bootstrap_inventory_test && round)
    std::reverse(options.bootstraps.begin(), options.bootstraps.end());
  if (pinning_test) {
    options.pinning = pins.Begin(host, static_cast<uint16_t>(ParseUnsigned(port)), "loopback-fixture");
    Require(options.pinning != nullptr, "pinning scope accepted");
    options.cipher_suites = {static_cast<uint16_t>(round == 1 ? 0x1302 : 0x1301)};
  }
  SocketHandle stream = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  unsigned port_number = ParseUnsigned(port);
  Require(port_number > 0 && port_number <= 65535, "valid TCP port");
  address.sin_port = htons(static_cast<uint16_t>(port_number));
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  Require(connect(stream, reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) == 0,
          "connect loopback");
  const std::vector<std::string> anchors{ReadFile(root)};
  net::httpps::Client client(
      host, external_verification || options.allow_unauthenticated
                ? std::vector<std::string>{} : anchors,
      external_verification, options);
  if (selected_credential)
    Require(client.SetClientCredential(*selected_credential), "explicit prepared credential");
  if (client_leaf && client_key) {
    net::httpps::ClientCredential credential;
    credential.certificates.push_back(ReadFile(client_leaf));
    if (client_grant) {
      auto grant = ReadFile(client_grant);
      credential.delegation.assign(grant.begin(), grant.end());
    }
    net::httpps::Secret raw_public;
    if (net::httpps::ExtractRawPublicKey(net::httpps::StringBytes(credential.certificates.front()),
                                       &raw_public))
      credential.certificate_type = 2;
    auto key = ReadFile(client_key);
    Require(key.size() == credential.private_key.size(), "raw client X25519 key length");
    std::copy(key.begin(), key.end(), credential.private_key.begin());
    Require(client.SetClientCredential(credential), "explicit client credential selection");
    OPENSSL_cleanse(key.data(), key.size());
  }
  const bool early = (resume_test && round == 2) || (!resume_test && !options.external_psks.empty() &&
                                    options.external_psks.front().max_early_data != 0);
  std::string request = "GET / HTTP/1.1\r\nHost: " + std::string(host) +
                        "\r\nConnection: close\r\n\r\n";
  Require(client.Start(session ? &*session : nullptr, {}, early), "start handshake");
  Send(stream, client.TakeOutput());
  Require(client.OutputFlushed(), "CH flush");
  if (early) {
    Bytes encrypted;
    Require(client.SendEarlyData(Bytes(request.begin(), request.end()), &encrypted),
            "send early request before reading ServerHello");
    Send(stream, encrypted);
  }
  while (!client.established()) {
    Bytes unused;
    auto alert_secret = reject_long_chain != ChainRejection::kNone || expected_handshake_alert
        ? HandshakeSendingSecretForTest(client) : Bytes{};
    const bool accepted = client.Receive(Record(stream), &unused);
    if (!accepted) {
      auto alert = client.TakeFatalAlert();
      if (reject_long_chain != ChainRejection::kNone || expected_handshake_alert) {
        const auto expected_error = options.delegated_credentials
            ? net::httpps::Client::Error::kCertificate : net::httpps::Client::Error::kProtocol;
        Require(!client.established() && client.error() == expected_error &&
                    unused.empty() && client.TakeOutput().empty(),
                "expected rejection does not establish a channel or expose data");
        const uint8_t expected = expected_handshake_alert ? expected_handshake_alert : 50;
        if (plaintext_handshake_alert) {
          Require(alert_secret.empty() && alert == Bytes({21, 3, 3, 0, 2, 2, expected}),
                  "Hello parser generates the exact plaintext fatal alert");
        } else {
          Require(alert_secret.size() == 32, "authenticated alert has handshake keys");
          net::httpps::RecordCipher alert_reader(alert_secret);
          OPENSSL_cleanse(alert_secret.data(), alert_secret.size());
          uint8_t type = 0;
          Bytes content;
          Require(alert_reader.Open(alert, &type, &content) && type == 21 && content == Bytes({2, expected}),
                  "certificate parser generates the exact authenticated fatal alert");
        }
        if (reject_long_chain == ChainRejection::kReset) {
          // This fixed peer sends one CV and one Finished record after the
          // Certificate. Drain both before an abortive close so the server is
          // reading, not racing another write. No timing sleeps are involved.
          Record(stream);
          Record(stream);
          linger reset{1, 0};
          Require(setsockopt(stream, SOL_SOCKET, SO_LINGER,
                             reinterpret_cast<const char*>(&reset), sizeof(reset)) == 0,
                  "force a reset without delivering the locally checked alert");
        } else {
          Send(stream, alert);
          if (expected_handshake_alert) {
            // Preserve peer receipt independently of unread CV/Finished bytes:
            // send FIN, then discard its remaining flight until it closes.
#if defined(_WIN32)
            Require(shutdown(stream, SD_SEND) == 0, "finish expected alert write");
#else
            Require(shutdown(stream, SHUT_WR) == 0, "finish expected alert write");
#endif
            char discarded[4096];
            while (recv(stream, discarded, sizeof(discarded), 0) > 0) {}
          }
        }
#if defined(_WIN32)
        closesocket(stream);
        WSACleanup();
#else
        close(stream);
#endif
        if (expected_handshake_alert)
          std::cout << (plaintext_handshake_alert ? "Hello parser: plaintext fatal alert " :
                        "certificate parser: authenticated fatal alert ") << unsigned{expected} << " generated\n";
        else
          std::cout << "oversized chain: authenticated fatal decode_error generated\n";
        return 0;
      }
      if (!alert.empty())
        Send(stream, alert);
    }
    OPENSSL_cleanse(alert_secret.data(), alert_secret.size());
    Require(accepted, "authenticated server flight");
    if (client.certificate_verification_pending()) {
      Require(external_verification && !client.established() &&
                  client.TakeOutput().empty(),
              "no Finished or application data before trust decision");
      // Exercise the engine's deferred decision boundary independently of
      // Chromium. This fixture validator is NOT the browser CertVerifier.
      net::httpps::Secret key;
      bool trusted = net::httpps::VerifyLabChain(client.certificates(), anchors,
                                                 host, &key);
      Require(client.CompleteCertificateVerification(trusted,
                  net::httpps::ValidatedPrivateIssuer(client.certificates(), anchors, host, client.delegated()),
                  net::httpps::ValidatedPrivatePath(client.certificates(), anchors, host, client.delegated())),
              "external certificate decision and buffered proof");
    }
    auto output = client.TakeOutput();
    if (!output.empty()) {
      Send(stream, output);
      Require(client.OutputFlushed(), "CF flush");
    }
  }
  Require(reject_long_chain == ChainRejection::kNone && !expected_handshake_alert,
          "oversized chain must never establish a connection");
  Bytes output;
  if (bootstrap_inventory_test) {
    const auto group = std::find(options.groups.begin(), options.groups.end(), client.traffic_group());
    Require(group != options.groups.end(), "bootstrap negotiated an offered traffic group");
    std::rotate(options.groups.begin(), group, options.groups.end());
  }
  if (options.allow_unauthenticated)
    Require(client.authentication() == net::httpps::Authentication::kUnauthenticated,
            "unauthenticated lineage is preserved, including resumption");
  if (authenticator_test)
    AuthenticatorTest(stream, client, anchors, client_leaf, client_key, client_grant);
  if (client_ocsp_authenticator_test)
    AuthenticatorTest(stream, client, anchors, nullptr, nullptr, nullptr, selected_credential);
  if (resume_test) {
    Require(client.resumed() == (round != 0), "expected session resumption");
    Require(client.early_data_accepted() == (early && expect_early_acceptance),
            "expected early acceptance or rejection");
    Require(client.Export("test exporter", Bytes{1, 2, 3}, 64, &output) &&
                output.size() == 64,
            "normal exporter available after Finished");
    if (!early || !client.early_data_accepted()) {
      constexpr char digits[] = "0123456789abcdef";
      std::string value;
      for (uint8_t byte : output) {
        value += digits[byte >> 4];
        value += digits[byte & 15];
      }
      request.insert(request.size() - 2, "X-Test-Exporter: " + value + "\r\n");
    }
  }
  if (!authenticator_test && (!early || !client.early_data_accepted())) {
    if (resume_test) {
      Require(client.RequestKeyUpdate(true, &output), "request key update");
      Send(stream, output);
    }
    Require(client.Send(Bytes(request.begin(), request.end()), &output),
            "application encrypt");
    Send(stream, output);
  }
  while (!client.closed()) {
    const bool accepted = client.Receive(Record(stream), &output);
    if (!accepted && expected_post_handshake_alert) {
      auto alert = client.TakeFatalAlert();
      Require(client.error() == net::httpps::Client::Error::kProtocol &&
                  !client.established() && output.empty() && client.TakeOutput().empty() && !alert.empty(),
              "invalid PHA reference closes without a client proof or application response");
      // The independent server verifies the exact authenticated alert using
      // the active application epoch; do not substitute a local error code.
      Send(stream, alert);
#if defined(_WIN32)
      Require(shutdown(stream, SD_SEND) == 0, "finish expected PHA alert write");
#else
      Require(shutdown(stream, SHUT_WR) == 0, "finish expected PHA alert write");
#endif
      char discarded[4096];
      while (recv(stream, discarded, sizeof(discarded), 0) > 0) {}
#if defined(_WIN32)
      closesocket(stream);
      WSACleanup();
#else
      close(stream);
#endif
      std::cout << "PHA reference: authenticated fatal alert "
                << unsigned{expected_post_handshake_alert} << " sent for peer verification\n";
      return 0;
    }
    Require(accepted, "application decrypt");
    auto controls = client.TakeOutput();
    if (!controls.empty()) {
      Send(stream, controls);
      Require(client.OutputFlushed(), "post-handshake response flush");
    }
    auto tickets = client.TakeTickets();
    if (!tickets.empty() && !cache_test && !pinning_test) {
      session = std::move(tickets.back());
      if (ocsp_request_recheck_test) {
        Require(!session->certificate_extensions.empty() &&
                    session->certificate_extensions.front().count(5),
                "OCSP ticket contains the actual received staple");
        for (bool offer_early : {false, true}) {
          auto changed = options;
          // DER Extensions containing unknown OID1.2.3.4, critical TRUE.
          changed.ocsp_request_extensions = {0x30, 0x0e, 0x30, 0x0c, 6, 3,
              0x2a, 3, 4, 1, 1, 0xff, 4, 2, 5, 0};
          Require(net::httpps::CredentialRequestOptionsValid(changed),
                  "unsupported critical OCSP request is well-framed, not malformed");
          net::httpps::Client rejected(host, anchors, false, changed);
          Require(!rejected.Start(&*session, {}, offer_early) &&
                      rejected.TakeOutput().empty() && !rejected.early_data_available(),
                  "cached generic OCSP cannot fulfill new critical requirements or emit CH/early data");
          // The same extension without criticality is ignorable, not a policy
          // mismatch that should suppress an otherwise usable saved ticket.
          changed.ocsp_request_extensions = {0x30, 0x0b, 0x30, 9, 6, 3,
              0x2a, 3, 4, 4, 2, 5, 0};
          net::httpps::Client allowed(host, anchors, false, changed);
          Require(allowed.Start(&*session, {}, offer_early) && !allowed.TakeOutput().empty() &&
                      allowed.early_data_available() == offer_early,
                  "cached OCSP tolerates unknown noncritical request extensions");
        }
      }
      if (bootstrap_inventory_test) {
        Require(client.bootstrap_authenticated() && client.client_identity_authenticated(),
                "selected bootstrap possession retained by tickets");
        const auto selected = std::find_if(options.bootstraps.begin(), options.bootstraps.end(),
            [&](const auto& binding) { return binding.spki == expected_bootstrap; });
        Require(selected != options.bootstraps.end(), "selected binding remains locally authorized");
        const size_t index = selected - options.bootstraps.begin();
        for (int fault = 0; fault < 5; ++fault) {
          auto changed = options;
          if (fault == 0) changed.bootstraps.erase(changed.bootstraps.begin() + index);
          if (fault == 1) changed.bootstraps[index].scope += "-revoked";
          if (fault == 2) changed.bootstraps[index].expires_unix_seconds = 1;
          if (fault == 3) changed.bootstraps[index].provisioning_trust =
              !changed.bootstraps[index].provisioning_trust;
          if (fault == 4) changed.bootstraps[index].credential =
              changed.bootstraps[1 - index].credential;
          net::httpps::Client rejected(host, anchors, false, changed);
          Require(!rejected.Start(&*session, {}, true) && rejected.TakeOutput().empty(),
                  "bootstrap ticket cannot survive selected authority retirement or substitution");
        }
        for (auto& binding : options.bootstraps) {
          if (binding.spki != expected_bootstrap) {
            binding.scope += "-unrelated-policy-change";
            if (round == 1) binding.expires_unix_seconds = 1;
          }
        }
      }
      if (options.its_policy) {
        auto reject_cached = [&](net::httpps::SessionTicket changed) {
          net::httpps::Client rejected(host, anchors, false, options);
          if (selected_credential)
            Require(rejected.SetClientCredential(*selected_credential), "ITS cached test selected identity");
          Require(!rejected.Start(&changed, {}, true) && rejected.TakeOutput().empty(),
                  "invalid ITS cached policy/evidence/deadline cannot emit CH or early data");
        };
        auto changed = *session;
        changed.its_policy_context.front() ^= 1;
        reject_cached(changed);
        changed = *session;
        changed.its_expires_unix_milliseconds = 0;
        reject_cached(changed);
        changed = *session;
        changed.certificates.front().back() ^= 1;
        reject_cached(changed);
      }
      if (options.password) {
        if (session->authentication == net::httpps::Authentication::kPassword)
          Require(session->certificates.empty(), "password ticket has no invented CA identity");
        auto tampered = *session;
        tampered.password_context[0] ^= 1;
        net::httpps::Client foreign(host, anchors, false, options);
        Require(!foreign.Start(&tampered, {}, true) && foreign.TakeOutput().empty(), "password ticket context before CH/early");
        auto changed = options;
        auto credential = std::make_shared<net::httpps::PasswordCredential>(*options.password);
        credential->password.push_back('x');
        changed.password = credential;
        net::httpps::Client wrong_password(host, anchors, false, changed);
        Require(!wrong_password.Start(&*session, {}, true) && wrong_password.TakeOutput().empty(),
                "changed password cannot reuse cached authorization");
        auto narrowed = options;
        narrowed.cipher_suites = {static_cast<uint16_t>(
            net::httpps::SuiteHashLength(session->cipher_suite) == 48 ? 0xc0b0 : 0xc0b1)};
        net::httpps::Client incompatible(host, anchors, false, narrowed);
        Require(!incompatible.Start(&*session, {}, true) && incompatible.TakeOutput().empty(),
                "cached password ticket cannot override newly restricted suite hash");
        if (session->cipher_suite == 0x1304) {
          narrowed.cipher_suites = {0xc0b0};
          net::httpps::Client no_old_early_cipher(host, anchors, false, narrowed);
          Require(no_old_early_cipher.Start(&*session, {}, true) && !no_old_early_cipher.early_data_available(),
                  "same-hash resumption never emits early data under a removed AEAD");
        }
      }
      if (options.ct_v2_policy) {
        auto tampered = *session;
        Require(!tampered.certificate_extensions.empty() &&
                    !tampered.certificate_extensions.front()[52].empty(), "CT ticket evidence saved");
        tampered.certificate_extensions.front()[52].back() ^= 1;
        net::httpps::Client changed_evidence(host, anchors, false, options);
        Require(!changed_evidence.Start(&tampered, {}, true) && changed_evidence.TakeOutput().empty(),
                "tampered cached CT cannot authorize CH or early data");
        tampered = *session;
        tampered.ct_policy_context.front() ^= 1;
        net::httpps::Client changed_policy(host, anchors, false, options);
        Require(!changed_policy.Start(&tampered, {}, true), "cached CT policy scope enforced");
      }
      if (options.dane_policy) {
        auto tampered = *session;
        Require(!tampered.dane_policy_context.empty(), "DANE policy context saved");
        tampered.dane_policy_context.front() ^= 1;
        net::httpps::Client changed_policy(host, anchors, false, options);
        Require(!changed_policy.Start(&tampered, {}, true), "cached DANE policy scope enforced");
        tampered = *session;
        tampered.dane_expires_unix_seconds = 0;
        net::httpps::Client expired_dns(host, anchors, false, options);
        Require(!expired_dns.Start(&tampered, {}, true), "cached DNS TTL cannot restart on resumption");
        tampered = *session;
        tampered.certificate_extensions.front().erase(59);
        net::httpps::Client missing_evidence(host, anchors, false, options);
        Require(!missing_evidence.Start(&tampered, {}, true) && missing_evidence.TakeOutput().empty(),
                "cached DANE must be revalidated before CH or early data");
      }
      if (client_leaf) {
        net::httpps::Client removed_identity(host, anchors);
        Require(!removed_identity.Start(&*session),
                "a client-authenticated ticket cannot outlive identity selection");
      }
    }
    std::cout.write(reinterpret_cast<const char*>(output.data()),
                    output.size());
  }
  Require(!expected_post_handshake_alert, "invalid cached PHA reference must be rejected");
  if (client.Close(&output)) {
    Send(stream, output);
  }
  if (cache_test) {
    options.cached_certificates = {{client.server_certificate_type(), client.certificates()}};
    options.cached_request_templates = client.authenticated_request_templates();
  }
#if defined(_WIN32)
  closesocket(stream);
#else
  close(stream);
#endif
  if (resume_test)
    Require(session.has_value(), "fresh resumption ticket received");
  }
#if defined(_WIN32)
  WSACleanup();
#endif
  return 0;
}

void PskLifecycleTests() {
  using namespace net::httpps;
  ClientOptions options;
  ExternalPSK psk;
  psk.identity = {1};
  psk.secret = Bytes(32, 7);
  psk.hostname = "localhost";
  options.external_psks = {psk};
  options.external_psks.push_back(psk);
  options.external_psks.back().identity = {2};
  auto server_hello = [](int selected, bool retry) {
    Bytes body(38);
    body[0] = body[1] = 3;
    body[35] = 0x13;
    body[36] = 1;
    Bytes extensions{0, 43, 0, 2, 4, 0};
    if (retry) {
      const auto random = Unhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c");
      std::copy(random.begin(), random.end(), body.begin() + 2);
      extensions.insert(extensions.end(), {0, 44, 0, 3, 0, 1, 7});
    } else {
      Secret public_key{}, private_key{};
      X25519_keypair(public_key.data(), private_key.data());
      extensions.insert(extensions.end(), {0, 51, 0, 36, 0, 29, 0, 32});
      extensions.insert(extensions.end(), public_key.begin(), public_key.end());
      if (selected >= 0)
        extensions.insert(extensions.end(), {0, 41, 0, 2, 0, static_cast<uint8_t>(selected)});
    }
    body.push_back(static_cast<uint8_t>(extensions.size() >> 8));
    body.push_back(static_cast<uint8_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());
    Bytes record{22, 3, 3, 0, static_cast<uint8_t>(body.size() + 4),
                 2, 0, 0, static_cast<uint8_t>(body.size())};
    record.insert(record.end(), body.begin(), body.end());
    return record;
  };
  for (int selection : {0, 1, -1, -2}) {
    Client client("localhost", {}, true, options);
    Bytes exported, application;
    Require(client.Start() && !client.early_data_available(), "PSK without 0-RTT permission starts");
    Require(client.ExportEarly("lifecycle", {}, 32, &exported) && exported.size() == 32,
            "early exporter independent of early_data permission");
    const auto original = exported;
    client.TakeOutput();
    Require(client.OutputFlushed(), "PSK CH flushed");
    const bool accepted = client.Receive(server_hello(selection, selection == -2), &application);
    Require(accepted == (selection != -1), "provisioned PSK cannot silently fall back to certificate");
    Require(client.ExportEarly("lifecycle", {}, 32, &exported) == (selection == 0),
            "early exporter invalidated by retry, rejected or secondary PSK");
    if (selection == 0)
      Require(exported == original, "first selected PSK retains early exporter");
  }
  std::cout << "PSK exporter lifecycle and downgrade tests passed\n";
}

void SelfTest() {
  PskLifecycleTests();
  TlsFeaturesTests();
  RunPinningTests();
  RunControlProfileTests();
  RunProtocolRegressionTests();
  RunIntegrityOnlyTests();
  using RequestContext = net::httpps::RequestExtensionContext;
  for (uint16_t code : {0, 1, 10, 13, 15, 16, 17, 19, 20, 21, 25, 28,
                        29, 30, 31, 32, 33, 41, 42, 43, 44, 45, 49, 51,
                        55, 56, 58, 59, 0xff02})
    Require(!net::httpps::RequestExtensionAllowed(code, RequestContext::kCertificateRequest),
            "known misplaced CertificateRequest extension rejected");
  for (auto context : {RequestContext::kCertificateRequest, RequestContext::kServerAuthenticator,
                       RequestContext::kClientAuthenticator, RequestContext::kNewSessionTicket})
    Require(net::httpps::RequestExtensionAllowed(0xaaa0, context), "unknown offers stay extensible");
  Require(net::httpps::RequestExtensionAllowed(42, RequestContext::kNewSessionTicket) &&
          !net::httpps::RequestExtensionAllowed(43, RequestContext::kNewSessionTicket),
          "NST extension placements");
  {
    net::httpps::ClientOptions options;
    options.allow_unauthenticated = true;
    net::httpps::Client browser("localhost", {}, true, options);
    Require(!browser.Start(), "no unauthenticated browser profile");
    options.ordinary_httpps = false;
    net::httpps::Client explicit_library("localhost", {}, false, options);
    Require(explicit_library.Start(), "explicit generic unauthenticated start");
    options.bootstrap.emplace();
    net::httpps::Client mixed("localhost", {}, false, options);
    Require(!mixed.Start(), "unauthenticated exception never bypasses bootstrap binding");
  }
  for (uint16_t suite : {0xc0b4, 0xc0b5}) {
    net::httpps::ClientOptions options;
    options.cipher_suites = {suite};
    net::httpps::Client denied("localhost", {}, true, options);
    Require(!denied.Start(), "integrity-only is never an implicit fallback");
    options.allow_integrity_only = true;
    net::httpps::Client still_denied("localhost", {}, true, options);
    Require(!still_denied.Start(), "ordinary HTTPPS cannot enable integrity-only");
    options.ordinary_httpps = false;
    net::httpps::Client allowed("localhost", {}, true, options);
    Require(allowed.Start() && !allowed.confidential(), "explicit generic non-confidential application");
    const Bytes secret(net::httpps::SuiteHashLength(suite), 7), data{1, 2, 3};
    net::httpps::RecordCipher sender(secret, suite), receiver(secret, suite);
    Bytes record, recovered;
    uint8_t type = 0;
    Require(sender.Seal(data, 23, &record, 3) &&
        std::equal(data.begin(), data.end(), record.begin() + 5) &&
        receiver.Open(record, &type, &recovered) && type == 23 && recovered == data,
        "integrity-only record retains plaintext and authenticates it");
  }
  using net::httpps::Client;
  using net::httpps::Hash;
  using net::httpps::Label;
  using net::httpps::Mac;
  using net::httpps::RecordCipher;
  using net::httpps::Secret;
  using net::httpps::ValidServerName;
  Require(ValidServerName("localhost"), "localhost");
  Require(ValidServerName("xn--bcher-kva.example"), "A-label");
  for (std::string_view name :
       {"127.0.0.1", "::1", "EXAMPLE.com", "a..b", "a.", "-a.b"}) {
    Require(!ValidServerName(name), "invalid name");
  }
  auto expected_hash =
      Unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  auto hash = Hash(Bytes{'a', 'b', 'c'});
  Require(std::equal(hash.begin(), hash.end(), expected_hash.begin()),
          "SHA256");
  Secret secret{};
  for (size_t i = 0; i < secret.size(); ++i) {
    secret[i] = static_cast<uint8_t>(i);
  }
  RecordCipher sender(secret), receiver(secret);
  Bytes data = {'h', 'e', 'l', 'l', 'o'}, record, plaintext;
  uint8_t type = 0;
  Require(sender.Seal(data, 23, &record), "seal");
  Require(receiver.Open(record, &type, &plaintext) && plaintext == data &&
              type == 23,
          "AEAD roundtrip");
  Require(!receiver.Open(record, &type, &plaintext), "replay fails");
  Require(!receiver.Open(record, &type, &plaintext), "failure is permanent");
  for (size_t i = 0; i < record.size(); ++i) {
    RecordCipher altered_receiver(secret);
    auto altered = record;
    altered[i] ^= 1;
    Require(!altered_receiver.Open(altered, &type, &plaintext),
            "every record byte authenticated");
  }
  RecordCipher over_limit(secret);
  Require(!over_limit.Seal(Bytes(16385), 23, &record), "record size limit");
  Client no_trust("localhost", {});
  Require(!no_trust.Start(), "no implicit trust");
  Client deferred("localhost", {}, true);
  Require(deferred.Start() && !deferred.established() &&
              !deferred.certificate_verification_pending(),
          "external verifier may start without private roots");
  Require(!deferred.CompleteCertificateVerification(true),
          "premature trust decisions fail closed");

  // Public fixture secrets. Current labels/record answers were independently
  // calculated with Python cryptography HKDFExpand and AESGCM, not this engine.
  auto expected_root =
      Unhex("19977420610cd4b20d66b8ebc8cbdf07e8306a6fc82f7c54aeb0c86b4b7b14e3");
  auto peer =
      Unhex("675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f");
  auto private_key =
      Unhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
  Secret shared{};
  Require(X25519(shared.data(), private_key.data(), peer.data()),
          "vector X25519");
  auto expected_shared =
      Unhex("7c79d7b5f31b9aac367477f5f7c7a68b5c44cac28ed5c902a59ec48c02956a6a");
  Require(std::equal(shared.begin(), shared.end(), expected_shared.begin()),
          "vector agreement result");
  auto root = Mac(Secret{}, shared);
  Require(std::equal(root.begin(), root.end(), expected_root.begin()),
          "vector HKDF extract");
  auto t0 =
      Unhex("a6f1690c7cbbd82941e40253ad7c10068db74ddb8d8480ffd9066b9715b0c91d");
  auto c_hs = Label(root, "c hs traffic", t0, 32);
  Require(c_hs == Unhex("b73062cf8cca686c2004aa4269fbc75abac401b9520dccc4b4"
                        "d9d49e24362df1"),
          "vector handshake label");
  auto finished_key = Label(c_hs, "finished", {}, 32);
  Require(finished_key == Unhex("b01f661a66f36f6b5a0cef233bf7a5fa72ec6f1705b2438"
                                "dcd0c218b0b9fe0f8"),
          "vector finished label");
  auto c_app =
      Unhex("5ec0d822843e57a11364ce06df8fb9ad5a6892f274bd41b87708322816f6eff2");
  Require(
      Label(c_app, "key", {}, 16) == Unhex("f71cdb392a15e80951a54a3a22ec4ecd"),
      "vector record key");
  Require(Label(c_app, "iv", {}, 12) == Unhex("c14edf7a9131e25f5aa09f19"),
          "vector record IV");
  RecordCipher vector_sender(c_app);
  auto payload = Unhex("636c69656e7420636f6d706f6e656e74207061796c6f61640a");
  Require(vector_sender.Seal(payload, 23, &record), "vector seal");
  Require(record == Unhex("170303002a6fc24d098249f953c3cb02e1b003c5d652dd2140"
                          "a0d8378453e04fae4e4a346f02e6b827c250a8460f78"),
          "exact TLS 2.0 AEAD vector");
  RecordCipher padded_sender(secret), padded_receiver(secret);
  Require(padded_sender.Seal(data, 23, &record, 239) &&
              padded_receiver.Open(record, &type, &plaintext) &&
              plaintext == data && type == 23,
          "TLSInnerPlaintext zero padding stripped");
  Require(net::httpps::kPreface == "TLS20-EXPERIMENT\r\n" &&
              net::httpps::kPreface.size() == 18,
          "unversioned bootstrap exact bytes");
  std::cout << "TLS 2.0 native tests passed\n";
}
}  // namespace

int main(int argc, char** argv) {
  if (argc >= 4 && std::string_view(argv[1]) == "--check-client-chain") {
    net::httpps::ClientCredential credential;
    auto key = ReadFile(argv[2]);
    Require(key.size() == credential.private_key.size(), "raw client key length");
    std::copy(key.begin(), key.end(), credential.private_key.begin());
    OPENSSL_cleanse(key.data(), key.size());
    for (int i = 3; i < argc; ++i)
      credential.certificates.push_back(ReadFile(argv[i]));
    net::httpps::Client client("localhost", {}, false);
    return client.SetClientCredential(credential) ? 0 : 1;
  }
  if (argc >= 7 && (std::string_view(argv[1]) == "--get-client-chain" ||
                    std::string_view(argv[1]) == "--get-client-ocsp" ||
                    std::string_view(argv[1]) == "--get-client-ocsp-ea")) {
#if defined(_WIN32)
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    net::httpps::ClientCredential credential;
    auto key = ReadFile(argv[5]);
    Require(key.size() == credential.private_key.size(), "raw client key length");
    std::copy(key.begin(), key.end(), credential.private_key.begin());
    OPENSSL_cleanse(key.data(), key.size());
    const bool evidence = std::string_view(argv[1]) != "--get-client-chain";
    const bool evidence_ea = std::string_view(argv[1]) == "--get-client-ocsp-ea";
    if (evidence) {
      Require(argc >= 8, "client OCSP response and certificate paths");
      const auto response = ReadFile(argv[6]);
      credential.ocsp_responses.emplace_back(response.begin(), response.end());
    }
    for (int i = evidence ? 7 : 6; i < argc; ++i)
      credential.certificates.push_back(ReadFile(argv[i]));
    if (evidence) {
      auto invalid = credential;
      invalid.ocsp_responses.resize(invalid.certificates.size() + 1);
      net::httpps::Client probe("localhost", {}, false);
      Require(!probe.SetClientCredential(invalid), "OCSP entries cannot exceed certificate entries");
      invalid = credential;
      invalid.ocsp_responses = {Bytes{0x30, 1}};
      Require(!probe.SetClientCredential(invalid), "truncated OCSP DER envelope rejected locally");
      invalid.ocsp_responses = {Bytes(65528, 0)};
      Require(!probe.SetClientCredential(invalid), "OCSP cannot overflow CertificateEntry extensions");
      invalid = credential;
      invalid.ocsp_responses.front().push_back(0);
      Require(!probe.SetClientCredential(invalid), "trailing OCSP DER bytes rejected locally");
    }
    net::httpps::ClientOptions options;
    options.post_handshake_auth = true;
    return Get(argv[2], argv[3], argv[4], false, false, true, nullptr,
               nullptr, options, nullptr, false, false, false, &credential,
               false, false, ChainRejection::kNone, 0, evidence_ea);
  }
  if (argc >= 6 && std::string_view(argv[1]) == "--verify-native-chain") {
    auto provider = net::httpps::NativeProvider::Load(argv[4]);
    Require(provider != nullptr, "explicit native provider available");
    std::vector<std::string> chain;
    for (int i = 5; i < argc; ++i)
      chain.push_back(ReadFile(argv[i]));
    auto path = provider->VerifyCertificatePath(chain, {ReadFile(argv[3])}, argv[2]);
    if (!path) return 1;
    Require(net::httpps::CertificateTLSFeaturesAllowed(*path), "verified path TLSFeature policy");
    std::cout << "verified path certificates: " << path->size() << '\n';
    return 0;
  }
  if (argc == 4 && std::string_view(argv[1]) == "--gost-provider-test") {
    RunGostProviderTests(argv[2], argv[3]);
    return 0;
  }
#if defined(_WIN32)
  _setmode(_fileno(stdout), _O_BINARY);
#endif
  if ((argc == 3 || argc == 4) && std::string_view(argv[1]) == "--native-provider-test") {
    RunNativeProviderTests(argv[2], argc == 4 ? argv[3] : "");
    return 0;
  }
  if (argc >= 4 && std::string_view(argv[1]) == "--certificate-algorithms") {
    std::vector<std::string> chain;
    for (int i = 3; i < argc; ++i)
      chain.push_back(ReadFile(argv[i]));
    return net::httpps::CertificateAlgorithmsAllowed(chain,
        {static_cast<uint16_t>(ParseUnsigned(argv[2], 16))}) ? 0 : 1;
  }
  if (argc == 6 && std::string_view(argv[1]) == "--get-integrity") {
    net::httpps::ClientOptions options;
    options.ordinary_httpps = false;
    options.allow_integrity_only = true;
    options.cipher_suites = {static_cast<uint16_t>(ParseUnsigned(argv[5], 16))};
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
  }
  if (argc == 8 && std::string_view(argv[1]) == "--get-native-provider") {
    net::httpps::ClientOptions options;
    options.native_provider = net::httpps::NativeProvider::Load(argv[5]);
    Require(options.native_provider != nullptr, "explicit native provider available");
    options.certificate_signature_algorithms.push_back(0x0708);
    options.grant_signature_algorithms.push_back(0x0708);
    options.delegated_credentials = true;
    options.groups = {static_cast<uint16_t>(ParseUnsigned(argv[6]))};
    options.cipher_suites = {static_cast<uint16_t>(ParseUnsigned(argv[7], 16))};
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
  }
  if (argc == 6 && std::string_view(argv[1]) == "--get-ct") {
    auto policy = std::make_shared<net::httpps::CTv2Policy>();
    net::httpps::CTLog log;
    log.id = {0x2b, 0x06, 0x01, 0x04, 0x01};
    auto key = ReadFile(argv[5]);
    log.public_key_spki.assign(key.begin(), key.end());
    policy->logs.push_back(std::move(log));
    net::httpps::ClientOptions options;
    options.ct_v2_policy = std::move(policy);
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
  }
  if (argc == 8 && std::string_view(argv[1]) == "--get-dane") {
    auto policy = std::make_shared<net::httpps::DANEPolicy>();
    policy->provider = net::httpps::DNSSECProvider::Load(argv[5]);
    Require(policy->provider != nullptr, "explicit DNSSEC provider available");
    auto anchor = ReadFile(argv[6]);
    policy->trust_anchors.assign(anchor.begin(), anchor.end());
    policy->port = static_cast<uint16_t>(ParseUnsigned(argv[3]));
    policy->application_policy_context = {'l','o','o','p','b','a','c','k','-','f','i','x','t','u','r','e'};
    const std::string hostname = argv[2];
    policy->dane_path_validator = [hostname](const std::vector<Bytes>& input, const Bytes& ca) {
      std::vector<std::string> path;
      for (const auto& der : input)
        path.emplace_back(der.begin(), der.end());
      net::httpps::Secret ignored;
      return net::httpps::VerifyLabChain(path, {std::string(ca.begin(), ca.end())}, hostname, &ignored);
    };
    net::httpps::ClientOptions options;
    options.dane_policy = std::move(policy);
    if (std::string_view(argv[7]) == "raw")
      options.server_certificate_types = {2};
    else
      Require(std::string_view(argv[7]) == "certificate", "DANE fixture credential kind");
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
  }
#if defined(PHROMIUM_HTTPPS_TEST_DIAGNOSTICS)
  if (argc == 6 && std::string_view(argv[1]) == "--get-diagnostics") {
    net::httpps::ClientOptions options;
    std::string_view mode = argv[5];
    options.authorize_test_diagnostics = mode != "off";
    options.authorize_exporter_diagnostics = mode == "exporters";
    std::vector<std::string> labels;
    options.diagnostic_sink = [&](std::string_view entry) {
      auto first = entry.find(' '), second = entry.find(' ', first + 1);
      Require(first != std::string_view::npos && second == first + 65 &&
                  entry.size() == second + 66 && entry.back() == '\n', "diagnostic complete exact entry");
      labels.emplace_back(entry.substr(0, first));
      if (mode == "throw")
        throw std::ios_base::failure("synthetic diagnostic sink unavailable");
      return mode != "failure";
    };
    int result;
    try {
      result = Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
    } catch (const std::ios_base::failure&) {
      // Deliberately never print exception text or the entry it was given.
      std::cerr << "diagnostic sink failure escaped into the handshake\n";
      return 1;
    }
    Require(labels.size() == (mode == "off" ? 0u : mode == "failure" || mode == "throw" ? 3u : mode == "exporters" ? 18u : 13u),
            "diagnostic gates, derivation events and sink failure");
    if (mode == "exporters") {
      Require(std::count(labels.begin(), labels.end(), "TLS20_EXPORTER_SECRET") == 3 &&
                  std::count(labels.begin(), labels.end(), "TLS20_EARLY_EXPORTER_SECRET") == 2,
              "early exporters exist for both resumed ClientHellos, including zero early payload");
    }
    for (const auto& label : labels)
      Require(label.starts_with("TLS20_") && label.find("SECRET_1") == std::string::npos &&
              (mode == "exporters" || label.find("EXPORTER") == std::string::npos), "diagnostic protocol and category separation");
    return result;
  }
#endif
  if (argc == 6 && std::string_view(argv[1]) == "--get-grease") {
    net::httpps::ClientOptions options;
    options.grease = true;
    options.client_hello_padding = ParseUnsigned(argv[5]);
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
  }
  if (argc == 5 && std::string_view(argv[1]) == "--get-grease-once") {
    net::httpps::ClientOptions options;
    options.grease = true;
    options.client_hello_padding = 20000;
    return Get(argv[2], argv[3], argv[4], false, false, false, nullptr, nullptr, options);
  }
  if ((argc == 5 || argc == 6) && std::string_view(argv[1]) == "--get-controls") {
    net::httpps::ClientOptions options;
    options.ticket_request = net::httpps::TicketRequest{3, 2};
    net::httpps::SignalingBinding signaling;
    signaling.local_hash = Bytes(32, 0x11);
    signaling.peer_hash = Bytes(32, 0x22);
    std::string local = "client-0123456789012345", peer = "server-0123456789012345";
    signaling.local_session_id.assign(local.begin(), local.end());
    signaling.peer_session_id.assign(peer.begin(), peer.end());
    options.signaling = signaling;
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
  }
  if (argc == 9 && std::string_view(argv[1]) == "--get-bootstrap") {
    net::httpps::ClientOptions options;
    options.cipher_suites = {static_cast<uint16_t>(ParseUnsigned(argv[5], 16))};
    net::httpps::BootstrapBinding binding;
    auto spki = ReadFile(argv[6]);
    binding.spki.assign(spki.begin(), spki.end());
    binding.service = argv[2];
    binding.scope = "loopback-provisioning";
    binding.provisioning_trust = std::string_view(argv[8]) == "provisioning";
    options.bootstrap = binding;
    options.ordinary_httpps = !binding.provisioning_trust;
    return Get(argv[2], argv[3], argv[4], false, true, true, argv[6], argv[7], options);
  }
  if (argc == 10 && std::string_view(argv[1]) == "--get-bootstrap-multi") {
    net::httpps::ClientOptions options;
    options.cipher_suites = {0x1301, 0x1302};
    options.groups = {29, 23};
    options.alpn_protocols = {"h2", "http/1.1"};
    const bool provisioning = std::string_view(argv[9]) == "provisioning";
    options.ordinary_httpps = !provisioning;
    for (size_t offset : {size_t{5}, size_t{7}}) {
      net::httpps::BootstrapBinding binding;
      auto spki = ReadFile(argv[offset]);
      auto key = ReadFile(argv[offset + 1]);
      Require(key.size() == 32, "explicit bootstrap inventory private key");
      binding.spki.assign(spki.begin(), spki.end());
      binding.service = argv[2];
      binding.scope = offset == 5 ? "unselected-bootstrap" : "loopback-provisioning";
      binding.provisioning_trust = provisioning;
      binding.credential.emplace();
      binding.credential->certificates = {spki};
      binding.credential->certificate_type = 2;
      std::copy(key.begin(), key.end(), binding.credential->private_key.begin());
      OPENSSL_cleanse(key.data(), key.size());
      options.bootstraps.push_back(std::move(binding));
    }
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr,
               options, nullptr, false, false, false, nullptr, true);
  }
  if (argc == 5 && std::string_view(argv[1]) == "--get-pinning") {
    return Get(argv[2], argv[3], argv[4], false, false, true, nullptr, nullptr,
               {}, nullptr, false, false, true);
  }
  if (argc == 8 && std::string_view(argv[1]) == "--get-authenticator") {
    net::httpps::ClientOptions options;
    options.spontaneous_authenticators = true;
    options.request_ocsp = true;
    options.request_scts = true;
    options.cipher_suites = {static_cast<uint16_t>(ParseUnsigned(argv[5], 16))};
    return Get(argv[2], argv[3], argv[4], false, false, true,
               std::string_view(argv[6]) == "-" ? nullptr : argv[6],
               std::string_view(argv[7]) == "-" ? nullptr : argv[7], options, nullptr, false, true);
  }
  if (argc == 8 && std::string_view(argv[1]) == "--get-cache") {
    net::httpps::ClientOptions options;
    if (ParseUnsigned(argv[5]))
      options.certificate_compression = {static_cast<uint16_t>(ParseUnsigned(argv[5]))};
    options.post_handshake_auth = true;
    return Get(argv[2], argv[3], argv[4], false, false, true,
               std::string_view(argv[6]) == "-" ? nullptr : argv[6],
               std::string_view(argv[7]) == "-" ? nullptr : argv[7], options, nullptr, true);
  }
  if (argc == 8 && std::string_view(argv[1]) == "--get-delegation") {
    net::httpps::ClientOptions options;
    options.delegated_credentials = true;
    options.certificate_compression = {1, 2, 3};
    return Get(argv[2], argv[3], argv[4], false, true, true,
               std::string_view(argv[5]) == "-" ? nullptr : argv[5],
               std::string_view(argv[6]) == "-" ? nullptr : argv[6], options,
               std::string_view(argv[7]) == "-" ? nullptr : argv[7]);
  }
  if (argc == 7 && std::string_view(argv[1]) == "--delegation-alert") {
    net::httpps::ClientOptions options;
    options.delegated_credentials = true;
    options.allow_unauthenticated = std::string_view(argv[5]) == "unauthenticated";
    options.ordinary_httpps = !options.allow_unauthenticated;
    if (std::string_view(argv[5]) == "compressed")
      options.certificate_compression = {1, 2, 3};
    const auto expected = ParseUnsigned(argv[6]);
    Require(expected == 0 || expected == 42 || expected == 47 || expected == 50,
            "explicit delegated credential rejection alert or positive control");
    return Get(argv[2], argv[3], argv[4], false, false, true, nullptr, nullptr,
               options, nullptr, false, false, false, nullptr, false, false,
               ChainRejection::kNone, static_cast<uint8_t>(expected));
  }
  if (argc == 9 && std::string_view(argv[1]) == "--get-delegation-direction") {
    net::httpps::ClientOptions options;
    options.delegated_credentials = true;
    options.grant_signature_algorithms = {0x0403};
    options.post_handshake_auth = true;
    const bool authenticator = std::string_view(argv[8]) == "ea";
    return Get(argv[2], argv[3], argv[4], false, false, true,
               argv[5], argv[6], options, argv[7], false, authenticator);
  }
  if (argc == 5 && std::string_view(argv[1]) == "--check-client-delegation") {
    net::httpps::ClientCredential credential;
    credential.certificates = {ReadFile(argv[2])};
    auto key = ReadFile(argv[3]);
    Require(key.size() == credential.private_key.size(), "local delegated key length");
    std::copy(key.begin(), key.end(), credential.private_key.begin());
    OPENSSL_cleanse(key.data(), key.size());
    const auto grant = ReadFile(argv[4]);
    credential.delegation.assign(grant.begin(), grant.end());
    net::httpps::ClientOptions options;
    options.delegated_credentials = true;
    options.grant_signature_algorithms = {0x0403};
    net::httpps::Client client("example.test", {}, false, options);
    return client.SetClientCredential(credential) ? 0 : 1;
  }
  if (argc == 8 && std::string_view(argv[1]) == "--get-compression") {
    net::httpps::ClientOptions options;
    options.certificate_compression = {static_cast<uint16_t>(ParseUnsigned(argv[5]))};
    options.post_handshake_auth = true;
    return Get(argv[2], argv[3], argv[4], false, false, true,
               std::string_view(argv[6]) == "-" ? nullptr : argv[6],
               std::string_view(argv[7]) == "-" ? nullptr : argv[7], options);
  }
  if (argc == 8 && std::string_view(argv[1]) == "--get-rpk") {
    net::httpps::ClientOptions options;
    options.server_certificate_types = {2};
    auto pin = ReadFile(argv[5]);
    options.server_raw_public_keys.emplace_back(pin.begin(), pin.end());
    return Get(argv[2], argv[3], argv[4], false, true, true,
               std::string_view(argv[6]) == "-" ? nullptr : argv[6],
               std::string_view(argv[7]) == "-" ? nullptr : argv[7], options);
  }
  if ((argc == 11 || argc == 12) && (std::string_view(argv[1]) == "--get-password" ||
                                    std::string_view(argv[1]) == "--get-password-mixed")) {
    net::httpps::ClientOptions options;
    options.native_provider = net::httpps::NativeProvider::Load(argv[5]);
    Require(options.native_provider != nullptr, "explicit PAKE native provider");
    auto credential = std::make_shared<net::httpps::PasswordCredential>();
    credential->service = argv[2];
    credential->helper_path = argv[6];
    credential->username = "alice";
    credential->password = argv[9];
    if (argc == 12) {
      const auto spki = ReadFile(argv[11]);
      credential->protection_spki.assign(spki.begin(), spki.end());
    }
    options.password = credential;
    options.cipher_suites = {static_cast<uint16_t>(ParseUnsigned(argv[7], 16))};
    if (std::string_view(argv[1]) == "--get-password-mixed") {
      options.cipher_suites.push_back(0x1301);
      options.cipher_suites.push_back(0x1302);
    }
    options.groups = {static_cast<uint16_t>(ParseUnsigned(argv[8]))};
    return Get(argv[2], argv[3], argv[4], false,
        std::string_view(argv[10]) == "resume", true, nullptr, nullptr, options);
  }
  if (argc == 9 && std::string_view(argv[1]) == "--get-password-authenticator") {
    net::httpps::ClientOptions options;
    options.native_provider = net::httpps::NativeProvider::Load(argv[5]);
    auto credential = std::make_shared<net::httpps::PasswordCredential>();
    credential->service = argv[2]; credential->helper_path = argv[6];
    credential->username = "alice"; credential->password = "correct horse";
    options.password = credential;
    options.cipher_suites = {0xc0b1}; options.groups = {24};
    options.spontaneous_authenticators = true;
    options.request_ocsp = true;
    options.request_scts = true;
    return Get(argv[2], argv[3], argv[4], false, false, true,
        std::string_view(argv[7]) == "-" ? nullptr : argv[7],
        std::string_view(argv[8]) == "-" ? nullptr : argv[8], options, nullptr, false, true);
  }
  if (argc == 9 && std::string_view(argv[1]) == "--get-gost") {
    net::httpps::ClientOptions options;
    options.native_provider = net::httpps::NativeProvider::Load(argv[5], argv[6]);
    Require(options.native_provider && options.native_provider->SupportsGost(), "explicit GOST native provider");
    options.cipher_suites = {static_cast<uint16_t>(ParseUnsigned(argv[7], 16))};
    options.groups = {static_cast<uint16_t>(ParseUnsigned(argv[8]))};
    for (uint16_t algorithm = 0x0709; algorithm <= 0x070f; ++algorithm) {
      options.certificate_signature_algorithms.push_back(algorithm);
      options.grant_signature_algorithms.push_back(algorithm);
    }
    options.delegated_credentials = true;
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
  }
  if (argc == 8 && std::string_view(argv[1]) == "--get-its") {
    const std::filesystem::path directory(argv[6]);
    auto read = [&](const char* name) { return ReadFile((directory / name).string().c_str()); };
    const auto wire = read("live-policy.bin");
    net::httpps::ByteSpan cursor = net::httpps::StringBytes(wire).subspan(4u);
    auto number = [&](size_t count) {
      Require(cursor.size() >= count, "ITS fixture integer");
      uint64_t value = 0;
      for (auto byte : cursor.first(count)) value = (value << 8) | byte;
      cursor = cursor.subspan(count);
      return value;
    };
    auto vector = [&](size_t width) {
      const size_t count = number(width);
      Require(count <= cursor.size(), "ITS fixture vector");
      auto bytes = cursor.first(count); cursor = cursor.subspan(count);
      return Bytes(bytes.begin(), bytes.end());
    };
    auto policy = std::make_shared<net::httpps::ITSPolicy>();
    policy->provider = net::httpps::ITSProvider::Load(argv[5]);
    policy->identity = argv[2]; policy->tai_utc_offset = 37;
    number(8);
    policy->inventory_valid_until = number(8);
    policy->max_grant_lifetime_microseconds = number(8);
    policy->role = number(1); policy->psid = number(8);
    policy->application_scope = vector(2); policy->ssp_coer = vector(2);
    const auto root = read("live-root.coer"), leaf = read("live-leaf.coer");
    policy->trust_roots.emplace_back(root.begin(), root.end());
    const auto leaf_hash = net::httpps::Hash(net::httpps::StringBytes(leaf));
    policy->authorized_leaves.emplace_back(leaf_hash.begin(), leaf_hash.end());
    const std::string_view mode = argv[7];
    if (mode == "revoked") policy->revoked = policy->authorized_leaves;
    if (mode == "expired") policy->inventory_valid_until = 1;
    if (mode == "wrong-role") policy->role = 1;
    if (mode == "wrong-service") policy->identity = "other.test";
    net::httpps::ClientOptions options;
    options.its_policy = policy; options.server_certificate_types = {3};
    options.post_handshake_auth = mode == "client";
    std::optional<net::httpps::ClientCredential> credential;
    if (mode == "client") {
      credential.emplace(); credential->certificate_type = 3;
      credential->certificates = {read("live-client.bin")};
      credential->private_key.fill(9);
      auto client_policy = std::make_shared<net::httpps::ITSPolicy>(*policy);
      client_policy->role = 1;
      credential->its_policy = std::move(client_policy);
    }
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr,
               options, nullptr, false, false, false, credential ? &*credential : nullptr);
  }
  if (argc == 6 && std::string_view(argv[1]) == "--get-public-signature") {
    net::httpps::ClientOptions options;
    options.native_provider = net::httpps::NativeProvider::Load(argv[5]);
    Require(options.native_provider != nullptr, "explicit signature provider");
    for (uint16_t algorithm : {0x0808, 0x0809, 0x080a, 0x080b, 0x081a, 0x081b, 0x081c}) {
      options.certificate_signature_algorithms.push_back(algorithm);
      options.grant_signature_algorithms.push_back(algorithm);
    }
    options.delegated_credentials = true;
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
  }
  if (argc == 6 && std::string_view(argv[1]) == "--check-ocsp-request") {
    net::httpps::ClientOptions options;
    auto id = ReadFile(argv[2]), extensions = ReadFile(argv[3]), response = ReadFile(argv[4]);
    if (!id.empty()) options.ocsp_responder_ids.emplace_back(id.begin(), id.end());
    options.ocsp_request_extensions.assign(extensions.begin(), extensions.end());
    auto name = ReadFile(argv[5]);
    if (!name.empty()) options.certificate_authorities.emplace_back(name.begin(), name.end());
    if (!net::httpps::CredentialRequestOptionsValid(options)) return 2;
    return net::httpps::OCSPRequestMatchesResponse(options, net::httpps::StringBytes(response)) ? 0 : 1;
  }
  if (argc == 8 && std::string_view(argv[1]) == "--get-credential-request") {
    net::httpps::ClientOptions options;
    const auto name = ReadFile(argv[5]), id = ReadFile(argv[6]), extensions = ReadFile(argv[7]);
    options.request_ocsp = true;
    options.certificate_authorities.emplace_back(name.begin(), name.end());
    options.ocsp_responder_ids.emplace_back(id.begin(), id.end());
    options.ocsp_request_extensions.assign(extensions.begin(), extensions.end());
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr,
               options, nullptr, false, false, false, nullptr, false, true);
  }
  if (argc == 6 && std::string_view(argv[1]) == "--check-delegated-credential") {
    auto provider = net::httpps::NativeProvider::Load(argv[5]);
    const auto certificate = ReadFile(argv[2]), root = ReadFile(argv[3]), grant = ReadFile(argv[4]);
    const std::string leaf(certificate.begin(), certificate.end()), anchor(root.begin(), root.end());
    net::httpps::Secret key;
    Require(provider != nullptr, "signature provider");
    Require(net::httpps::VerifyLabChain({leaf}, {anchor}, "example.test", &key, true, provider.get()), "delegated parent path");
    Require(net::httpps::ValidateDelegation(leaf, net::httpps::StringBytes(grant), true,
        {0x0808, 0x0809, 0x080a, 0x080b, 0x081a, 0x081b, 0x081c}, &key, provider.get()), "delegated grant signature");
    return 0;
  }
  if (argc == 7 && std::string_view(argv[1]) == "--get-limit") {
    net::httpps::ClientOptions options;
    options.record_size_limit = static_cast<uint16_t>(ParseUnsigned(argv[5]));
    options.record_padding_multiple = ParseUnsigned(argv[6]);
    return Get(argv[2], argv[3], argv[4], false, true, true, nullptr, nullptr, options);
  }
  if (argc == 12 && std::string_view(argv[1]) == "--get-psk") {
    net::httpps::ClientOptions options;
    net::httpps::ExternalPSK psk;
    psk.identity = Unhex(argv[5]);
    psk.secret = Unhex(argv[6]);
    psk.hostname = argv[2];
    psk.cipher_suite = static_cast<uint16_t>(std::stoul(argv[7], nullptr, 16));
    psk.imported = std::string_view(argv[9]) == "imp";
    psk.combined = std::string_view(argv[10]) == "combined";
    psk.max_early_data = std::string_view(argv[11]) == "early" ? 16384 : 0;
    options.cipher_suites = {psk.cipher_suite};
    options.psk_modes = {static_cast<uint8_t>(ParseUnsigned(argv[8]))};
    if (std::string_view(argv[11]) == "multiple") {
      auto unknown = psk;
      unknown.identity.push_back(0);
      unknown.secret[0] ^= 1;
      options.external_psks.push_back(std::move(unknown));
    }
    options.external_psks.push_back(std::move(psk));
    return Get(argv[2], argv[3], argv[4], false, std::string_view(argv[11]) == "resume",
               true, nullptr, nullptr, options);
  }
  if (argc == 7 && std::string_view(argv[1]) == "--get-pha") {
    net::httpps::ClientOptions options;
    options.post_handshake_auth = true;
    return Get(argv[2], argv[3], argv[4], false, false, true,
               std::string_view(argv[5]) == "-" ? nullptr : argv[5],
               std::string_view(argv[6]) == "-" ? nullptr : argv[6], options);
  }
  if (argc == 9 && std::string_view(argv[1]) == "--oid-filter-alert") {
    net::httpps::ClientOptions options;
    const std::string_view mode = argv[7];
    Require(mode == "initial" || mode == "pha", "explicit OID request phase");
    options.post_handshake_auth = mode == "pha";
    const unsigned expected = ParseUnsigned(argv[8]);
    Require(expected == 0 || expected == 47 || expected == 50,
            "explicit OID request syntax or semantic alert");
    return Get(argv[2], argv[3], argv[4], false, false, true,
               std::string_view(argv[5]) == "-" ? nullptr : argv[5],
               std::string_view(argv[6]) == "-" ? nullptr : argv[6], options,
               nullptr, false, false, false, nullptr, false, false, ChainRejection::kNone,
               mode == "initial" ? static_cast<uint8_t>(expected) : 0, false, false,
               mode == "pha" ? static_cast<uint8_t>(expected) : 0);
  }
  if (argc == 10 && std::string_view(argv[1]) == "--cached-request-alert") {
    net::httpps::ClientOptions options;
    const auto value = ReadFile(argv[5]);
    options.cached_request_templates.emplace_back(value.begin(), value.end());
    const std::string_view mode = argv[8];
    Require(mode == "initial" || mode == "pha", "explicit cached request phase");
    options.post_handshake_auth = mode == "pha";
    const unsigned expected = ParseUnsigned(argv[9]);
    Require(expected == 0 || expected == 10 || expected == 47 || expected == 50,
            "explicit cached request syntax or semantic alert");
    return Get(argv[2], argv[3], argv[4], false, false, true, argv[6], argv[7], options,
               nullptr, false, false, false, nullptr, false, false, ChainRejection::kNone,
               mode == "initial" ? static_cast<uint8_t>(expected) : 0, false, false,
               mode == "pha" ? static_cast<uint8_t>(expected) : 0);
  }
  if (argc == 7 && (std::string_view(argv[1]) == "--get-suite" ||
                   std::string_view(argv[1]) == "--get-suite-resume")) {
    net::httpps::ClientOptions options;
    options.cipher_suites = {static_cast<uint16_t>(ParseUnsigned(argv[2], 16))};
    options.groups = {static_cast<uint16_t>(ParseUnsigned(argv[3]))};
    return Get(argv[4], argv[5], argv[6], false,
               std::string_view(argv[1]) == "--get-suite-resume", true,
               nullptr, nullptr, options);
  }
  if (argc == 7 && (std::string_view(argv[1]) == "--get-client-auth" ||
                   std::string_view(argv[1]) == "--get-client-auth-resume")) {
    return Get(argv[2], argv[3], argv[4], false,
               std::string_view(argv[1]) == "--get-client-auth-resume", true,
               argv[5], argv[6]);
  }
  if (argc == 5 && (std::string_view(argv[1]) == "--get-no-alpn" ||
                   std::string_view(argv[1]) == "--get-unauthenticated" ||
                   std::string_view(argv[1]) == "--get-unauthenticated-resume")) {
    net::httpps::ClientOptions options;
    options.no_alpn_http11 = std::string_view(argv[1]) == "--get-no-alpn";
    options.allow_unauthenticated = !options.no_alpn_http11;
    options.ordinary_httpps = !options.allow_unauthenticated;
    return Get(argv[2], argv[3], argv[4], false,
               std::string_view(argv[1]) == "--get-unauthenticated-resume", true,
               nullptr, nullptr, options);
  }
  if (argc == 7 && std::string_view(argv[1]) == "--reject-compression-alert") {
    net::httpps::ClientOptions options;
    options.certificate_compression = {static_cast<uint16_t>(ParseUnsigned(argv[5]))};
    const unsigned expected = ParseUnsigned(argv[6]);
    Require(expected == 42 || expected == 47 || expected == 50,
            "explicit compression rejection alert");
    return Get(argv[2], argv[3], argv[4], false, false, true, nullptr, nullptr, options,
               nullptr, false, false, false, nullptr, false, false, ChainRejection::kNone,
               static_cast<uint8_t>(expected));
  }
  if ((argc == 10 || argc == 11) && std::string_view(argv[1]) == "--certificate-alert") {
    net::httpps::ClientOptions options;
    const auto compression = ParseUnsigned(argv[6]);
    Require(compression <= 3, "explicit certificate compression algorithm");
    if (compression)
      options.certificate_compression = {static_cast<uint16_t>(compression)};
    if (ParseUnsigned(argv[7]))
      options.cached_certificates = {{0, {ReadFile(argv[5])}}};
    options.request_ocsp = std::string_view(argv[8]) == "ocsp";
    options.request_scts = std::string_view(argv[8]) == "sct";
    if (std::string_view(argv[8]) == "ct") {
      Require(argc == 11, "CT envelope fixture requires an explicit trusted log");
      auto policy = std::make_shared<net::httpps::CTv2Policy>();
      net::httpps::CTLog log;
      log.id = {0x2b, 0x06, 0x01, 0x04, 0x01};
      const auto key = ReadFile(argv[10]);
      log.public_key_spki.assign(key.begin(), key.end());
      policy->logs.push_back(std::move(log));
      options.ct_v2_policy = std::move(policy);
    }
    const auto expected = ParseUnsigned(argv[9]);
    Require(expected == 0 || expected == 10 || expected == 47 || expected == 50 || expected == 110,
            "explicit CertificateEntry rejection alert or positive control");
    return Get(argv[2], argv[3], argv[4], false, false, true, nullptr, nullptr,
               options, nullptr, false, false, false, nullptr, false, false,
               ChainRejection::kNone, static_cast<uint8_t>(expected));
  }
  if (argc == 7 && std::string_view(argv[1]) == "--reject-ee-alert") {
    net::httpps::ClientOptions options;
    if (std::string_view(argv[5]) == "heartbeat") options.heartbeat_mode = 1;
    else if (std::string_view(argv[5]) == "rsl") options.record_size_limit = 16385;
    else if (std::string_view(argv[5]) == "mfl") options.max_fragment_length = 1;
    else if (std::string_view(argv[5]) == "ticket") options.ticket_request = net::httpps::TicketRequest{};
    else if (std::string_view(argv[5]) == "server-type") options.server_certificate_types = {0, 2};
    const unsigned expected = ParseUnsigned(argv[6]);
    Require(expected == 0 || expected == 47 || expected == 50 || expected == 110,
            "explicit encrypted-extension rejection alert or positive control");
    return Get(argv[2], argv[3], argv[4], false, false, true, nullptr, nullptr, options,
               nullptr, false, false, false, nullptr, false, false, ChainRejection::kNone,
               static_cast<uint8_t>(expected));
  }
  if ((argc == 7 || argc == 9) && std::string_view(argv[1]) == "--hello-structure-alert") {
    net::httpps::ClientOptions options;
    const std::string_view mode = argv[5];
    if (mode == "psk" || mode == "combined") {
      net::httpps::ExternalPSK psk;
      psk.identity = Bytes{1}; psk.secret = Bytes(32, 7); psk.hostname = argv[2];
      psk.combined = mode == "combined";
      options.external_psks = {psk};
    } else if (mode == "pwd") {
      Require(argc == 9, "PWD alert fixture requires an explicit provider/helper");
      options.native_provider = net::httpps::NativeProvider::Load(argv[7]);
      Require(options.native_provider != nullptr, "explicit PWD alert provider");
      auto credential = std::make_shared<net::httpps::PasswordCredential>();
      credential->service = argv[2]; credential->helper_path = argv[8];
      credential->username = "alice"; credential->password = "correct horse";
      options.password = credential;
      options.cipher_suites = {0xc0b0}; options.groups = {23};
    } else {
      Require(mode == "none", "explicit Hello fixture mode");
    }
    const auto expected = ParseUnsigned(argv[6]);
    Require(expected == 0 || expected == 47 || expected == 50, "explicit Hello syntax alert");
    return Get(argv[2], argv[3], argv[4], false, false, true, nullptr, nullptr, options,
               nullptr, false, false, false, nullptr, false, false, ChainRejection::kNone,
               static_cast<uint8_t>(expected), false, true);
  }
  if (argc == 6 && std::string_view(argv[1]) == "--reject-hello-alert") {
    const unsigned expected = ParseUnsigned(argv[5]);
    Require(expected == 47 || expected == 50 || expected == 110,
            "explicit Hello rejection alert");
    return Get(argv[2], argv[3], argv[4], false, false, true, nullptr, nullptr, {},
               nullptr, false, false, false, nullptr, false, false, ChainRejection::kNone,
               static_cast<uint8_t>(expected), false, true);
  }
  if (argc == 5 && (std::string_view(argv[1]) == "--reject-long-chain" ||
                   std::string_view(argv[1]) == "--reject-long-chain-reset")) {
    return Get(argv[2], argv[3], argv[4], false, false, true, nullptr, nullptr, {},
               nullptr, false, false, false, nullptr, false, false,
               std::string_view(argv[1]) == "--reject-long-chain-reset"
                   ? ChainRejection::kReset : ChainRejection::kSendAlert);
  }
  if (argc == 5 && (std::string_view(argv[1]) == "--get-resume-reject" ||
                    std::string_view(argv[1]) == "--get-resume" ||
                    std::string_view(argv[1]) == "--get" ||
                    std::string_view(argv[1]) == "--get-external")) {
    return Get(argv[2], argv[3], argv[4],
               std::string_view(argv[1]) == "--get-external",
               std::string_view(argv[1]).starts_with("--get-resume"),
               std::string_view(argv[1]) != "--get-resume-reject");
  }
  if (argc >= 5 && std::string_view(argv[1]) == "--verify") {
    std::vector<std::string> chain;
    for (int i = 4; i < argc; ++i) {
      chain.push_back(ReadFile(argv[i]));
    }
    net::httpps::Secret key;
    return net::httpps::VerifyLabChain(chain, {ReadFile(argv[3])}, argv[2],
                                       &key)
               ? 0
               : 1;
  }
  if (argc == 5 && std::string_view(argv[1]) == "--cert-mutations") {
    auto root = ReadFile(argv[3]);
    auto leaf = ReadFile(argv[4]);
    net::httpps::Secret key;
    Require(net::httpps::VerifyLabChain({leaf}, {root}, argv[2], &key),
            "original certificate valid");
    for (size_t i = 0; i < leaf.size(); ++i) {
      auto mutation = leaf;
      mutation[i] ^= 1;
      Require(!net::httpps::VerifyLabChain({mutation}, {root}, argv[2], &key),
              "every certificate byte is protected or strictly parsed");
    }
    std::cout << leaf.size() << " certificate byte mutation checks passed\n";
    return 0;
  }
  SelfTest();
  return 0;
}
