// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Portable test driver for the exact engine used by HttppsClientSocket. The
// optional network mode connects ONLY to loopback; it is not a browser proxy.
#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>

#include "net/httpps/draft01.h"
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

namespace {
using net::httpps::Bytes;

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

int Get(const char* host,
        const char* port,
        const char* root,
        bool external_verification,
        bool resume_test = false,
        bool expect_early_acceptance = true,
        const char* client_leaf = nullptr,
        const char* client_key = nullptr) {
#if defined(_WIN32)
  WSADATA data;
  Require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "winsock init");
#endif
  std::optional<net::httpps::SessionTicket> session;
  for (int round = 0; round < (resume_test ? 3 : 1); ++round) {
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
      host, external_verification ? std::vector<std::string>{} : anchors,
      external_verification);
  if (client_leaf && client_key) {
    net::httpps::ClientCredential credential;
    credential.certificates.push_back(ReadFile(client_leaf));
    auto key = ReadFile(client_key);
    Require(key.size() == credential.private_key.size(), "raw client X25519 key length");
    std::copy(key.begin(), key.end(), credential.private_key.begin());
    Require(client.SetClientCredential(credential), "explicit client credential selection");
    OPENSSL_cleanse(key.data(), key.size());
  }
  const bool early = round == 2;
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
    Require(client.Receive(Record(stream), &unused),
            "authenticated server flight");
    if (client.certificate_verification_pending()) {
      Require(external_verification && !client.established() &&
                  client.TakeOutput().empty(),
              "no Finished or application data before trust decision");
      // Exercise the engine's deferred decision boundary independently of
      // Chromium. This fixture validator is NOT the browser CertVerifier.
      net::httpps::Secret key;
      bool trusted = net::httpps::VerifyLabChain(client.certificates(), anchors,
                                                 host, &key);
      Require(client.CompleteCertificateVerification(trusted),
              "external certificate decision and buffered proof");
    }
    auto output = client.TakeOutput();
    if (!output.empty()) {
      Send(stream, output);
      Require(client.OutputFlushed(), "CF flush");
    }
  }
  Bytes output;
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
  if (!early || !client.early_data_accepted()) {
    if (resume_test) {
      Require(client.RequestKeyUpdate(true, &output), "request key update");
      Send(stream, output);
    }
    Require(client.Send(Bytes(request.begin(), request.end()), &output),
            "application encrypt");
    Send(stream, output);
  }
  while (!client.closed()) {
    Require(client.Receive(Record(stream), &output), "application decrypt");
    auto tickets = client.TakeTickets();
    if (!tickets.empty()) {
      session = std::move(tickets.back());
      if (client_leaf) {
        net::httpps::Client removed_identity(host, anchors);
        Require(!removed_identity.Start(&*session),
                "a client-authenticated ticket cannot outlive identity selection");
      }
    }
    std::cout.write(reinterpret_cast<const char*>(output.data()),
                    output.size());
  }
  if (client.Close(&output)) {
    Send(stream, output);
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

void SelfTest() {
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
#if defined(_WIN32)
  _setmode(_fileno(stdout), _O_BINARY);
#endif
  if (argc == 7 && (std::string_view(argv[1]) == "--get-client-auth" ||
                   std::string_view(argv[1]) == "--get-client-auth-resume")) {
    return Get(argv[2], argv[3], argv[4], false,
               std::string_view(argv[1]) == "--get-client-auth-resume", true,
               argv[5], argv[6]);
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
