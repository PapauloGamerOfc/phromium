// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/draft01.h"
#include "net/httpps/credential_validation.h"

#include <algorithm>
#if !defined(PHROMIUM_HTTPPS_STANDALONE)
#include "base/memory/stack_allocated.h"
#endif
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net::httpps {
namespace {
using Extensions = std::map<uint16_t, Bytes>;

void Append(Bytes* out, ByteSpan value) {
  out->insert(out->end(), value.begin(), value.end());
}
void Number(Bytes* out, size_t value, size_t width) {
  for (size_t i = width; i; --i)
    out->push_back(static_cast<uint8_t>(value >> (8 * (i - 1))));
}
void Vector(Bytes* out, ByteSpan value, size_t width) {
  Number(out, value.size(), width);
  Append(out, value);
}
Bytes Frame(uint8_t type, ByteSpan body) {
  Bytes out{type};
  Vector(&out, body, 3);
  return out;
}
bool Equal(ByteSpan a, ByteSpan b) {
  return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
struct Reader {
#if !defined(PHROMIUM_HTTPPS_STANDALONE)
  STACK_ALLOCATED();
 public:
#endif
  ByteSpan input;
  bool Take(size_t size, ByteSpan* result) {
    if (size > input.size())
      return false;
    *result = input.first(size);
    input = input.subspan(size);
    return true;
  }
  bool Vector(size_t width, ByteSpan* result) {
    ByteSpan encoded;
    if (!Take(width, &encoded))
      return false;
    size_t size = 0;
    for (uint8_t byte : encoded)
      size = (size << 8) | byte;
    return Take(size, result);
  }
  bool Frame(uint8_t type, ByteSpan* frame, ByteSpan* body) {
    auto start = input;
    ByteSpan kind;
    if (!Take(1, &kind) || kind[0] != type || !Vector(3, body))
      return false;
    *frame = start.first(start.size() - input.size());
    return true;
  }
};
bool DecodeExtensions(ByteSpan value, Extensions* extensions) {
  Reader reader{value};
  while (!reader.input.empty()) {
    ByteSpan kind, data;
    if (!reader.Take(2, &kind) || !reader.Vector(2, &data))
      return false;
    uint16_t code = (uint16_t{kind[0]} << 8) | kind[1];
    if (code == 13 || !extensions->emplace(code, Bytes(data.begin(), data.end())).second)
      return false;
  }
  return true;
}
bool EncodeExtensions(const Extensions& extensions, Bytes* encoded) {
  for (const auto& [kind, value] : extensions) {
    if (value.size() > 65535)
      return false;
    Number(encoded, kind, 2);
    Vector(encoded, value, 2);
  }
  return encoded->size() <= 65535;
}
bool Algorithms(ByteSpan encoded, std::vector<uint16_t>* out) {
  Reader reader{encoded};
  ByteSpan list;
  if (!reader.Vector(2, &list) || !reader.input.empty() || list.empty() || list.size() % 2)
    return false;
  for (size_t i = 0; i < list.size(); i += 2)
    out->push_back((uint16_t{list[i]} << 8) | list[i + 1]);
  return true;
}
bool Offers(const Extensions& extensions) {
  auto path = extensions.find(50);
  if (path == extensions.end() || extensions.count(13))
    return false;
  std::vector<uint16_t> algorithms;
  if (!Algorithms(path->second, &algorithms))
    return false;
  auto signatures = [](const std::vector<uint16_t>& values) {
    return std::none_of(values.begin(), values.end(), [](uint16_t code) {
      return code == 0xfe00 || code == 0xfe01 || code == 0x0420 || code == 0x0520 || code == 0x0620;
    });
  };
  if (!signatures(algorithms) || extensions.count(34) != extensions.count(0xff04))
    return false;
  if (extensions.count(34)) {
    std::vector<uint16_t> macs, grants;
    // Unsupported delegated schemes are valid offers. They prevent selecting
    // that delegated credential, but do not prevent a direct X25519 identity.
    if (!Algorithms(extensions.at(34), &macs) ||
        !Algorithms(extensions.at(0xff04), &grants) || !signatures(grants))
      return false;
  }
  return true;
}
struct Request {
  bool server;
  Bytes context;
  Extensions extensions;
  Secret share{};
};
bool ParseRequest(ByteSpan wire, Request* request) {
  *request = Request{};
  if (wire.empty() || (wire[0] != 13 && wire[0] != 17))
    return false;
  Reader reader{wire};
  ByteSpan frame, body, context, extensions;
  if (!reader.Frame(wire[0], &frame, &body) || !reader.input.empty())
    return false;
  reader.input = body;
  if (!reader.Vector(1, &context) || !reader.Vector(2, &extensions) ||
      !reader.input.empty() || !DecodeExtensions(extensions, &request->extensions))
    return false;
  request->server = wire[0] == 17;
  request->context.assign(context.begin(), context.end());
  const uint16_t share_type = request->server ? 0xff02 : 0xff03;
  auto share = request->extensions.find(share_type);
  if (share == request->extensions.end() || share->second.size() != 32 ||
      request->extensions.count(request->server ? 0xff03 : 0xff02))
    return false;
  for (const auto& [code, data] : request->extensions)
    if (!RequestExtensionAllowed(code, request->server
            ? RequestExtensionContext::kServerAuthenticator
            : RequestExtensionContext::kClientAuthenticator))
      return false;
  if (!request->server && request->extensions.count(0))
    return false;
  // Both requested directions inherit CR's empty OCSP request. Only a
  // spontaneous server authenticator inherits the ClientHello request.
  if (request->extensions.count(5) && !request->extensions.at(5).empty())
    return false;
  std::vector<Bytes> authorities;
  if (request->extensions.count(47) &&
      !ParseCertificateAuthorities(request->extensions.at(47), &authorities))
    return false;
  std::copy(share->second.begin(), share->second.end(), request->share.begin());
  return Offers(request->extensions);
}
bool Certificate(const AuthenticatorIdentity& identity, Bytes* frame) {
  if (identity.context.size() > 255 || identity.certificates.size() > kMaxCertificates ||
      identity.extensions.size() != identity.certificates.size())
    return false;
  Bytes entries;
  for (size_t i = 0; i < identity.certificates.size(); ++i) {
    if (identity.certificates[i].empty() || identity.certificates[i].size() > 0xffffff)
      return false;
    Bytes extensions;
    if (!EncodeExtensions(identity.extensions[i], &extensions))
      return false;
    Vector(&entries, StringBytes(identity.certificates[i]), 3);
    Vector(&entries, extensions, 2);
  }
  if (entries.size() > 0xffffff - identity.context.size() - 4)
    return false;
  Bytes body;
  Vector(&body, identity.context, 1);
  Vector(&body, entries, 3);
  *frame = Frame(11, body);
  return true;
}
bool ParseCertificate(ByteSpan body, AuthenticatorIdentity* identity) {
  Reader reader{body};
  ByteSpan context, entries;
  if (!reader.Vector(1, &context) || !reader.Vector(3, &entries) || !reader.input.empty())
    return false;
  identity->context.assign(context.begin(), context.end());
  reader.input = entries;
  while (!reader.input.empty()) {
    if (identity->certificates.size() >= kMaxCertificates)
      return false;
    ByteSpan der, extensions;
    Extensions parsed;
    if (!reader.Vector(3, &der) || der.empty() || !reader.Vector(2, &extensions) ||
        !DecodeExtensions(extensions, &parsed))
      return false;
    identity->certificates.emplace_back(reinterpret_cast<const char*>(der.data()), der.size());
    identity->extensions.push_back(std::move(parsed));
  }
  return true;
}
bool CertificateOffers(const AuthenticatorIdentity& identity, const Extensions& offers) {
  for (size_t i = 0; i < identity.extensions.size(); ++i) {
    for (const auto& [kind, value] : identity.extensions[i]) {
      if (!offers.count(kind) || (kind != 5 && kind != 18 && kind != 34 && kind != 52 && kind != 59) ||
          (kind == 34 && i != 0))
        return false;
      // Evidence policy may ignore an unknown SCT, but cannot decide whether
      // its enclosing protocol vectors are well-formed. Keep these checks in
      // the application authenticator: rejection must not emit a TLS alert.
      Reader reader{value};
      ByteSpan payload;
      if (kind == 5) {
        ByteSpan type;
        if (!reader.Take(1, &type) || type[0] != 1 ||
            !reader.Vector(3, &payload) || payload.empty() || !reader.input.empty())
          return false;
      } else if (kind == 18 || kind == 52) {
        // RFC9162 section 6.5 permits empty extension_data, not an encoded
        // empty TransItemList. Each TransItem contains a two-byte type.
        if (kind == 52 && value.empty()) continue;
        if (!reader.Vector(2, &payload) || payload.empty() || !reader.input.empty())
          return false;
        reader.input = payload;
        while (!reader.input.empty()) {
          ByteSpan sct;
          if (!reader.Vector(2, &sct) || sct.size() < (kind == 52 ? 2u : 1u))
            return false;
        }
      }
    }
  }
  return true;
}
struct Erase {
  Bytes value;
  ~Erase() { OPENSSL_cleanse(value.data(), value.size()); }
};
Bytes Proof(uint16_t suite, ByteSpan finished, const Secret& private_key,
            const Secret& peer, ByteSpan transcript, bool server, const NativeProvider* provider) {
  Erase shared{Bytes(32)};
  if (!X25519(shared.value.data(), private_key.data(), peer.data()))
    return {};
  auto hash = SuiteHash(suite, transcript, provider);
  Erase root{SuiteMac(suite, finished, shared.value, provider)};
  Erase key{SuiteLabel(suite, root.value, server ? "server ea mac" : "client ea mac", hash,
                      SuiteHashLength(suite), provider)};
  Bytes context(64, 0x20);
  Append(&context, StringBytes(server ? "TLS 2.0, server exported authenticator"
                                     : "TLS 2.0, client exported authenticator"));
  context.push_back(0);
  Append(&context, hash);
  return SuiteMac(suite, key.value, context, provider);
}
}  // namespace

Client::PendingAuthenticator::~PendingAuthenticator() {
  OPENSSL_cleanse(private_key.data(), private_key.size());
}

bool Client::AuthenticatorReady() const {
  return established() && !closed() && !close_sent_ && !authenticators_disabled_;
}

bool Client::ClaimAuthenticatorContext(const Bytes& context) {
  return context.size() <= 255 && used_authenticator_contexts_.size() < options_.authenticator_context_budget &&
      used_authenticator_contexts_.insert(context).second;
}

void Client::DisableAuthenticators() {
  authenticators_disabled_ = true;
  pending_authenticators_.clear();
  OPENSSL_cleanse(authenticator_a_.data(), authenticator_a_.size());
}

bool Client::ChannelBinding(Bytes* output) const {
  return Export("EXPORTER-Channel-Binding", {}, 32, output);
}

bool Client::AuthenticatorKeys(bool server, Bytes* context, Bytes* finished) const {
  return AuthenticatorReady() && Export(server ? "EXPORTER-server authenticator handshake context"
                                              : "EXPORTER-client authenticator handshake context",
      {}, SuiteHashLength(suite_), context) &&
      Export(server ? "EXPORTER-server authenticator finished key"
                    : "EXPORTER-client authenticator finished key", {}, SuiteHashLength(suite_), finished);
}

bool Client::RequestServerAuthenticator(ByteSpan context,
    const Extensions& extra_extensions, Bytes* request) {
  if (!AuthenticatorReady() || context.size() > 255)
    return false;
  Bytes algorithms, encoded_algorithms;
  for (uint16_t value : options_.certificate_signature_algorithms) {
    algorithms.push_back(static_cast<uint8_t>(value >> 8));
    algorithms.push_back(static_cast<uint8_t>(value));
  }
  Vector(&encoded_algorithms, algorithms, 2);
  Extensions extensions{{50, std::move(encoded_algorithms)}};
  PendingAuthenticator pending;
  Secret share;
  X25519_keypair(share.data(), pending.private_key.data());
  extensions.emplace(0xff02, Bytes(share.begin(), share.end()));
  for (const auto& [kind, value] : extra_extensions) {
    if (kind == 0xff02 || (kind != 50 && extensions.count(kind)))
      return false;
    extensions[kind] = value;
  }
  Bytes encoded, body;
  if (!EncodeExtensions(extensions, &encoded))
    return false;
  Vector(&body, context, 1);
  Vector(&body, encoded, 2);
  pending.request = Frame(17, body);
  Request parsed;
  if (pending.request.size() > options_.authenticator_message_budget ||
      !ParseRequest(pending.request, &parsed) || !ClaimAuthenticatorContext(parsed.context))
    return false;
  *request = pending.request;
  pending_authenticators_.emplace(parsed.context, std::move(pending));
  return true;
}

bool Client::CancelAuthenticator(ByteSpan request) {
  if (request.size() > options_.authenticator_message_budget)
    return false;
  Request parsed;
  if (!ParseRequest(request, &parsed))
    return false;
  auto found = pending_authenticators_.find(parsed.context);
  if (found == pending_authenticators_.end() || !Equal(found->second.request, request))
    return false;
  pending_authenticators_.erase(found);
  return true;
}

bool Client::AuthenticateClient(ByteSpan request, const ClientCredential* credential,
                                 Bytes* authenticator) {
  Request parsed;
  if (!AuthenticatorReady() || request.size() > options_.authenticator_message_budget ||
      !ParseRequest(request, &parsed) || parsed.server)
    return false;
  // Reuse the ordinary credential selector for CA/OID/path/grant constraints,
  // but not its handshake transcript or client identity state. An application
  // request is not a record-level CertificateRequest and may use an empty ctx.
  if (credential) {
    Client selection(hostname_, {}, false, options_);
    Bytes encoded, body{0};
    if (credential->certificate_type != 0 || !selection.SetClientCredential(*credential) ||
        !EncodeExtensions(parsed.extensions, &encoded))
      return false;
    Vector(&body, encoded, 2);
    if (!selection.AcceptCertificateRequest(Frame(13, body), false))
      return false;
    if (!selection.ClientCredentialMatchesRequest())
      credential = nullptr;
  }
  if (!ClaimAuthenticatorContext(parsed.context))
    return false;
  AuthenticatorIdentity identity;
  identity.context = parsed.context;
  if (credential) {
    identity.certificates = credential->certificates;
    identity.extensions.resize(identity.certificates.size());
    if (!credential->delegation.empty())
      identity.extensions.front().emplace(34, credential->delegation);
    if (parsed.extensions.count(5))
      for (size_t index = 0; index < credential->ocsp_responses.size(); ++index)
        if (!credential->ocsp_responses[index].empty())
          identity.extensions[index].emplace(5, Frame(1, credential->ocsp_responses[index]));
  }
  Bytes certificate, transcript;
  Erase finished;
  if (!CertificateOffers(identity, parsed.extensions) || !Certificate(identity, &certificate) ||
      !AuthenticatorKeys(false, &transcript, &finished.value))
    return false;
  Append(&transcript, request);
  Append(&transcript, certificate);
  Bytes result;
  if (credential) {
    auto proof = Proof(suite_, finished.value, credential->private_key, parsed.share, transcript, false, options_.native_provider.get());
    if (proof.size() != SuiteHashLength(suite_))
      return false;
    Bytes body{0xfe, 1};
    Vector(&body, proof, 2);
    auto verify = Frame(15, body);
    result = certificate;
    Append(&result, verify);
    Append(&transcript, verify);
  }
  Append(&result, Frame(20, Mac(finished.value, Hash(transcript))));
  if (result.size() > options_.authenticator_message_budget)
    return false;
  *authenticator = std::move(result);
  return true;
}

bool Client::ValidateServerAuthenticator(ByteSpan authenticator,
    const AuthenticatorValidator& validator, bool* authenticated, ByteSpan exact_request) {
  *authenticated = false;
  if (!AuthenticatorReady() || authenticator.empty() ||
      authenticator.size() > options_.authenticator_message_budget ||
      exact_request.size() > options_.authenticator_message_budget)
    return false;
  const bool refusal = authenticator[0] == 20;
  Reader reader{authenticator};
  AuthenticatorIdentity identity;
  ByteSpan certificate, body;
  Request parsed;
  if (refusal) {
    if (exact_request.empty() || !ParseRequest(exact_request, &parsed) || !parsed.server)
      return false;
    identity.context = parsed.context;
  } else if (!reader.Frame(11, &certificate, &body) || !ParseCertificate(body, &identity) ||
             identity.certificates.empty()) {
    return false;
  }
  PendingAuthenticator pending;
  Extensions offers;
  auto found = pending_authenticators_.find(identity.context);
  if (found != pending_authenticators_.end()) {
    if ((!exact_request.empty() && !Equal(exact_request, found->second.request)) ||
        !ParseRequest(found->second.request, &parsed))
      return false;
    pending = std::move(found->second);
    pending_authenticators_.erase(found);  // Consumption precedes all policy/proof checks.
    offers = parsed.extensions;
  } else {
    if (refusal || !exact_request.empty() || !options_.spontaneous_authenticators ||
        authenticator_a_ == Secret{} || !ClaimAuthenticatorContext(identity.context))
      return false;
    pending.private_key = authenticator_a_;
    offers = authenticator_capabilities_;
    if (!Offers(offers))
      return false;
  }
  Bytes empty_certificate, transcript;
  Erase finished;
  if (!AuthenticatorKeys(true, &transcript, &finished.value))
    return false;
  if (refusal) {
    if (!Certificate(identity, &empty_certificate))
      return false;
    certificate = empty_certificate;
  }
  Append(&transcript, pending.request);
  Append(&transcript, certificate);
  if (!refusal) {
    ByteSpan verify, proof;
    if (!validator || !CertificateOffers(identity, offers) ||
        !reader.Frame(15, &verify, &body) || body.size() < 4 || body[0] != 0xfe || body[1] != 0)
      return false;
    Reader mac_reader{body.subspan(2u)};
    if (!mac_reader.Vector(2, &proof) || !mac_reader.input.empty() || proof.size() != SuiteHashLength(suite_))
      return false;
    Secret authorized;
    if (!validator(identity, offers, &authorized) || !AuthenticatorReady())
      return false;
    auto expected = Proof(suite_, finished.value, pending.private_key, authorized, transcript, true, options_.native_provider.get());
    if (!Equal(proof, expected))
      return false;
    Append(&transcript, verify);
  }
  ByteSpan frame, value;
  if (!reader.Frame(20, &frame, &value) || !reader.input.empty() ||
      !Equal(value, Mac(finished.value, Hash(transcript))))
    return false;
  *authenticated = !refusal;
  return true;
}

}  // namespace net::httpps
