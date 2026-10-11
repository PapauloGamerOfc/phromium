// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/httpps/dnssec.h"

#include <algorithm>
#include <ctime>
#include <limits>
#include <set>
#if !defined(PHROMIUM_HTTPPS_STANDALONE)
#include "base/memory/raw_ptr_exclusion.h"
#endif
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/sha.h"
#include "third_party/boringssl/src/include/openssl/x509.h"
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace net::httpps {
namespace {
using Name = std::vector<std::string>;
using Handle = std::unique_ptr<void, void(*)(void*)>;
constexpr size_t kMaxRecords = 512;
constexpr size_t kMaxSignatures = 64;
constexpr size_t kMaxAliases = 16;
constexpr size_t kMaxNSEC3Iterations = 150;
constexpr size_t kMaxValidationWork = 4096;
constexpr size_t kMaxNSEC3HashWork = 262144;
void Error(std::string* error, const char* text) { if (error) *error = text; }
uint16_t U16(ByteSpan data, size_t i) {
  return static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
}
uint32_t U32(ByteSpan data, size_t i) {
  return (static_cast<uint32_t>(U16(data, i)) << 16) | U16(data, i + 2);
}
void Put16(DNSBytes& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>(v >> 8)); out.push_back(static_cast<uint8_t>(v));
}
void Put32(DNSBytes& out, uint32_t v) {
  Put16(out, static_cast<uint16_t>(v >> 16)); Put16(out, static_cast<uint16_t>(v));
}
bool ReadName(ByteSpan in, size_t* offset, Name* name) {
  const size_t start = *offset;
  name->clear();
  while (*offset < in.size() && *offset - start < 255) {
    const auto length = in[(*offset)++];
    if (!length) return *offset - start <= 255;
    if (length > 63 || length > in.size() - *offset) return false;
    std::string label;
    for (size_t i = 0; i < length; ++i) {
      auto v = in[(*offset)++];
      label.push_back(static_cast<char>(v >= 'A' && v <= 'Z' ? v + 32 : v));
    }
    name->push_back(std::move(label));
  }
  return false;
}
void PutName(DNSBytes& out, const Name& name) {
  for (const auto& label : name) {
    out.push_back(static_cast<uint8_t>(label.size()));
    out.insert(out.end(), label.begin(), label.end());
  }
  out.push_back(0);
}
std::optional<Name> ServiceName(std::string_view hostname, uint16_t port) {
  if (!port || hostname.empty() || hostname.size() > 253 || hostname.back() == '.') return {};
  Name result{"_" + std::to_string(port), "_tcp"};
  while (!hostname.empty()) {
    const size_t dot = hostname.find('.');
    const auto label = hostname.substr(0, dot);
    if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return {};
    std::string canonical;
    for (char c : label) {
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-')) return {};
      canonical.push_back(c >= 'A' && c <= 'Z' ? c + 32 : c);
    }
    result.push_back(std::move(canonical));
    if (dot == std::string_view::npos) break;
    hostname.remove_prefix(dot + 1);
  }
  DNSBytes encoded; PutName(encoded, result);
  if (encoded.size() > 255) return {};
  return result;
}
bool StrictSubdomain(const Name& name, const Name& parent) {
  return name.size() > parent.size() &&
         std::equal(parent.rbegin(), parent.rend(), name.rbegin());
}
struct RR {
  Name name;
  uint16_t type = 0;
  uint16_t covered = 0;
  uint32_t ttl = 0;
  DNSBytes wire;
  DNSBytes data;
  Name target;
};
bool ParseRecords(ByteSpan wire, std::vector<RR>* out, bool anchors = false) {
  if (wire.empty() || wire.size() > 65535) return false;
  size_t at = 0, signatures = 0;
  while (at < wire.size()) {
    const size_t start = at;
    RR rr;
    if (out->size() >= kMaxRecords || !ReadName(wire, &at, &rr.name) || wire.size() - at < 10) return false;
    rr.type = U16(wire, at); rr.ttl = U32(wire, at + 4);
    const size_t length = U16(wire, at + 8);
    if (U16(wire, at + 2) != 1 || (anchors && rr.type != 43 && rr.type != 48)) return false;
    at += 10;
    if (length > wire.size() - at) return false;
    rr.data.assign(wire.begin() + at, wire.begin() + at + length);
    at += length; rr.wire.assign(wire.begin() + start, wire.begin() + at);
    size_t p = 0;
    if (rr.type == 5 || rr.type == 39 || rr.type == 2) {
      if (!ReadName(rr.data, &p, &rr.target) || p != rr.data.size()) return false;
    } else if (rr.type == 46) {
      if (++signatures > kMaxSignatures || rr.data.size() < 20) return false;
      rr.covered = U16(rr.data, 0); p = 18;
      if (!ReadName(rr.data, &p, &rr.target) || p == rr.data.size()) return false;
    } else if (rr.type == 47) {
      if (!ReadName(rr.data, &p, &rr.target) || p == rr.data.size()) return false;
    } else if (rr.type == 50) {
      if (rr.data.size() < 6 || U16(rr.data, 2) > kMaxNSEC3Iterations) return false;
    } else if (rr.type == 6) {
      Name ignored;
      if (!ReadName(rr.data, &p, &ignored) || !ReadName(rr.data, &p, &ignored) || rr.data.size() - p != 20) return false;
    } else if (rr.type != 43 && rr.type != 48 && rr.type != 52) {
      return false;
    }
    if (rr.type == 52 && rr.data.size() < 4) return false;
    out->push_back(std::move(rr));
  }
  return !out->empty();
}
bool AnswerType(uint16_t type) { return type == 5 || type == 39 || type == 52; }
bool AuthorityType(uint16_t type) { return type == 47 || type == 50 || type == 6 || type == 2; }
bool WorkBudget(const std::vector<RR>& records, const std::vector<RR>& anchors,
                const Name& question, const std::vector<RR>& synthesized) {
  // Conservative upper bound before entering the synchronous provider. Limits
  // prevent colliding-key/signature and DS digest cross products from scaling
  // with all 64 KiB of peer-controlled input (KeyTrap-style work amplification).
  size_t keys = 0, signatures = 0, ds = 0;
  std::set<std::pair<Name, uint16_t>> rrsets;
  auto count = [&](const RR& rr) {
    if (rr.type == 48) {
      ++keys;
      if (rr.data.size() < 5 || rr.data.size() > 2048) return false;
      const auto algorithm = rr.data[3];
      if (algorithm == 1 || algorithm == 5 || algorithm == 7 || algorithm == 8 || algorithm == 10) {
        size_t offset = 5, exponent = rr.data[4];
        if (!exponent) {
          if (rr.data.size() < 7) return false;
          exponent = U16(rr.data, 5); offset = 7;
        }
        if (!exponent || exponent > 4 || exponent >= rr.data.size() - offset ||
            rr.data.size() - offset - exponent > 1024) return false;
      }
    } else if (rr.type == 46) ++signatures;
    else if (rr.type == 43) ++ds;
    if (rr.type != 46) rrsets.emplace(rr.name, rr.type);
    return true;
  };
  for (const auto& rr : records) if (!count(rr)) return false;
  for (const auto& rr : anchors) if (!count(rr)) return false;
  // Iteration limits alone do not bound NSEC3 work across many names/salts.
  // Charge each record (without deduplication), every possible suffix, and
  // exact/next-closer/wildcard lookups. Six SHA-1 compression blocks cover the
  // maximum 255-byte wire name + 255-byte salt, including SHA-1 padding.
  size_t names = question.size() + 1, rounds = 0;
  for (const auto& rr : records) {
    names += rr.name.size() + rr.target.size() + 2;
    if (rr.type == 50) rounds += static_cast<size_t>(U16(rr.data, 2)) + 1;
  }
  for (const auto& rr : synthesized)
    names += rr.name.size() + rr.target.size() + 2;
  // Divide rather than multiply so the bound remains safe on 32-bit builds.
  if (rounds && names > kMaxNSEC3HashWork / 18 / rounds) return false;
  return keys <= kMaxRecords && signatures &&
      keys * (signatures * rrsets.size() + ds) <= kMaxValidationWork;
}
std::optional<Name> Resolve(const Name& question, const std::vector<RR>& records,
                            std::vector<RR>* synthesized) {
  Name owner = question;
  std::set<Name> seen;
  for (size_t hop = 0; hop <= kMaxAliases; ++hop) {
    if (!seen.insert(owner).second) return {};
    const RR* alias = nullptr;
    bool tlsa = false;
    for (const auto& rr : records) {
      if (rr.name == owner && rr.type == 52) tlsa = true;
      if (rr.name == owner && rr.type == 5) {
        if (alias && alias->target != rr.target) return {};
        alias = &rr;
      }
    }
    if (tlsa) return alias ? std::optional<Name>{} : owner;
    if (alias) { owner = alias->target; continue; }
    for (const auto& rr : records) {
      if (rr.type != 39 || !StrictSubdomain(owner, rr.name)) continue;
      if (!alias || rr.name.size() > alias->name.size()) alias = &rr;
      else if (rr.name == alias->name && rr.target != alias->target) return {};
    }
    if (!alias) return owner;
    Name target(owner.begin(), owner.end() - alias->name.size());
    target.insert(target.end(), alias->target.begin(), alias->target.end());
    RR generated; generated.name = owner; generated.target = target;
    generated.type = 5; generated.ttl = alias->ttl; PutName(generated.data, target);
    if (generated.data.size() > 255) return {};
    PutName(generated.wire, owner); Put16(generated.wire, 5); Put16(generated.wire, 1);
    Put32(generated.wire, alias->ttl); Put16(generated.wire, static_cast<uint16_t>(generated.data.size()));
    generated.wire.insert(generated.wire.end(), generated.data.begin(), generated.data.end());
    synthesized->push_back(std::move(generated)); owner = std::move(target);
  }
  return {};
}
DNSBytes Digest(ByteSpan bytes, bool sha512 = false) {
  DNSBytes result(sha512 ? 64 : 32);
  if (sha512) SHA512(bytes.data(), bytes.size(), result.data());
  else SHA256(bytes.data(), bytes.size(), result.data());
  return result;
}
bool Matches(const TLSAAssociation& association, const DNSBytes& der, bool raw) {
  DNSBytes value = der;
  if (association.selector == 1 && !raw) {
    const uint8_t* cursor = der.data();
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())));
    if (!cert || cursor != ByteSpan(der).subspan(der.size()).data()) return false;
    bssl::UniquePtr<EVP_PKEY> key(X509_get_pubkey(cert.get()));
    if (!key) return false;
    const int length = i2d_PUBKEY(key.get(), nullptr);
    if (length <= 0) return false;
    value.resize(static_cast<size_t>(length)); auto* p = value.data();
    if (i2d_PUBKEY(key.get(), &p) != length) return false;
  } else if (association.selector != (raw ? 1 : 0)) return false;
  if (association.matching == 1 || association.matching == 2) value = Digest(value, association.matching == 2);
  else if (association.matching != 0) return false;
  return value.size() == association.association.size() &&
         CRYPTO_memcmp(value.data(), association.association.data(), value.size()) == 0;
}
}  // namespace

struct DNSSECProvider::Impl {
#if !defined(PHROMIUM_HTTPPS_STANDALONE)
  // An OS loader handle, not a pointer to PartitionAlloc-managed memory.
  RAW_PTR_EXCLUSION
#endif
  void* module = nullptr;
  void* (*getdns_list_create)() = nullptr;
  void (*getdns_list_destroy)(void*) = nullptr;
  void (*getdns_dict_destroy)(void*) = nullptr;
  int (*getdns_list_set_dict)(void*, size_t, const void*) = nullptr;
  int (*getdns_wire2rr_dict_scan)(const uint8_t**, size_t*, void**) = nullptr;
  int (*getdns_wire2msg_dict)(const uint8_t*, size_t, void**) = nullptr;
  int (*getdns_validate_dnssec2)(const void*, const void*, const void*, time_t, uint32_t) = nullptr;
  template<class T> bool Bind(T* function, const char* name) {
#if defined(_WIN32)
    *function = reinterpret_cast<T>(GetProcAddress(static_cast<HMODULE>(module), name));
#else
    *function = reinterpret_cast<T>(dlsym(module, name));
#endif
    return *function != nullptr;
  }
  bool BindAll() {
#define LOAD(name) if (!Bind(&name, #name)) return false
    LOAD(getdns_list_create); LOAD(getdns_list_destroy); LOAD(getdns_dict_destroy);
    LOAD(getdns_list_set_dict); LOAD(getdns_wire2rr_dict_scan); LOAD(getdns_wire2msg_dict);
    LOAD(getdns_validate_dnssec2);
#undef LOAD
    return true;
  }
  ~Impl() {
    if (module) {
#if defined(_WIN32)
      FreeLibrary(static_cast<HMODULE>(module));
#else
      dlclose(module);
#endif
    }
  }
  Handle List(const std::vector<RR>& records) const {
    Handle result(getdns_list_create(), getdns_list_destroy);
    if (!result) return result;
    size_t i = 0;
    for (const auto& rr : records) {
      const uint8_t* cursor = rr.wire.data(); size_t length = rr.wire.size(); void* raw = nullptr;
      const auto status = getdns_wire2rr_dict_scan(&cursor, &length, &raw);
      Handle dict(raw, getdns_dict_destroy);
      if (status != 0 || length || !dict || getdns_list_set_dict(result.get(), i++, dict.get()) != 0) {
        result.reset(); break;
      }
    }
    return result;
  }
  bool ValidateMessage(ByteSpan message, const void* support, const void* anchors, int64_t now) const {
    void* raw = nullptr;
    const auto status = getdns_wire2msg_dict(message.data(), message.size(), &raw);
    Handle dict(raw, getdns_dict_destroy), list(getdns_list_create(), getdns_list_destroy);
    return status == 0 && dict && list && getdns_list_set_dict(list.get(), 0, dict.get()) == 0 &&
           getdns_validate_dnssec2(list.get(), support, anchors, static_cast<time_t>(now), 0) == 400;
  }
};
DNSSECProvider::DNSSECProvider() : impl_(std::make_unique<Impl>()) {}
DNSSECProvider::~DNSSECProvider() = default;
std::shared_ptr<DNSSECProvider> DNSSECProvider::Load(std::string_view absolute_path) {
  if (absolute_path.empty() || absolute_path.find('\0') != std::string_view::npos) return {};
  auto result = std::shared_ptr<DNSSECProvider>(new DNSSECProvider());
#if defined(_WIN32)
  if (absolute_path.size() > 32767 || !(absolute_path.starts_with("\\\\") ||
      (absolute_path.size() >= 3 && absolute_path[1] == ':' &&
       (absolute_path[2] == '\\' || absolute_path[2] == '/')))) return {};
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      absolute_path.data(), static_cast<int>(absolute_path.size()), nullptr, 0);
  if (length <= 0) return {};
  std::wstring path(length, L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, absolute_path.data(),
      static_cast<int>(absolute_path.size()), path.data(), length) != length) return {};
  result->impl_->module = LoadLibraryExW(path.c_str(), nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
#else
  if (absolute_path.front() != '/') return {};
  int flags = RTLD_LOCAL | RTLD_NOW;
#if defined(RTLD_DEEPBIND)
  flags |= RTLD_DEEPBIND;
#endif
  result->impl_->module = dlopen(std::string(absolute_path).c_str(), flags);
#endif
  if (!result->impl_->module || !result->impl_->BindAll()) return {};
  return result;
}
std::optional<DNSSECService> DNSSECProvider::Validate(
    ByteSpan chain, ByteSpan anchors, std::string_view hostname,
    uint16_t port, int64_t now, std::string* error) const {
  auto fail = [&](const char* reason) -> std::optional<DNSSECService> { Error(error, reason); return {}; };
  std::vector<RR> records, trusted, synthesized;
  const auto question = ServiceName(hostname, port);
  if (now < 0 || now > std::numeric_limits<time_t>::max() - 0x7fffffff || !question ||
      !ParseRecords(chain, &records) || !ParseRecords(anchors, &trusted, true))
    return fail("invalid DNSSEC inputs or resource limit");
  const auto owner = Resolve(*question, records, &synthesized);
  if (!owner) return fail("invalid DNSSEC service alias chain");
  if (!WorkBudget(records, trusted, *question, synthesized))
    return fail("invalid DNSSEC inputs or resource limit");
  auto support = impl_->List(records), trust = impl_->List(trusted);
  if (!support || !trust) return fail("DNSSEC provider could not parse records");
  DNSBytes answers, authority;
  uint16_t answer_count = 0, authority_count = 0;
  auto append = [&](const RR& rr) {
    const uint16_t type = rr.type == 46 ? rr.covered : rr.type;
    if (AnswerType(type)) { ++answer_count; answers.insert(answers.end(), rr.wire.begin(), rr.wire.end()); }
    else if (AuthorityType(type)) { ++authority_count; authority.insert(authority.end(), rr.wire.begin(), rr.wire.end()); }
  };
  for (const auto& rr : records) append(rr);
  for (const auto& rr : synthesized) append(rr);
  DNSBytes message{0, 0, 0x84, 0, 0, 1};
  Put16(message, answer_count); Put16(message, authority_count); Put16(message, 0);
  PutName(message, *question); Put16(message, 52); Put16(message, 1);
  message.insert(message.end(), answers.begin(), answers.end());
  message.insert(message.end(), authority.begin(), authority.end());
  if (message.size() > 65535 || !impl_->ValidateMessage(message, support.get(), trust.get(), now)) return fail("DNSSEC question or authentication chain did not validate securely");
  DNSSECService result;
  result.expires_unix_seconds = now + 0x7fffffff;
  for (const auto& rr : records) {
    result.expires_unix_seconds = std::min(result.expires_unix_seconds, now + std::min<uint32_t>(rr.ttl, 0x7fffffff));
    if (rr.type == 46) {
      result.expires_unix_seconds = std::min(result.expires_unix_seconds,
          now + std::min<uint32_t>(U32(rr.data, 4), 0x7fffffff));
      // RFC 1982 wrapping times: only positive signed serial distance is live.
      const uint32_t distance = U32(rr.data, 8) - static_cast<uint32_t>(now);
      if (distance < 0x80000000u) result.expires_unix_seconds = std::min(result.expires_unix_seconds, now + distance);
    }
    if (rr.type == 52 && rr.name == *owner) result.records.push_back({rr.data[0], rr.data[1], rr.data[2], DNSBytes(rr.data.begin() + 3, rr.data.end())});
  }
  result.authenticated_denial = result.records.empty();
  return result;
}
bool DANEPolicy::IsValid() const {
  std::vector<RR> parsed;
  return provider && port && application_policy_context.size() <= 4096 &&
      (!(pkix_validator || dane_path_validator) || !application_policy_context.empty()) &&
      ParseRecords(trust_anchors, &parsed, true);
}
DNSBytes DANEPolicy::Context() const {
  if (!IsValid()) return {};
  DNSBytes context{'D','A','N','E',0}; Put16(context, port);
  context.push_back(allow_authenticated_denial); context.push_back(!!pkix_validator); context.push_back(!!dane_path_validator);
  Put16(context, static_cast<uint16_t>(trust_anchors.size()));
  context.insert(context.end(), trust_anchors.begin(), trust_anchors.end());
  context.insert(context.end(), application_policy_context.begin(), application_policy_context.end());
  return Digest(context);
}
std::optional<DANEAuthorization> DANEPolicy::Verify(
    std::string_view hostname, const std::vector<DNSBytes>& material,
    uint8_t type, ByteSpan evidence, int64_t now, std::string* error) const {
  auto fail = [&](const char* reason) -> std::optional<DANEAuthorization> { Error(error, reason); return {}; };
  if (!IsValid() || material.empty() || material.size() > 64 ||
      (type != 0 && type != 2) || (type == 2 && material.size() != 1) ||
      evidence.size() < 5 || evidence.size() > 65535 || U16(evidence, 2) != evidence.size() - 4)
    return fail("invalid DANE policy, credential or extension envelope");
  for (const auto& der : material) {
    if (der.empty() || der.size() > (1 << 20)) return fail("DANE credential size limit");
    if (type == 0) {
      const uint8_t* cursor = der.data();
      bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())));
      if (!cert || cursor != ByteSpan(der).subspan(der.size()).data()) return fail("malformed DANE certificate");
    } else {
      CBS input; CBS_init(&input, der.data(), der.size());
      bssl::UniquePtr<EVP_PKEY> key(EVP_parse_public_key(&input));
      if (!key || CBS_len(&input)) return fail("malformed DANE public key");
    }
  }
  auto result = provider->Validate(evidence.subspan(4u), trust_anchors, hostname, port, now, error);
  if (!result) return {};
  const uint16_t lifetime = U16(evidence, 0);
  if (result->authenticated_denial) {
    if (!allow_authenticated_denial) return fail("DANE policy requires a positive TLSA authorization");
    return DANEAuthorization{-1, result->expires_unix_seconds, lifetime};
  }
  std::optional<std::vector<DNSBytes>> pkix_path;
  bool checked_pkix = false;
  for (const auto& record : result->records) {
    if (record.usage == 3 && Matches(record, material.front(), type == 2))
      return DANEAuthorization{3, result->expires_unix_seconds, lifetime};
    if (type == 2) continue;
    if ((record.usage == 0 || record.usage == 1) && pkix_validator) {
      if (!checked_pkix) { pkix_path = pkix_validator(material); checked_pkix = true; }
      if (pkix_path && !pkix_path->empty() && pkix_path->front() == material.front()) {
        const size_t start = record.usage == 1 ? 0 : 1;
        const size_t end = record.usage == 1 ? 1 : pkix_path->size();
        for (size_t i = start; i < end; ++i) if (Matches(record, (*pkix_path)[i], false))
          return DANEAuthorization{record.usage, result->expires_unix_seconds, lifetime};
      }
    } else if (record.usage == 2 && dane_path_validator) {
      std::vector<DNSBytes> candidates(material.begin() + 1, material.end());
      if (record.selector == 0 && record.matching == 0) candidates.push_back(record.association);
      for (const auto& candidate : candidates)
        if (Matches(record, candidate, false) && dane_path_validator(material, candidate))
          return DANEAuthorization{2, result->expires_unix_seconds, lifetime};
    }
  }
  return fail("authenticated TLSA records do not authorize this credential");
}
}  // namespace net::httpps
