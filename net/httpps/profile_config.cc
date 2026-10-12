// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/httpps/profile_config.h"

#include <algorithm>
#include <limits>
#include <set>

#include "base/base64.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/strings/string_number_conversions.h"
#include "base/values.h"
#include "net/base/schemeful_site.h"
#include "net/httpps/dnssec.h"
#include "net/httpps/its_credentials.h"
#include "net/httpps/native_provider.h"
#include "net/httpps/transparency.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net::httpps {
namespace {
// JSONReader validates the grammar but intentionally accepts duplicate keys.
// After successful parsing, scan the original strings so a repeated policy
// cannot silently overwrite a restriction (including escaped equivalent keys).
bool UniqueObjectKeys(std::string_view json) {
  std::vector<std::set<std::string>> objects;
  for (size_t i = 0; i < json.size(); ++i) {
    if (json[i] == '{') {
      objects.emplace_back();
    } else if (json[i] == '}') {
      if (objects.empty()) {
        return false;
      }
      objects.pop_back();
    } else if (json[i] == '"') {
      const size_t start = i++;
      while (i < json.size() && json[i] != '"') {
        if (json[i] == '\\') {
          ++i;
        }
        ++i;
      }
      if (i >= json.size()) {
        return false;
      }
      size_t next = i + 1;
      while (next < json.size() && (json[next] == ' ' || json[next] == '\t' ||
                                    json[next] == '\r' || json[next] == '\n')) {
        ++next;
      }
      if (next < json.size() && json[next] == ':') {
        auto key = base::JSONReader::Read(json.substr(start, i - start + 1),
                                          base::JSON_PARSE_RFC);
        if (objects.empty() || !key || !key->is_string() ||
            !objects.back().insert(key->GetString()).second) {
          return false;
        }
      }
    }
  }
  return objects.empty();
}

// Consume keys, then reject leftovers: misspelled policy never silently weakens
// an intended restriction. Integer values wider than 31 bits are decimal
// strings.
class Fields {
 public:
  explicit Fields(const base::DictValue& dict) : dict_(dict.Clone()) {}
  bool Done() const { return ok_ && dict_.empty(); }
  bool Has(std::string_view key) const { return dict_.contains(key); }
  std::optional<base::Value> Take(std::string_view key) {
    return dict_.Extract(key);
  }
  bool String(std::string_view key, std::string* out, bool required = false) {
    auto value = Take(key);
    if (!value) {
      return !required;
    }
    if (!value->is_string()) {
      return false;
    }
    *out = value->GetString();
    return !required || !out->empty();
  }
  bool Bool(std::string_view key, bool* out) {
    auto value = Take(key);
    if (!value) {
      return true;
    }
    if (!value->is_bool()) {
      return false;
    }
    *out = value->GetBool();
    return true;
  }
  template <class T>
  bool Number(std::string_view key, T* out, bool required = false) {
    auto value = Take(key);
    if (!value) {
      return !required;
    }
    uint64_t number;
    if (value->is_int() && value->GetInt() >= 0) {
      number = value->GetInt();
    } else if (value->is_string() && !value->GetString().empty() &&
               std::ranges::all_of(
                   value->GetString(),
                   [](char c) { return c >= '0' && c <= '9'; }) &&
               base::StringToUint64(value->GetString(), &number)) {
    } else {
      return false;
    }
    if (number > static_cast<uint64_t>(std::numeric_limits<T>::max())) {
      return false;
    }
    *out = static_cast<T>(number);
    return true;
  }
  template <class T>
  bool Optional(std::string_view key, std::optional<T>* out) {
    if (!Has(key)) {
      return true;
    }
    T value{};
    if (!Number(key, &value)) {
      return false;
    }
    *out = value;
    return true;
  }
  bool Binary(std::string_view key, Bytes* out, bool required = false) {
    if (!Has(key)) {
      return !required;
    }
    std::string encoded, decoded;
    if (!String(key, &encoded) || !base::Base64Decode(encoded, &decoded) ||
        base::Base64Encode(decoded) != encoded ||
        decoded.size() > 1024 * 1024 || (required && decoded.empty())) {
      return false;
    }
    out->assign(decoded.begin(), decoded.end());
    return true;
  }
  bool Binaries(std::string_view key,
                std::vector<Bytes>* out,
                bool required = false) {
    auto list = Take(key);
    if (!list) {
      return !required;
    }
    if (!list->is_list() || list->GetList().size() > 128) {
      return false;
    }
    out->clear();
    for (const auto& value : list->GetList()) {
      if (!value.is_string()) {
        return false;
      }
      Fields item(base::DictValue().Set("value", value.Clone()));
      Bytes bytes;
      if (!item.Binary("value", &bytes, true)) {
        return false;
      }
      out->push_back(std::move(bytes));
    }
    return !required || !out->empty();
  }
  bool Strings(std::string_view key,
               std::vector<std::string>* out,
               bool required = false) {
    std::vector<Bytes> decoded;
    bool present = Has(key);
    if (!Binaries(key, &decoded, required)) {
      return false;
    }
    if (present) {
      out->clear();
      for (const auto& b : decoded) {
        out->emplace_back(b.begin(), b.end());
      }
    }
    return true;
  }
  template <class T>
  bool Numbers(std::string_view key, std::vector<T>* out) {
    auto list = Take(key);
    if (!list) {
      return true;
    }
    if (!list->is_list() || list->GetList().empty() ||
        list->GetList().size() > 256) {
      return false;
    }
    out->clear();
    std::set<T> seen;
    for (const auto& value : list->GetList()) {
      Fields item(base::DictValue().Set("value", value.Clone()));
      T number{};
      if (!item.Number("value", &number) || !seen.insert(number).second) {
        return false;
      }
      out->push_back(number);
    }
    return true;
  }

 private:
  base::DictValue dict_;
  bool ok_ = true;
};

bool Absolute(const std::string& path) {
  return !path.empty() && path.find('\0') == std::string::npos &&
         base::FilePath::FromUTF8Unsafe(path).IsAbsolute() &&
         !base::FilePath::FromUTF8Unsafe(path).ReferencesParent();
}

std::shared_ptr<ITSPolicy> ITS(const base::Value& value) {
  if (!value.is_dict()) {
    return {};
  }
  Fields f(value.GetDict());
  auto p = std::make_shared<ITSPolicy>();
  std::string library;
  if (!f.String("library", &library, true) || !Absolute(library) ||
      !f.String("identity", &p->identity, true) ||
      !f.Number("role", &p->role, true) || !f.Number("psid", &p->psid, true) ||
      !f.Binary("application_scope", &p->application_scope, true) ||
      !f.Binary("ssp_coer", &p->ssp_coer, true) ||
      !f.Binaries("trust_roots", &p->trust_roots, true) ||
      !f.Binaries("authorized_leaves", &p->authorized_leaves, true) ||
      !f.Binaries("revoked", &p->revoked) ||
      !f.Binaries("allowed_regions", &p->allowed_regions) ||
      !f.Number("inventory_valid_until", &p->inventory_valid_until, true) ||
      !f.Number("max_grant_lifetime_microseconds",
                &p->max_grant_lifetime_microseconds, true) ||
      !f.Number("tai_utc_offset", &p->tai_utc_offset, true)) {
    return {};
  }
  if (auto pairs = f.Take("geographic_containment")) {
    if (!pairs->is_list() || pairs->GetList().size() > 256) {
      return {};
    }
    for (const auto& pair : pairs->GetList()) {
      if (!pair.is_dict()) {
        return {};
      }
      Fields relation(pair.GetDict());
      Bytes parent, child;
      if (!relation.Binary("parent", &parent, true) ||
          !relation.Binary("child", &child, true) || !relation.Done()) {
        return {};
      }
      p->geographic_containment.emplace_back(std::move(parent),
                                             std::move(child));
    }
  }
  if (!f.Done()) {
    return {};
  }
  p->provider = ITSProvider::Load(library);
  return p->IsValid() ? p : nullptr;
}

bool Configure(const base::DictValue& dict,
               const HostPortPair& server,
               ClientOptions* options,
               std::optional<ClientCredential>* credential,
               std::vector<std::string>* roots) {
  Fields f(dict);
  auto& o = *options;
  if (!f.Strings("trust_anchors", roots)) {
    return false;
  }
  std::string native, gost;
  if (!f.String("native_library", &native) || !f.String("gost_module", &gost)) {
    return false;
  }
  if (!native.empty()) {
    if (!Absolute(native) || (!gost.empty() && !Absolute(gost))) {
      return false;
    }
    o.native_provider = NativeProvider::Load(native, gost);
    if (!o.native_provider) {
      return false;
    }
  } else if (!gost.empty()) {
    return false;
  }
  if (auto value = f.Take("password")) {
    if (!value->is_dict() || !o.native_provider) {
      return false;
    }
    Fields p(value->GetDict());
    auto account = std::make_shared<PasswordCredential>();
    if (!p.String("service", &account->service, true) ||
        account->service != server.host() ||
        !p.String("username", &account->username, true) ||
        !p.String("password", &account->password, true) ||
        !p.String("helper_library", &account->helper_path, true) ||
        !Absolute(account->helper_path) ||
        !p.Binary("protection_spki", &account->protection_spki) || !p.Done()) {
      return false;
    }
    o.password = account;
  }
  if (auto list = f.Take("external_psks")) {
    if (!list->is_list() || list->GetList().empty() ||
        list->GetList().size() > 16) {
      return false;
    }
    for (const auto& value : list->GetList()) {
      if (!value.is_dict()) {
        return false;
      }
      Fields p(value.GetDict());
      ExternalPSK key;
      key.hostname = server.host();
      if (!p.Binary("identity", &key.identity, true) ||
          !p.Binary("secret", &key.secret, true) ||
          !p.String("alpn", &key.alpn) ||
          !p.Number("cipher_suite", &key.cipher_suite) ||
          !p.Bool("combined", &key.combined) ||
          !p.Number("max_early_data", &key.max_early_data)) {
        return false;
      }
      if (p.Has("import_context")) {
        Bytes context;
        uint16_t base_suite = key.cipher_suite;
        if (!p.Binary("import_context", &context) ||
            !p.Number("base_suite", &base_suite)) {
          return false;
        }
        auto imported =
            ImportPSK(key.secret, key.identity, context, key.hostname, key.alpn,
                      base_suite, key.cipher_suite, key.combined);
        if (!imported) {
          return false;
        }
        imported->max_early_data = key.max_early_data;
        key = std::move(*imported);
      }
      if (!p.Done()) {
        return false;
      }
      o.external_psks.push_back(std::move(key));
    }
  }
  if (auto value = f.Take("client_credential")) {
    if (!value->is_dict()) {
      return false;
    }
    Fields p(value->GetDict());
    ClientCredential c;
    Bytes scalar;
    if (!p.Strings("certificates", &c.certificates, true) ||
        !p.Binary("private_key", &scalar, true) || scalar.size() != 32 ||
        !p.Number("certificate_type", &c.certificate_type) ||
        !p.Binary("delegation", &c.delegation)) {
      return false;
    }
    std::copy(scalar.begin(), scalar.end(), c.private_key.begin());
    if (auto its = p.Take("its")) {
      c.its_policy = ITS(*its);
      if (!c.its_policy) {
        return false;
      }
    }
    if (!p.Done()) {
      return false;
    }
    *credential = std::move(c);
  }
  if (auto value = f.Take("its")) {
    o.its_policy = ITS(*value);
    if (!o.its_policy) {
      return false;
    }
  }
  if (auto value = f.Take("ct_v2")) {
    if (!value->is_dict()) {
      return false;
    }
    Fields p(value->GetDict());
    auto policy = std::make_shared<CTv2Policy>();
    if (!p.Number("minimum_logs", &policy->minimum_logs) ||
        !p.Bool("require_inclusion", &policy->require_inclusion) ||
        !p.Bool("require_inclusion_after_mmd",
                &policy->require_inclusion_after_mmd)) {
      return false;
    }
    auto logs = p.Take("logs");
    if (!logs || !logs->is_list() || logs->GetList().size() > 64) {
      return false;
    }
    for (const auto& log_value : logs->GetList()) {
      if (!log_value.is_dict()) {
        return false;
      }
      Fields l(log_value.GetDict());
      CTLog log;
      std::string hash = "sha256";
      if (!l.Binary("id", &log.id, true) ||
          !l.Binary("public_key_spki", &log.public_key_spki, true) ||
          !l.Number("signature_scheme", &log.signature_scheme) ||
          !l.String("hash", &hash) ||
          !l.Number("valid_from_ms", &log.valid_from_ms) ||
          !l.Number("valid_until_ms", &log.valid_until_ms) ||
          !l.Number("maximum_merge_delay_seconds",
                    &log.maximum_merge_delay_seconds)) {
        return false;
      }
      if (hash == "sha256") {
        log.hash = CTHash::kSHA256;
      } else if (hash == "sha384") {
        log.hash = CTHash::kSHA384;
      } else if (hash == "sha512") {
        log.hash = CTHash::kSHA512;
      } else {
        return false;
      }
      if (auto tree = l.Take("trusted_tree_head")) {
        if (!tree->is_dict()) {
          return false;
        }
        Fields t(tree->GetDict());
        CTTreeHead head;
        if (!t.Number("size", &head.size, true) ||
            !t.Number("timestamp_ms", &head.timestamp_ms, true) ||
            !t.Binary("root", &head.root, true) || !t.Done() ||
            !policy->trusted_tree_heads.emplace(log.id, std::move(head))
                 .second) {
          return false;
        }
      }
      if (!l.Done()) {
        return false;
      }
      policy->logs.push_back(std::move(log));
    }
    if (!p.Done() || !policy->IsValid()) {
      return false;
    }
    o.ct_v2_policy = policy;
    o.request_scts = true;
    o.request_ocsp = true;
  }
  if (auto value = f.Take("dane")) {
    if (!value->is_dict() || !o.native_provider) {
      return false;
    }
    Fields p(value->GetDict());
    auto policy = std::make_shared<DANEPolicy>();
    std::string library;
    if (!p.String("library", &library, true) || !Absolute(library) ||
        !p.Binary("trust_anchors", &policy->trust_anchors, true) ||
        !p.Binary("application_policy_context",
                  &policy->application_policy_context, true) ||
        !p.Bool("allow_authenticated_denial",
                &policy->allow_authenticated_denial) ||
        !p.Done()) {
      return false;
    }
    policy->port = server.port();
    policy->provider = DNSSECProvider::Load(library);
    auto native_provider = o.native_provider;
    auto public_roots = *roots;
    auto hostname = server.host();
    policy->pkix_validator = [native_provider, public_roots,
                              hostname](const std::vector<Bytes>& material)
        -> std::optional<std::vector<Bytes>> {
      std::vector<std::string> chain;
      for (const auto& b : material) {
        chain.emplace_back(b.begin(), b.end());
      }
      auto path =
          native_provider->VerifyCertificatePath(chain, public_roots, hostname);
      if (!path || !CertificateTLSFeaturesAllowed(*path)) {
        return {};
      }
      std::vector<Bytes> result;
      for (const auto& b : *path) {
        result.emplace_back(b.begin(), b.end());
      }
      return result;
    };
    policy->dane_verified_path_validator = [native_provider, hostname](
                                      const std::vector<Bytes>& material,
                                      const Bytes& anchor) -> std::optional<std::vector<Bytes>> {
      std::vector<std::string> chain;
      for (const auto& b : material) {
        chain.emplace_back(b.begin(), b.end());
      }
      const auto path = native_provider->VerifyCertificatePath(
          chain, {std::string(anchor.begin(), anchor.end())}, hostname, true,
          true);
      // DANE-TA changes the authorized anchor, not its path constraints. Use
      // the verifier's actual path (including omitted issuers), just as the
      // ordinary browser/private-CA path does, on full and resumed handshakes.
      if (!path || !CertificateTLSFeaturesAllowed(*path)) return {};
      std::vector<Bytes> result;
      for (const auto& der : *path) result.emplace_back(der.begin(), der.end());
      return result;
    };
    if (!policy->IsValid()) {
      return false;
    }
    o.dane_policy = policy;
  }
  const auto bootstrap_binding = [&](const base::Value& value,
                                     BootstrapBinding* binding,
                                     bool require_key) {
    if (!value.is_dict()) {
      return false;
    }
    Fields p(value.GetDict());
    if (!p.Binary("spki", &binding->spki, true) ||
        !p.String("service", &binding->service, true) ||
        binding->service != server.host() ||
        !p.String("scope", &binding->scope, true) ||
        !p.Number("expires_unix_seconds", &binding->expires_unix_seconds)) {
      return false;
    }
    if (require_key || p.Has("private_key")) {
      Bytes scalar;
      if (!p.Binary("private_key", &scalar, true) || scalar.size() != 32)
        return false;
      ClientCredential selected;
      selected.certificate_type = 2;
      selected.certificates.emplace_back(binding->spki.begin(), binding->spki.end());
      std::copy(scalar.begin(), scalar.end(), selected.private_key.begin());
      OPENSSL_cleanse(scalar.data(), scalar.size());
      binding->credential = std::move(selected);
    }
    // Bootstrap metadata never grants unauthenticated website trust.
    return p.Done();
  };
  if (auto value = f.Take("bootstrap")) {
    BootstrapBinding binding;
    if (!bootstrap_binding(*value, &binding, false)) return false;
    o.bootstrap = std::move(binding);
  }
  if (auto values = f.Take("bootstraps")) {
    if (!values->is_list() || values->GetList().empty()) return false;
    for (const auto& value : values->GetList()) {
      BootstrapBinding binding;
      if (!bootstrap_binding(value, &binding, true)) return false;
      o.bootstraps.push_back(std::move(binding));
    }
  }
  if (auto value = f.Take("ticket_request")) {
    if (!value->is_dict()) {
      return false;
    }
    Fields p(value->GetDict());
    TicketRequest request;
    if (!p.Number("new_session_count", &request.new_session_count) ||
        !p.Number("resumption_count", &request.resumption_count) || !p.Done()) {
      return false;
    }
    o.ticket_request = request;
  }
  if (auto value = f.Take("signaling")) {
    if (!value->is_dict()) {
      return false;
    }
    Fields p(value->GetDict());
    SignalingBinding binding;
    if (!p.Binary("local_hash", &binding.local_hash) ||
        !p.Binary("peer_hash", &binding.peer_hash) ||
        !p.Binary("local_session_id", &binding.local_session_id) ||
        !p.Binary("peer_session_id", &binding.peer_session_id) ||
        !p.Bool("required", &binding.required) || !p.Done() ||
        !binding.IsValid()) {
      return false;
    }
    o.signaling = std::move(binding);
  }
  return f.Bool("continuity_pinning", &o.continuity_pinning) &&
         f.Bool("no_alpn_http11", &o.no_alpn_http11) &&
         f.Bool("post_handshake_auth", &o.post_handshake_auth) &&
         f.Bool("spontaneous_authenticators", &o.spontaneous_authenticators) &&
         f.Bool("delegated_credentials", &o.delegated_credentials) &&
         f.Bool("grease", &o.grease) &&
         f.Bool("request_ocsp", &o.request_ocsp) &&
         f.Bool("request_scts", &o.request_scts) &&
         f.Numbers("cipher_suites", &o.cipher_suites) &&
         f.Numbers("groups", &o.groups) &&
         f.Numbers("psk_modes", &o.psk_modes) &&
         f.Numbers("server_certificate_types", &o.server_certificate_types) &&
         f.Numbers("certificate_signature_algorithms",
                   &o.certificate_signature_algorithms) &&
         f.Numbers("grant_signature_algorithms",
                   &o.grant_signature_algorithms) &&
         f.Numbers("certificate_compression", &o.certificate_compression) &&
         f.Binaries("server_raw_public_keys", &o.server_raw_public_keys) &&
         f.Binaries("certificate_authorities", &o.certificate_authorities) &&
         f.Binaries("ocsp_responder_ids", &o.ocsp_responder_ids) &&
         f.Binary("ocsp_request_extensions", &o.ocsp_request_extensions) &&
         f.Optional("record_size_limit", &o.record_size_limit) &&
         f.Optional("max_fragment_length", &o.max_fragment_length) &&
         f.Optional("heartbeat_mode", &o.heartbeat_mode) &&
         f.Number("record_padding_multiple", &o.record_padding_multiple) &&
         f.Number("client_hello_padding", &o.client_hello_padding) &&
         f.Number("authenticator_context_budget",
                  &o.authenticator_context_budget) &&
         f.Number("authenticator_message_budget",
                  &o.authenticator_message_budget) &&
         f.Done();
}

struct Profile {
  HostPortPair server;
  SchemefulSite top_frame_site;
  bool cross_site = false;
  int privacy_mode = 0;
  bool proxied = false;
  base::DictValue options;
};
class Registry {
 public:
  explicit Registry(std::string_view json) {
    if (json.size() > kMaxProfileConfigBytes) {
      return;
    }
    auto root = base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC, 32);
    if (!root || !UniqueObjectKeys(json)) {
      return;
    }
    Fields f(*root);
    int version = 0;
    if (!f.Number("format", &version, true) || version != 1) {
      return;
    }
    auto profiles = f.Take("profiles");
    if (!profiles || !profiles->is_list() || profiles->GetList().size() > 64 ||
        !f.Done()) {
      return;
    }
    std::set<std::tuple<std::string, std::string, bool, int, bool>> scopes;
    for (const auto& entry : profiles->GetList()) {
      if (!entry.is_dict()) {
        return;
      }
      Fields p(entry.GetDict());
      Profile profile;
      std::string origin, site, route;
      if (!p.String("origin", &origin, true) ||
          !p.String("top_frame_site", &site, true) || !p.Has("cross_site") ||
          !p.Bool("cross_site", &profile.cross_site) ||
          !p.Number("privacy_mode", &profile.privacy_mode, true) ||
          profile.privacy_mode > 3 || !p.String("route", &route, true) ||
          (route != "direct" && route != "proxied")) {
        return;
      }
      GURL url(origin), top(site);
      if (!url.is_valid() || !url.SchemeIs("httpps") || url.has_username() ||
          url.has_password() || url.has_query() || url.has_ref() ||
          url.path() != "/" || url::Origin::Create(url).Serialize() != origin ||
          !top.is_valid() || SchemefulSite(top).opaque() ||
          SchemefulSite(top).Serialize() != site) {
        return;
      }
      auto options = p.Take("options");
      if (!options || !options->is_dict() || !p.Done() ||
          !scopes
               .emplace(origin, site, profile.cross_site, profile.privacy_mode,
                        route == "proxied")
               .second) {
        return;
      }
      profile.server = HostPortPair::FromURL(url);
      profile.top_frame_site = SchemefulSite(top);
      profile.proxied = route == "proxied";
      profile.options = std::move(options->GetDict());
      profiles_.push_back(std::move(profile));
    }
    valid_ = true;
  }
  std::optional<std::vector<std::string>> Libraries() const {
    if (!valid_) {
      return std::nullopt;
    }
    std::vector<std::string> result;
    std::set<std::string> seen;
    const auto add = [&](const base::DictValue& dict, const char* key,
                         bool required = false) {
      const auto* value = dict.Find(key);
      if (!value) {
        return !required;
      }
      if (!value->is_string() || !Absolute(value->GetString())) {
        return false;
      }
      if (seen.insert(value->GetString()).second) {
        result.push_back(value->GetString());
      }
      return true;
    };
    const auto nested = [&](const base::DictValue& dict, const char* key,
                            const char* library_key) {
      const auto* value = dict.Find(key);
      return !value ||
             (value->is_dict() && add(value->GetDict(), library_key, true));
    };
    for (const auto& profile : profiles_) {
      const auto& o = profile.options;
      // Dependencies precede their modules. Never recursively discover paths
      // from arbitrary fields, expand environment variables, or load secrets.
      if (!add(o, "native_library") || !add(o, "gost_module") ||
          !nested(o, "password", "helper_library") ||
          !nested(o, "its", "library") || !nested(o, "dane", "library")) {
        return std::nullopt;
      }
      if (const auto* credential = o.Find("client_credential")) {
        if (!credential->is_dict() ||
            !nested(credential->GetDict(), "its", "library")) {
          return std::nullopt;
        }
      }
    }
    return result;
  }
  std::optional<bool> Apply(const HostPortPair& server,
                            const SSLConfig& config,
                            ClientOptions* options,
                            std::optional<ClientCredential>* credential,
                            std::vector<std::string>* roots) {
    if (!config.is_httpps || config.session_usage == SessionUsage::kProxy) {
      return std::nullopt;
    }
    if (!valid_) {
      return false;
    }
    bool known_origin = false;
    for (const auto& profile : profiles_) {
      if (profile.server != server) {
        continue;
      }
      known_origin = true;
      const auto& key = config.network_anonymization_key;
      if (key.IsTransient() || !key.GetTopFrameSite() || key.GetNonce() ||
          key.network_isolation_partition() !=
              NetworkIsolationPartition::kGeneral ||
          *key.GetTopFrameSite() != profile.top_frame_site ||
          key.IsCrossSite() != profile.cross_site ||
          static_cast<int>(config.privacy_mode) != profile.privacy_mode ||
          (!config.proxy_chain.is_direct()) != profile.proxied) {
        continue;
      }
      if (!Configure(profile.options, server, options, credential, roots)) {
        return false;
      }
      // Fetch credentials:'omit' is not permission to disclose an account,
      // even when an administrator supplied a matching local profile.
      return config.privacy_mode != PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS ||
             (!*credential && !options->password &&
              options->external_psks.empty() && !options->bootstrap &&
              options->bootstraps.empty());
    }
    // A scoped identity must not silently fall back to a different auth mode.
    return known_origin ? std::optional<bool>(false) : std::nullopt;
  }

 private:
  bool valid_ = false;
  std::vector<Profile> profiles_;
};
}  // namespace

SSLClientContext::HttppsProfileProvider CreateProfileProvider(
    std::string_view json) {
  return base::BindRepeating(&Registry::Apply,
                             std::make_shared<Registry>(json));
}
std::optional<std::vector<std::string>> CollectProfileLibraries(
    std::string_view json) {
  return Registry(json).Libraries();
}
}  // namespace net::httpps
