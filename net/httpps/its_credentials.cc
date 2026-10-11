// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/httpps/its_credentials.h"

#include <algorithm>
#include <iterator>
#include <limits>
#if !defined(PHROMIUM_HTTPPS_STANDALONE)
#include "base/memory/raw_ptr_exclusion.h"
#endif
#include "third_party/boringssl/src/include/openssl/sha.h"
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
constexpr size_t kMaxInput = 262144;
constexpr int64_t kEpochSeconds = 1072915200;
void Put(ITSBytes& out, uint64_t number, size_t width) {
  for (size_t n = width; n; --n) out.push_back(static_cast<uint8_t>(number >> (8 * (n - 1))));
}
void Vector(ITSBytes& out, ByteSpan bytes, size_t width) {
  Put(out, bytes.size(), width);
  out.insert(out.end(), bytes.begin(), bytes.end());
}
void Vector(ITSBytes& out, std::string_view bytes, size_t width) {
  Put(out, bytes.size(), width);
  out.insert(out.end(), bytes.begin(), bytes.end());
}
void ObjectList(ITSBytes& out, const std::vector<ITSBytes>& objects) {
  ITSBytes list;
  for (const auto& object : objects) Vector(list, object, 3);
  Vector(out, list, 3);
}
void HashList(ITSBytes& out, const std::vector<ITSBytes>& hashes) {
  Put(out, hashes.size() * 32, 3);
  for (const auto& hash : hashes) out.insert(out.end(), hash.begin(), hash.end());
}
ITSBytes PolicyBytes(const ITSPolicy& policy, uint64_t now) {
  ITSBytes result{'I', 'T', 'S', '1'};
  Put(result, now, 8); Put(result, policy.inventory_valid_until, 8);
  Put(result, policy.max_grant_lifetime_microseconds, 8);
  result.push_back(policy.role); Put(result, policy.psid, 8);
  Vector(result, policy.application_scope, 2); Vector(result, policy.ssp_coer, 2);
  ObjectList(result, policy.trust_roots);
  HashList(result, policy.authorized_leaves); HashList(result, policy.revoked);
  ObjectList(result, policy.allowed_regions);
  return result;
}
}  // namespace

struct ITSProvider::Impl {
#if !defined(PHROMIUM_HTTPPS_STANDALONE)
  // An OS loader handle, not a pointer to PartitionAlloc-managed memory.
  RAW_PTR_EXCLUSION
#endif
  void* module = nullptr;
  uint32_t (*version)() = nullptr;
  int (*authorize)(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t) = nullptr;
  template<class T> bool Bind(T* function, const char* name) {
#if defined(_WIN32)
    *function = reinterpret_cast<T>(GetProcAddress(static_cast<HMODULE>(module), name));
#else
    *function = reinterpret_cast<T>(dlsym(module, name));
#endif
    return *function != nullptr;
  }
  ~Impl() {
    if (!module) return;
#if defined(_WIN32)
    FreeLibrary(static_cast<HMODULE>(module));
#else
    dlclose(module);
#endif
  }
};
ITSProvider::ITSProvider() : impl_(std::make_unique<Impl>()) {}
ITSProvider::~ITSProvider() = default;
std::shared_ptr<ITSProvider> ITSProvider::Load(std::string_view path) {
  if (path.empty() || path.size() > 32767 || path.find('\0') != std::string_view::npos) return {};
  auto result = std::shared_ptr<ITSProvider>(new ITSProvider());
#if defined(_WIN32)
  if (!(path.starts_with("\\\\") || (path.size() >= 3 && path[1] == ':' &&
      (path[2] == '\\' || path[2] == '/')))) return {};
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      path.data(), static_cast<int>(path.size()), nullptr, 0);
  if (length <= 0) return {};
  std::wstring wide(length, L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(),
      static_cast<int>(path.size()), wide.data(), length) != length) return {};
  result->impl_->module = LoadLibraryExW(wide.c_str(), nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
#else
  if (path.front() != '/') return {};
  result->impl_->module = dlopen(std::string(path).c_str(), RTLD_LOCAL | RTLD_NOW);
#endif
  if (!result->impl_->module || !result->impl_->Bind(&result->impl_->version, "tls20_its_abi_version") ||
      !result->impl_->Bind(&result->impl_->authorize, "tls20_its_authorize") || result->impl_->version() != 1)
    return {};
  result->path_ = path;
  return result;
}
bool ITSPolicy::IsValid() const {
  if (!provider || identity.empty() || identity.size() > 4096 || role > 1 ||
      tai_utc_offset > 100 || !inventory_valid_until || !max_grant_lifetime_microseconds ||
      application_scope.size() > 65535 || ssp_coer.size() > 65535 ||
      trust_roots.empty() || trust_roots.size() > 32 || authorized_leaves.empty() ||
      authorized_leaves.size() > 1024 || revoked.size() > 4096 || allowed_regions.size() > 32) return false;
  size_t budget = 100 + application_scope.size() + ssp_coer.size();
  for (const auto* objects : {&trust_roots, &allowed_regions})
    for (const auto& object : *objects) {
      if (object.empty() || object.size() > 16384) return false;
      budget += 3 + object.size();
    }
  for (const auto* hashes : {&authorized_leaves, &revoked})
    for (const auto& hash : *hashes) {
      if (hash.size() != 32) return false;
      budget += 32;
    }
  return budget <= kMaxInput;
}
ITSBytes ITSPolicy::Context() const {
  if (!IsValid()) return {};
  constexpr char label[] = "TLS20 ITS service policy\0";
  const auto label_bytes = StringBytes(std::string_view(label, sizeof(label) - 1));
  ITSBytes input(label_bytes.begin(), label_bytes.end());
  Vector(input, identity, 3); Vector(input, provider->path(), 3);
  const ITSBytes offset{tai_utc_offset}; Vector(input, offset, 3);
  // Preserve category boundaries: moving an allowed leaf into revoked changes
  // the context even if the same raw fingerprint sequence remains overall.
  const auto policy = PolicyBytes(*this, 0); Vector(input, policy, 3);
  ITSBytes result(32); SHA256(input.data(), input.size(), result.data());
  return result;
}
std::optional<ITSAuthorization> ITSPolicy::Verify(ByteSpan grant,
    uint8_t expected_role, std::string_view expected_identity, int64_t now_ms,
    std::string* error) const {
  auto fail = [&](const char* reason) -> std::optional<ITSAuthorization> {
    if (error) *error = reason;
    return {};
  };
  if (!IsValid() || expected_role != role || expected_identity != identity ||
      grant.empty() || grant.size() > kMaxInput || now_ms < 0 ||
      now_ms > std::numeric_limits<int64_t>::max() / 1000)
    return fail("invalid ITS provider, service, role or input bounds");
  const int64_t adjustment = (kEpochSeconds - tai_utc_offset) * 1000000;
  const int64_t micros = now_ms * 1000;
  if (micros < adjustment) return fail("ITS current time precedes Time64 epoch");
  const auto now = static_cast<uint64_t>(micros - adjustment);
  if (now >= inventory_valid_until) return fail("ITS revocation inventory expired");
  const auto policy = PolicyBytes(*this, now);
  std::array<uint8_t, 72> output{};
  if (provider->impl_->authorize(grant.data(), grant.size(), policy.data(), policy.size(),
      output.data(), output.size()) != 1) return fail("ITS offline credential authorization failed");
  ITSAuthorization result;
  std::copy_n(output.begin(), 32, result.public_key.begin());
  const auto fingerprint = ByteSpan(output).subspan(40u, 32u);
  std::copy(fingerprint.begin(), fingerprint.end(), result.leaf_sha256.begin());
  uint64_t expiry = 0;
  for (size_t i = 32; i < 40; ++i) expiry = (expiry << 8) | output[i];
  if (expiry <= now || expiry > inventory_valid_until) return fail("ITS provider returned invalid lifetime");
  result.expires_unix_milliseconds = static_cast<int64_t>(expiry / 1000) +
      (kEpochSeconds - tai_utc_offset) * 1000;
  return result;
}
}  // namespace net::httpps
