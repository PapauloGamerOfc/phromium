// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/native_provider.h"
#include "net/httpps/ffdhe.h"

#include <algorithm>
#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_FOREIGN_HANDLE
#else
#include "base/logging.h"
#include "base/memory/raw_ptr_exclusion.h"
#define HTTPPS_FOREIGN_HANDLE RAW_PTR_EXCLUSION
#endif
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/ec.h"
#include "third_party/boringssl/src/include/openssl/ecdh.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/hkdf.h"
#include "third_party/boringssl/src/include/openssl/x509.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace net::httpps {
namespace {
const char* GroupName(uint16_t group) {
  switch (group) {
    case 30: return "X448";
    case 31: return "brainpoolP256r1";
    case 32: return "brainpoolP384r1";
    case 33: return "brainpoolP512r1";
    case 34: return "TCA";
    case 35: return "TCB";
    case 36: return "TCC";
    case 37: return "TCD";
    case 38: return "A";
    case 39: return "B";
    case 40: return "C";
    case 41: return "SM2";
    default: return nullptr;
  }
}
size_t GroupWidth(uint16_t group) {
  switch (group) {
    case 30: return 56;
    case 31: case 34: case 35: case 36: case 37: case 41: return 32;
    case 32: return 48;
    case 33: case 38: case 39: case 40: return 64;
    default: return 0;
  }
}
using Handle = std::unique_ptr<void, void(*)(void*)>;
thread_local const NativeProvider* certificate_provider = nullptr;
void LoadFailure(const char* stage, unsigned long platform_error = 0) {
#if !defined(PHROMIUM_HTTPPS_STANDALONE)
  // Never include library paths, credentials or OpenSSL's error queue here.
  LOG(ERROR) << "HTTPPS native provider unavailable at " << stage
             << " (platform error " << platform_error << ")";
#else
  (void)stage;
  (void)platform_error;
#endif
}
}  // namespace

struct NativeProvider::Impl {
  // OS/library-owned handles use their own allocator and explicit deleters.
  HTTPPS_FOREIGN_HANDLE void* module = nullptr;
  HTTPPS_FOREIGN_HANDLE void* context = nullptr;
  HTTPPS_FOREIGN_HANDLE void* provider = nullptr;
  HTTPPS_FOREIGN_HANDLE void* gost_provider = nullptr;
#if defined(_WIN32)
  HTTPPS_FOREIGN_HANDLE void* gost_module_handle = nullptr;
  using ProviderInit = int (*)(const void*, const void*, const void**, void**);
  int (*OSSL_PROVIDER_add_builtin)(void*, const char*, ProviderInit) = nullptr;
#endif
  HTTPPS_FOREIGN_HANDLE void* kuznyechik = nullptr;
  HTTPPS_FOREIGN_HANDLE void* magma = nullptr;
  HTTPPS_FOREIGN_HANDLE void* sm4_gcm = nullptr;
  HTTPPS_FOREIGN_HANDLE void* sm4_ccm = nullptr;
  HTTPPS_FOREIGN_HANDLE void* aes256_ccm = nullptr;
  HTTPPS_FOREIGN_HANDLE void* hkdf = nullptr;
  std::set<uint16_t> groups;

  unsigned long (*OpenSSL_version_num)() = nullptr;
  void* (*OSSL_LIB_CTX_new)() = nullptr;
  void (*OSSL_LIB_CTX_free)(void*) = nullptr;
  void (*OPENSSL_thread_stop_ex)(void*) = nullptr;
  void (*OPENSSL_thread_stop)() = nullptr;
  void* (*OSSL_PROVIDER_load)(void*, const char*) = nullptr;
  int (*OSSL_PROVIDER_unload)(void*) = nullptr;
  void (*ERR_clear_error)() = nullptr;
  void* (*EVP_PKEY_CTX_new_from_name)(void*, const char*, const char*) = nullptr;
  void* (*EVP_PKEY_CTX_new_from_pkey)(void*, void*, const char*) = nullptr;
  void (*EVP_PKEY_CTX_free)(void*) = nullptr;
  void (*EVP_PKEY_free)(void*) = nullptr;
  int (*EVP_PKEY_keygen_init)(void*) = nullptr;
  int (*EVP_PKEY_paramgen_init)(void*) = nullptr;
  int (*EVP_PKEY_CTX_set_group_name)(void*, const char*) = nullptr;
  int (*EVP_PKEY_generate)(void*, void**) = nullptr;
  int (*EVP_PKEY_get_octet_string_param)(void*, const char*, void*, size_t, size_t*) = nullptr;
  int (*EVP_PKEY_get_raw_public_key)(void*, void*, size_t*) = nullptr;
  void* (*EVP_PKEY_new_raw_public_key_ex)(void*, const char*, const char*, const void*, size_t) = nullptr;
  int (*EVP_PKEY_set1_encoded_public_key)(void*, const void*, size_t) = nullptr;
  int (*EVP_PKEY_public_check)(void*) = nullptr;
  int (*EVP_PKEY_derive_init)(void*) = nullptr;
  int (*EVP_PKEY_derive_set_peer)(void*, void*) = nullptr;
  int (*EVP_PKEY_derive)(void*, void*, size_t*) = nullptr;
  int (*EVP_Q_digest)(void*, const char*, const char*, const void*, size_t, void*, size_t*) = nullptr;
  void* (*EVP_Q_mac)(void*, const char*, const char*, const char*, const void*, const void*, size_t, const void*, size_t, void*, size_t, size_t*) = nullptr;
  void* (*EVP_KDF_fetch)(void*, const char*, const char*) = nullptr;
  void (*EVP_KDF_free)(void*) = nullptr;
  void* (*EVP_KDF_CTX_new)(void*) = nullptr;
  void (*EVP_KDF_CTX_free)(void*) = nullptr;
  int (*EVP_KDF_derive)(void*, void*, size_t, const void*) = nullptr;
  void* (*OSSL_PARAM_BLD_new)() = nullptr;
  void (*OSSL_PARAM_BLD_free)(void*) = nullptr;
  int (*OSSL_PARAM_BLD_push_utf8_string)(void*, const char*, const char*, size_t) = nullptr;
  int (*OSSL_PARAM_BLD_push_octet_string)(void*, const char*, const void*, size_t) = nullptr;
  void* (*OSSL_PARAM_BLD_to_param)(void*) = nullptr;
  void (*OSSL_PARAM_free)(void*) = nullptr;
  void* (*EVP_CIPHER_fetch)(void*, const char*, const char*) = nullptr;
  void (*EVP_CIPHER_free)(void*) = nullptr;
  void* (*EVP_CIPHER_CTX_new)() = nullptr;
  void (*EVP_CIPHER_CTX_free)(void*) = nullptr;
  int (*EVP_CIPHER_CTX_ctrl)(void*, int, int, void*) = nullptr;
  int (*EVP_EncryptInit_ex2)(void*, void*, const void*, const void*, const void*) = nullptr;
  int (*EVP_DecryptInit_ex2)(void*, void*, const void*, const void*, const void*) = nullptr;
  int (*EVP_EncryptUpdate)(void*, void*, int*, const void*, int) = nullptr;
  int (*EVP_DecryptUpdate)(void*, void*, int*, const void*, int) = nullptr;
  int (*EVP_EncryptFinal_ex)(void*, void*, int*) = nullptr;
  int (*EVP_DecryptFinal_ex)(void*, void*, int*) = nullptr;
  void* (*d2i_PUBKEY_ex)(void**, const uint8_t**, long, void*, const char*) = nullptr;
  int (*EVP_PKEY_is_a)(const void*, const char*) = nullptr;
  void* (*EVP_MD_CTX_new)() = nullptr;
  void (*EVP_MD_CTX_free)(void*) = nullptr;
  int (*EVP_DigestVerifyInit_ex)(void*, void**, const char*, void*, const char*, void*, const void*) = nullptr;
  int (*EVP_DigestVerify)(void*, const void*, size_t, const void*, size_t) = nullptr;
  int (*EVP_DigestVerifyUpdate)(void*, const void*, size_t) = nullptr;
  int (*EVP_DigestVerifyFinal)(void*, const void*, size_t) = nullptr;
  int (*EVP_PKEY_get_utf8_string_param)(const void*, const char*, char*, size_t, size_t*) = nullptr;
  int (*EVP_PKEY_get_bits)(const void*) = nullptr;
  int (*EVP_PKEY_CTX_set_rsa_padding)(void*, int) = nullptr;
  int (*EVP_PKEY_CTX_set_rsa_pss_saltlen)(void*, int) = nullptr;
  int (*EVP_PKEY_CTX_set_rsa_mgf1_md_name)(void*, const char*, const char*) = nullptr;
  int (*EVP_PKEY_CTX_set1_id)(void*, const void*, int) = nullptr;
  void* (*X509_new_ex)(void*, const char*) = nullptr;
  void* (*d2i_X509)(void**, const uint8_t**, long) = nullptr;
  int (*i2d_X509)(const void*, uint8_t**) = nullptr;
  void (*X509_free)(void*) = nullptr;
  int (*X509_get_signature_nid)(const void*) = nullptr;
  int (*OBJ_txt2nid)(const char*) = nullptr;
  void* (*ASN1_OCTET_STRING_new)() = nullptr;
  int (*ASN1_OCTET_STRING_set)(void*, const void*, int) = nullptr;
  void (*ASN1_OCTET_STRING_free)(void*) = nullptr;
  void (*X509_set0_distinguishing_id)(void*, void*) = nullptr;
  void* (*X509_STORE_new)() = nullptr;
  void (*X509_STORE_free)(void*) = nullptr;
  int (*X509_STORE_add_cert)(void*, void*) = nullptr;
  void* (*X509_STORE_CTX_new_ex)(void*, const char*) = nullptr;
  void (*X509_STORE_CTX_free)(void*) = nullptr;
  int (*X509_STORE_CTX_init)(void*, void*, void*, void*) = nullptr;
  int (*X509_STORE_CTX_set_purpose)(void*, int) = nullptr;
  void* (*X509_STORE_CTX_get0_param)(void*) = nullptr;
  void* (*X509_STORE_CTX_get1_chain)(void*) = nullptr;
  int (*X509_verify_cert)(void*) = nullptr;
  void (*X509_STORE_CTX_set_verify_cb)(void*, int(*)(int, void*)) = nullptr;
  int (*X509_STORE_CTX_get_error)(const void*) = nullptr;
  void (*X509_STORE_CTX_set_error)(void*, int) = nullptr;
  int (*X509_STORE_CTX_get_error_depth)(const void*) = nullptr;
  void* (*X509_STORE_CTX_get_current_cert)(const void*) = nullptr;
  void* (*X509_STORE_CTX_get0_chain)(const void*) = nullptr;
  int (*X509_VERIFY_PARAM_set_flags)(void*, unsigned long) = nullptr;
  void (*X509_VERIFY_PARAM_set_hostflags)(void*, unsigned) = nullptr;
  int (*X509_VERIFY_PARAM_set1_host)(void*, const char*, size_t) = nullptr;
  int (*X509_VERIFY_PARAM_set1_ip_asc)(void*, const char*) = nullptr;
  void* (*OPENSSL_sk_new_null)() = nullptr;
  void (*OPENSSL_sk_free)(void*) = nullptr;
  int (*OPENSSL_sk_push)(void*, const void*) = nullptr;
  int (*OPENSSL_sk_num)(const void*) = nullptr;
  void* (*OPENSSL_sk_value)(const void*, int) = nullptr;

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
    LOAD(OPENSSL_thread_stop_ex); LOAD(OPENSSL_thread_stop);
    LOAD(OpenSSL_version_num); LOAD(OSSL_LIB_CTX_new); LOAD(OSSL_LIB_CTX_free);
    LOAD(OSSL_PROVIDER_load); LOAD(OSSL_PROVIDER_unload); LOAD(ERR_clear_error);
#if defined(_WIN32)
    LOAD(OSSL_PROVIDER_add_builtin);
#endif
    LOAD(EVP_PKEY_CTX_new_from_name); LOAD(EVP_PKEY_CTX_new_from_pkey);
    LOAD(EVP_PKEY_CTX_free); LOAD(EVP_PKEY_free); LOAD(EVP_PKEY_keygen_init);
    LOAD(EVP_PKEY_paramgen_init); LOAD(EVP_PKEY_CTX_set_group_name); LOAD(EVP_PKEY_generate);
    LOAD(EVP_PKEY_get_octet_string_param); LOAD(EVP_PKEY_get_raw_public_key);
    LOAD(EVP_PKEY_new_raw_public_key_ex); LOAD(EVP_PKEY_set1_encoded_public_key);
    LOAD(EVP_PKEY_public_check); LOAD(EVP_PKEY_derive_init);
    LOAD(EVP_PKEY_derive_set_peer); LOAD(EVP_PKEY_derive);
    LOAD(EVP_Q_digest); LOAD(EVP_Q_mac); LOAD(EVP_KDF_fetch); LOAD(EVP_KDF_free);
    LOAD(EVP_KDF_CTX_new); LOAD(EVP_KDF_CTX_free); LOAD(EVP_KDF_derive);
    LOAD(OSSL_PARAM_BLD_new); LOAD(OSSL_PARAM_BLD_free); LOAD(OSSL_PARAM_BLD_push_utf8_string);
    LOAD(OSSL_PARAM_BLD_push_octet_string); LOAD(OSSL_PARAM_BLD_to_param); LOAD(OSSL_PARAM_free);
    LOAD(EVP_CIPHER_fetch); LOAD(EVP_CIPHER_free); LOAD(EVP_CIPHER_CTX_new); LOAD(EVP_CIPHER_CTX_free);
    LOAD(EVP_CIPHER_CTX_ctrl); LOAD(EVP_EncryptInit_ex2); LOAD(EVP_DecryptInit_ex2);
    LOAD(EVP_EncryptUpdate); LOAD(EVP_DecryptUpdate); LOAD(EVP_EncryptFinal_ex); LOAD(EVP_DecryptFinal_ex);
    LOAD(d2i_PUBKEY_ex); LOAD(EVP_PKEY_is_a); LOAD(EVP_MD_CTX_new); LOAD(EVP_MD_CTX_free);
    LOAD(EVP_DigestVerifyInit_ex); LOAD(EVP_DigestVerify); LOAD(EVP_PKEY_CTX_set1_id);
    LOAD(EVP_DigestVerifyUpdate); LOAD(EVP_DigestVerifyFinal); LOAD(EVP_PKEY_get_utf8_string_param);
    LOAD(EVP_PKEY_get_bits); LOAD(EVP_PKEY_CTX_set_rsa_padding); LOAD(EVP_PKEY_CTX_set_rsa_pss_saltlen);
    LOAD(EVP_PKEY_CTX_set_rsa_mgf1_md_name);
    LOAD(X509_new_ex); LOAD(d2i_X509); LOAD(i2d_X509); LOAD(X509_free); LOAD(X509_get_signature_nid); LOAD(OBJ_txt2nid);
    LOAD(ASN1_OCTET_STRING_new); LOAD(ASN1_OCTET_STRING_set); LOAD(ASN1_OCTET_STRING_free); LOAD(X509_set0_distinguishing_id);
    LOAD(X509_STORE_new); LOAD(X509_STORE_free); LOAD(X509_STORE_add_cert);
    LOAD(X509_STORE_CTX_new_ex); LOAD(X509_STORE_CTX_free); LOAD(X509_STORE_CTX_init);
    LOAD(X509_STORE_CTX_set_purpose); LOAD(X509_STORE_CTX_get0_param); LOAD(X509_STORE_CTX_get1_chain); LOAD(X509_verify_cert);
    LOAD(X509_STORE_CTX_set_verify_cb); LOAD(X509_STORE_CTX_get_error); LOAD(X509_STORE_CTX_set_error);
    LOAD(X509_STORE_CTX_get_error_depth); LOAD(X509_STORE_CTX_get_current_cert); LOAD(X509_STORE_CTX_get0_chain);
    LOAD(X509_VERIFY_PARAM_set_flags); LOAD(X509_VERIFY_PARAM_set_hostflags);
    LOAD(X509_VERIFY_PARAM_set1_host); LOAD(X509_VERIFY_PARAM_set1_ip_asc);
    LOAD(OPENSSL_sk_new_null); LOAD(OPENSSL_sk_free); LOAD(OPENSSL_sk_push); LOAD(OPENSSL_sk_num); LOAD(OPENSSL_sk_value);
#undef LOAD
    return true;
  }
  // A shared provider may be initialized, used and finally released on
  // different persistent threads. OpenSSL only cleans the current thread when
  // freeing a libctx. Do not leave any per-thread registrations pointing at a
  // context (or dynamically loaded module) after the outer foreign call ends.
  // Nested verification callbacks may re-enter this provider or another one;
  // never clean an active outer call's context or its library-global TLS.
  struct ThreadScope {
    HTTPPS_FOREIGN_HANDLE Impl* api;
    // Stack-only linked scopes; no ownership or thread-exit destructor.
    HTTPPS_FOREIGN_HANDLE ThreadScope* previous;
    static thread_local ThreadScope* active;
    explicit ThreadScope(Impl& value) : api(&value), previous(active) {
      active = this;
    }
    ~ThreadScope() {
      bool context_active = false, module_active = false;
      for (auto* scope = previous; scope; scope = scope->previous) {
        context_active |= scope->api == api;
        module_active |= scope->api->module == api->module;
      }
      if (!context_active && api->context && api->OPENSSL_thread_stop_ex)
        api->OPENSSL_thread_stop_ex(api->context);
      if (!module_active && api->OPENSSL_thread_stop)
        api->OPENSSL_thread_stop();
      active = previous;
    }
    ThreadScope(const ThreadScope&) = delete;
    ThreadScope& operator=(const ThreadScope&) = delete;
  };
  ~Impl() {
    {
    ThreadScope cleanup(*this);
    if (sm4_gcm) EVP_CIPHER_free(sm4_gcm);
    if (sm4_ccm) EVP_CIPHER_free(sm4_ccm);
    if (aes256_ccm) EVP_CIPHER_free(aes256_ccm);
    if (hkdf) EVP_KDF_free(hkdf);
    if (kuznyechik) EVP_CIPHER_free(kuznyechik);
    if (magma) EVP_CIPHER_free(magma);
    if (gost_provider) OSSL_PROVIDER_unload(gost_provider);
    if (provider) OSSL_PROVIDER_unload(provider);
    if (context) OSSL_LIB_CTX_free(std::exchange(context, nullptr));
    }
#if defined(_WIN32)
    if (gost_module_handle) FreeLibrary(static_cast<HMODULE>(gost_module_handle));
#endif
    if (module) {
#if defined(_WIN32)
      FreeLibrary(static_cast<HMODULE>(module));
#else
      dlclose(module);
#endif
    }
  }
  Handle Generate(uint16_t group, bool parameters) {
    const auto* name = GroupName(group);
    if (!name || (parameters && group == 30))
      return {nullptr, EVP_PKEY_free};
    const bool gost = group >= 34 && group <= 40;
    Handle generation(EVP_PKEY_CTX_new_from_name(context, gost ? (group <= 37 ? "gost2012_256" : "gost2012_512")
        : group == 30 ? "X448" : "EC", gost ? nullptr : "provider=default"), EVP_PKEY_CTX_free);
    void* key = nullptr;
    if (!generation || (parameters ? EVP_PKEY_paramgen_init(generation.get()) : EVP_PKEY_keygen_init(generation.get())) != 1 ||
        (group != 30 && EVP_PKEY_CTX_set_group_name(generation.get(), name) != 1) ||
        EVP_PKEY_generate(generation.get(), &key) != 1) {
      EVP_PKEY_free(key);
      ERR_clear_error();
      return {nullptr, EVP_PKEY_free};
    }
    return {key, EVP_PKEY_free};
  }
};
thread_local NativeProvider::Impl::ThreadScope* NativeProvider::Impl::ThreadScope::active = nullptr;

NativeProvider::NativeProvider() : impl_(std::make_unique<Impl>()) {}
NativeProvider::~NativeProvider() = default;

std::shared_ptr<NativeProvider> NativeProvider::Load(std::string_view absolute_path, std::string_view gost_module) {
  if (absolute_path.empty() || absolute_path.find('\0') != std::string_view::npos)
    return nullptr;
  auto result = std::shared_ptr<NativeProvider>(new NativeProvider());
  auto& api = *result->impl_;
#if defined(_WIN32)
  if (absolute_path.size() > 32767 ||
      !(absolute_path.starts_with("\\\\") || (absolute_path.size() >= 3 &&
        ((absolute_path[0] >= 'A' && absolute_path[0] <= 'Z') ||
         (absolute_path[0] >= 'a' && absolute_path[0] <= 'z')) &&
        absolute_path[1] == ':' && (absolute_path[2] == '\\' || absolute_path[2] == '/'))))
    return nullptr;
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      absolute_path.data(), static_cast<int>(absolute_path.size()), nullptr, 0);
  if (length <= 0)
    return nullptr;
  std::wstring path(length, L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, absolute_path.data(),
       static_cast<int>(absolute_path.size()), path.data(), length) != length)
    return nullptr;
  api.module = LoadLibraryExW(path.c_str(), nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  if (!api.module) LoadFailure("library load", GetLastError());
#else
  if (absolute_path.front() != '/')
    return nullptr;
  const std::string path(absolute_path);
  int flags = RTLD_LOCAL | RTLD_NOW;
#if defined(RTLD_DEEPBIND)
  // Avoid interposition with a host process' independently linked BoringSSL.
  flags |= RTLD_DEEPBIND;
#endif
  api.module = dlopen(path.c_str(), flags);
  if (!api.module) LoadFailure("library load");
#endif
  if (!api.module)
    return nullptr;
  if (!api.BindAll()) {
    LoadFailure("required symbols");
    return nullptr;
  }
  Impl::ThreadScope cleanup(api);
  const auto version = api.OpenSSL_version_num();
  if (version < 0x30500000 || version >= 0x40000000) {
    LoadFailure("compatible version");
    return nullptr;
  }
  api.context = api.OSSL_LIB_CTX_new();
  if (!api.context || !(api.provider = api.OSSL_PROVIDER_load(api.context, "default"))) {
    LoadFailure("private default provider");
    return nullptr;
  }
  api.sm4_gcm = api.EVP_CIPHER_fetch(api.context, "SM4-GCM", "provider=default");
  api.sm4_ccm = api.EVP_CIPHER_fetch(api.context, "SM4-CCM", "provider=default");
  api.aes256_ccm = api.EVP_CIPHER_fetch(api.context, "AES-256-CCM", "provider=default");
  api.hkdf = api.EVP_KDF_fetch(api.context, "HKDF", "provider=default");
  for (uint16_t group : {30, 31, 32, 33, 41})
    if (api.Generate(group, false))
      api.groups.insert(group);
  if (!gost_module.empty()) {
    if (gost_module.find('\0') != std::string_view::npos || gost_module.size() > 32767) return {};
#if defined(_WIN32)
    if (!(gost_module.starts_with("\\\\") || (gost_module.size() > 2 && gost_module[1] == ':' &&
        (gost_module[2] == '/' || gost_module[2] == '\\')))) return {};
    // OpenSSL's Windows DSO loader uses LoadLibraryA, not UTF-8. Load the
    // explicitly selected file ourselves and register its initializer only in
    // this private context. Keep the module alive through provider/context and
    // per-thread cleanup; never fall back to a search-path provider name.
    const int wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        gost_module.data(), static_cast<int>(gost_module.size()), nullptr, 0);
    if (wide_length <= 0) return {};
    std::wstring wide_module(wide_length, L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, gost_module.data(),
        static_cast<int>(gost_module.size()), wide_module.data(), wide_length) != wide_length) return {};
    api.gost_module_handle = LoadLibraryExW(wide_module.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!api.gost_module_handle) return {};
    auto initialize = reinterpret_cast<Impl::ProviderInit>(GetProcAddress(
        static_cast<HMODULE>(api.gost_module_handle), "OSSL_provider_init"));
    if (!initialize || !api.OSSL_PROVIDER_add_builtin(api.context, "httpps-gost", initialize)) return {};
    api.gost_provider = api.OSSL_PROVIDER_load(api.context, "httpps-gost");
#else
    if (gost_module.front() != '/') return {};
    api.gost_provider = api.OSSL_PROVIDER_load(api.context, std::string(gost_module).c_str());
#endif
    if (!api.gost_provider) return {};
    api.kuznyechik = api.EVP_CIPHER_fetch(api.context, "kuznyechik-mgm", nullptr);
    api.magma = api.EVP_CIPHER_fetch(api.context, "magma-mgm", nullptr);
    if (!result->SupportsGost()) return {};
    for (uint16_t group = 34; group <= 40; ++group) {
      if (!api.Generate(group, false)) return {};
      api.groups.insert(group);
    }
  }
  if (api.groups.empty()) {
    LoadFailure("key agreement availability");
    return nullptr;
  }
  return result;
}

bool NativeProvider::SupportsGroup(uint16_t group) const {
  return impl_->groups.count(group) != 0;
}

bool NativeProvider::SupportsSM() const {
  return impl_->sm4_gcm && impl_->sm4_ccm && impl_->hkdf && Sm3({}).size() == 32;
}

bool NativeProvider::SupportsGost() const {
  return impl_->gost_provider && impl_->kuznyechik && impl_->magma && GostHash({}).size() == 32;
}
Bytes NativeProvider::GostHash(ByteSpan input, bool wide) const {
  Impl::ThreadScope cleanup(*impl_);
  if (!impl_->gost_provider || input.size() > (1 << 24)) return {};
  Bytes output(wide ? 64 : 32);
  size_t length = output.size();
  if (impl_->EVP_Q_digest(impl_->context, wide ? "md_gost12_512" : "md_gost12_256", nullptr,
      input.data(), input.size(), output.data(), &length) != 1 || length != output.size()) return {};
  return output;
}
Bytes NativeProvider::GostMac(ByteSpan key, ByteSpan input, bool wide) const {
  Impl::ThreadScope cleanup(*impl_);
  if (!impl_->gost_provider || key.size() > (1 << 20) || input.size() > (1 << 24)) return {};
  Bytes output(wide ? 64 : 32);
  size_t length = output.size();
  if (!impl_->EVP_Q_mac(impl_->context, "HMAC", nullptr, wide ? "md_gost12_512" : "md_gost12_256", nullptr,
      key.data(), key.size(), input.data(), input.size(), output.data(), output.size(), &length) || length != output.size()) {
    OPENSSL_cleanse(output.data(), output.size()); return {};
  }
  return output;
}
Bytes NativeProvider::GostExpand(ByteSpan secret, ByteSpan info, size_t length) const {
  Impl::ThreadScope cleanup(*impl_);
  if (!impl_->gost_provider || length > 255 * 32) return {};
  Bytes result, previous;
  for (size_t counter = 1; result.size() < length; ++counter) {
    Bytes input(previous);
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(static_cast<uint8_t>(counter));
    auto next = GostMac(secret, input);
    OPENSSL_cleanse(input.data(), input.size());
    OPENSSL_cleanse(previous.data(), previous.size());
    previous = std::move(next);
    if (previous.size() != 32) { OPENSSL_cleanse(result.data(), result.size()); return {}; }
    const auto part = ByteSpan(previous).first(std::min<size_t>(32, length - result.size()));
    result.insert(result.end(), part.begin(), part.end());
  }
  OPENSSL_cleanse(previous.data(), previous.size());
  return result;
}
bool NativeProvider::GostMgm(bool encrypt, uint16_t suite, ByteSpan key, ByteSpan nonce,
                            ByteSpan aad, ByteSpan input, Bytes* output) const {
  Impl::ThreadScope cleanup(*impl_);
  if (!output) return false;
  output->clear();
  const size_t width = GostTagLength(suite);
  if (!impl_->gost_provider || !width || key.size() != 32 || nonce.size() != width ||
      nonce[0] & 0x80 || aad.size() > 65535 || input.size() > 65535 || (!encrypt && input.size() < width)) return false;
  auto& api = *impl_;
  Handle context(api.EVP_CIPHER_CTX_new(), api.EVP_CIPHER_CTX_free);
  auto init = encrypt ? api.EVP_EncryptInit_ex2 : api.EVP_DecryptInit_ex2;
  auto update = encrypt ? api.EVP_EncryptUpdate : api.EVP_DecryptUpdate;
  auto final = encrypt ? api.EVP_EncryptFinal_ex : api.EVP_DecryptFinal_ex;
  const auto content = encrypt ? input : input.first(input.size() - width);
  Bytes tag = encrypt ? Bytes(width) : Bytes(input.last(width).begin(), input.last(width).end());
  Bytes result(content.size() + width);
  const uint8_t empty = 0;
  int count = 0, tail = 0;
  const bool ok = context && init(context.get(), width == 16 ? api.kuznyechik : api.magma, key.data(), nonce.data(), nullptr) == 1 &&
      (aad.empty() || update(context.get(), nullptr, &count, aad.data(), static_cast<int>(aad.size())) == 1) &&
      update(context.get(), result.data(), &count, content.empty() ? &empty : content.data(), static_cast<int>(content.size())) == 1 &&
      count >= 0 && static_cast<size_t>(count) <= content.size() &&
      (encrypt || api.EVP_CIPHER_CTX_ctrl(context.get(), 0x11, static_cast<int>(width), tag.data()) == 1) &&
      final(context.get(), MutableByteSpan(result).subspan(static_cast<size_t>(count)).data(), &tail) == 1 &&
      count + tail == static_cast<int>(content.size()) &&
      (!encrypt || api.EVP_CIPHER_CTX_ctrl(context.get(), 0x10, static_cast<int>(width), tag.data()) == 1);
  if (ok) {
    result.resize(content.size());
    if (encrypt) result.insert(result.end(), tag.begin(), tag.end());
    *output = std::move(result);
  } else { OPENSSL_cleanse(result.data(), result.size()); api.ERR_clear_error(); }
  return ok;
}

bool NativeProvider::SupportsPasswordAead() const { return impl_->aes256_ccm != nullptr; }
bool NativeProvider::PasswordAead(bool encrypt, ByteSpan key, ByteSpan nonce,
    ByteSpan aad, ByteSpan input, Bytes* output) const {
  return CipherAead(encrypt, 0xc0b3, key, nonce, aad, input, output);
}

bool NativeProvider::ProtectUsername(ByteSpan spki, ByteSpan username, Bytes* output) const {
  Impl::ThreadScope cleanup(*impl_);
  if (!output || spki.empty() || spki.size() > 16384 || username.empty() || username.size() > 255) return false;
  output->clear();
  const uint8_t* cursor = spki.data();
  bssl::UniquePtr<EVP_PKEY> key(d2i_PUBKEY(nullptr, &cursor, spki.size()));
  const EC_KEY* peer = key ? EVP_PKEY_get0_EC_KEY(key.get()) : nullptr;
  if (!peer || cursor != spki.subspan(spki.size()).data() || !EC_KEY_check_key(peer)) return false;
  const EC_GROUP* group = EC_KEY_get0_group(peer);
  const int nid = EC_GROUP_get_curve_name(group);
  const size_t width = nid == NID_X9_62_prime256v1 ? 32 : nid == NID_secp384r1 ? 48 : nid == NID_secp521r1 ? 66 : 0;
  const size_t key_size = width == 32 ? 32 : width == 48 ? 48 : 64;
  if (!width || width + 16 + std::max<size_t>(128, username.size()) > 255) return false;
  bssl::UniquePtr<EC_KEY> ephemeral(EC_KEY_new_by_curve_name(nid));
  Bytes secret(width), derived(key_size), encoded(width + 1), plaintext(username.begin(), username.end());
  plaintext.resize(std::max<size_t>(128, plaintext.size()), 0);
  auto wipe = [&]() {
    for (auto* bytes : {&secret, &derived, &plaintext}) OPENSSL_cleanse(bytes->data(), bytes->size());
  };
  if (!ephemeral || !EC_KEY_generate_key(ephemeral.get()) ||
      ECDH_compute_key(secret.data(), secret.size(), EC_KEY_get0_public_key(peer), ephemeral.get(), nullptr) != static_cast<int>(width) ||
      EC_POINT_point2oct(group, EC_KEY_get0_public_key(ephemeral.get()), POINT_CONVERSION_COMPRESSED,
          encoded.data(), encoded.size(), nullptr) != encoded.size() ||
      !HKDF(derived.data(), derived.size(), width == 32 ? EVP_sha256() : width == 48 ? EVP_sha384() : EVP_sha512(),
          secret.data(), secret.size(), nullptr, 0, nullptr, 0)) {
    wipe(); return false;
  }
  auto& api = *impl_;
  Handle cipher(api.EVP_CIPHER_fetch(api.context, key_size == 32 ? "AES-128-SIV" : key_size == 48 ? "AES-192-SIV" : "AES-256-SIV",
                                    "provider=default"), api.EVP_CIPHER_free);
  Handle context(api.EVP_CIPHER_CTX_new(), api.EVP_CIPHER_CTX_free);
  Bytes encrypted(plaintext.size() + 16), tag(16);
  int count = 0, tail = 0;
  const bool ok = cipher && context && api.EVP_EncryptInit_ex2(context.get(), cipher.get(), derived.data(), nullptr, nullptr) == 1 &&
      api.EVP_EncryptUpdate(context.get(), encrypted.data(), &count, plaintext.data(), static_cast<int>(plaintext.size())) == 1 &&
      count >= 0 && static_cast<size_t>(count) <= plaintext.size() &&
      api.EVP_EncryptFinal_ex(context.get(), MutableByteSpan(encrypted).subspan(static_cast<size_t>(count)).data(), &tail) == 1 &&
      count + tail == static_cast<int>(plaintext.size()) &&
      api.EVP_CIPHER_CTX_ctrl(context.get(), 0x10, 16, tag.data()) == 1;
  if (ok) {
    output->assign(encoded.begin() + 1, encoded.end());
    output->insert(output->end(), tag.begin(), tag.end());
    output->insert(output->end(), encrypted.begin(), encrypted.begin() + count + tail);
  } else api.ERR_clear_error();
  wipe();
  return ok;
}

Bytes NativeProvider::Sm3(ByteSpan input) const {
  Impl::ThreadScope cleanup(*impl_);
  Bytes output(32);
  size_t length = output.size();
  if (impl_->EVP_Q_digest(impl_->context, "SM3", "provider=default", input.data(), input.size(), output.data(), &length) != 1 || length != 32)
    return {};
  return output;
}
Bytes NativeProvider::Sm3Mac(ByteSpan key, ByteSpan input) const {
  Impl::ThreadScope cleanup(*impl_);
  Bytes output(32);
  size_t length = output.size();
  if (!impl_->EVP_Q_mac(impl_->context, "HMAC", "provider=default", "SM3", nullptr,
        key.data(), key.size(), input.data(), input.size(), output.data(), output.size(), &length) || length != 32) {
    OPENSSL_cleanse(output.data(), output.size());
    return {};
  }
  return output;
}
Bytes NativeProvider::Sm3Expand(ByteSpan secret, ByteSpan info, size_t length) const {
  Impl::ThreadScope cleanup(*impl_);
  if (length > 255 * 32 || !impl_->hkdf)
    return {};
  auto& api = *impl_;
  Handle builder(api.OSSL_PARAM_BLD_new(), api.OSSL_PARAM_BLD_free);
  Handle context(api.EVP_KDF_CTX_new(api.hkdf), api.EVP_KDF_CTX_free);
  if (!builder || !context ||
      api.OSSL_PARAM_BLD_push_utf8_string(builder.get(), "mode", "EXPAND_ONLY", 0) != 1 ||
      api.OSSL_PARAM_BLD_push_utf8_string(builder.get(), "digest", "SM3", 0) != 1 ||
      api.OSSL_PARAM_BLD_push_octet_string(builder.get(), "key", secret.data(), secret.size()) != 1 ||
      api.OSSL_PARAM_BLD_push_octet_string(builder.get(), "info", info.data(), info.size()) != 1)
    return {};
  Handle parameters(api.OSSL_PARAM_BLD_to_param(builder.get()), api.OSSL_PARAM_free);
  Bytes output(length);
  if (!parameters || api.EVP_KDF_derive(context.get(), output.data(), output.size(), parameters.get()) != 1) {
    OPENSSL_cleanse(output.data(), output.size());
    return {};
  }
  return output;
}
bool NativeProvider::Sm4(bool encrypt, uint16_t suite, ByteSpan key, ByteSpan nonce,
                          ByteSpan aad, ByteSpan input, Bytes* output) const {
  if (suite != 0x00c6 && suite != 0x00c7) return false;
  return CipherAead(encrypt, suite, key, nonce, aad, input, output);
}
bool NativeProvider::CipherAead(bool encrypt, uint16_t suite, ByteSpan key, ByteSpan nonce,
                          ByteSpan aad, ByteSpan input, Bytes* output) const {
  Impl::ThreadScope cleanup(*impl_);
  if (!output)
    return false;
  output->clear();
  if ((suite != 0x00c6 && suite != 0x00c7 && suite != 0xc0b3) || key.size() != (suite == 0xc0b3 ? 32u : 16u) || nonce.size() != 12 ||
      aad.size() > 65535 || input.size() > 65535 || (!encrypt && input.size() < 16))
    return false;
  auto& api = *impl_;
  const bool ccm = suite != 0x00c6;
  void* cipher = suite == 0xc0b3 ? api.aes256_ccm : ccm ? api.sm4_ccm : api.sm4_gcm;
  Handle context(api.EVP_CIPHER_CTX_new(), api.EVP_CIPHER_CTX_free);
  auto init = encrypt ? api.EVP_EncryptInit_ex2 : api.EVP_DecryptInit_ex2;
  auto update = encrypt ? api.EVP_EncryptUpdate : api.EVP_DecryptUpdate;
  auto final = encrypt ? api.EVP_EncryptFinal_ex : api.EVP_DecryptFinal_ex;
  ByteSpan content = encrypt ? input : input.first(input.size() - 16);
  Bytes tag = encrypt ? Bytes(16) : Bytes(input.last(16u).begin(), input.last(16u).end());
  Bytes result(content.size() + 16);
  // EVP uses a null input pointer as a control operation in CCM. Even a
  // zero-length plaintext must invoke the actual authentication operation.
  const uint8_t empty_input = 0;
  const uint8_t* content_data = content.empty() ? &empty_input : content.data();
  int count = 0;
  bool ok = cipher && context && init(context.get(), cipher, nullptr, nullptr, nullptr) == 1 &&
      api.EVP_CIPHER_CTX_ctrl(context.get(), 0x9, 12, nullptr) == 1 &&
      (!ccm || api.EVP_CIPHER_CTX_ctrl(context.get(), 0x11, 16, encrypt ? nullptr : tag.data()) == 1) &&
      init(context.get(), nullptr, key.data(), nonce.data(), nullptr) == 1 &&
      (!ccm || update(context.get(), nullptr, &count, nullptr, static_cast<int>(content.size())) == 1) &&
      (aad.empty() || update(context.get(), nullptr, &count, aad.data(), static_cast<int>(aad.size())) == 1) &&
      update(context.get(), result.data(), &count, content_data, static_cast<int>(content.size())) == 1;
  const int first = count;
  if (ok)
    ok = first >= 0 && static_cast<size_t>(first) <= result.size() &&
        (encrypt || ccm || api.EVP_CIPHER_CTX_ctrl(context.get(), 0x11, 16, tag.data()) == 1) &&
        final(context.get(), MutableByteSpan(result).subspan(static_cast<size_t>(first)).data(), &count) == 1 &&
        first + count == static_cast<int>(content.size()) &&
        (!encrypt || api.EVP_CIPHER_CTX_ctrl(context.get(), 0x10, 16, tag.data()) == 1);
  if (ok) {
    result.resize(content.size());
    if (encrypt)
      result.insert(result.end(), tag.begin(), tag.end());
    *output = std::move(result);
  } else {
    OPENSSL_cleanse(result.data(), result.size());
    api.ERR_clear_error();
  }
  return ok;
}

bool NativeProvider::VerifySm2Signature(ByteSpan spki, ByteSpan message, ByteSpan signature,
                                       std::string_view identifier) const {
  Impl::ThreadScope cleanup(*impl_);
  if (spki.empty() || spki.size() > 16384 || message.size() > (1 << 24) ||
      signature.size() < 8 || signature.size() > 80 || identifier.empty() || identifier.size() > 8191)
    return false;
  auto& api = *impl_;
  const uint8_t* cursor = spki.data();
  Handle key(api.d2i_PUBKEY_ex(nullptr, &cursor, static_cast<long>(spki.size()), api.context, "provider=default"), api.EVP_PKEY_free);
  Handle md(api.EVP_MD_CTX_new(), api.EVP_MD_CTX_free);
  void* pctx = nullptr;
  const bool ok = key && md && cursor == spki.subspan(spki.size()).data() && api.EVP_PKEY_is_a(key.get(), "SM2") == 1 &&
      api.EVP_DigestVerifyInit_ex(md.get(), &pctx, "SM3", api.context, "provider=default", key.get(), nullptr) == 1 &&
      api.EVP_PKEY_CTX_set1_id(pctx, identifier.data(), static_cast<int>(identifier.size())) == 1 &&
      api.EVP_DigestVerify(md.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
  if (!ok) api.ERR_clear_error();
  return ok;
}

bool NativeProvider::VerifyPublicSignature(ByteSpan spki, ByteSpan message, ByteSpan signature,
    uint16_t scheme, bool certificate_encoding) const {
  Impl::ThreadScope cleanup(*impl_);
  if (spki.empty() || spki.size() > 16384 || message.size() > (1 << 20) || signature.empty() || signature.size() > 16384) return false;
  const bool gost = scheme >= 0x0709 && scheme <= 0x070f;
  auto& api = *impl_;
  const auto* properties = gost ? nullptr : "provider=default";
  const uint8_t* cursor = spki.data();
  Handle key(api.d2i_PUBKEY_ex(nullptr, &cursor, static_cast<long>(spki.size()), api.context, properties), api.EVP_PKEY_free);
  if (!key || cursor != spki.subspan(spki.size()).data()) return false;
  const char* digest = nullptr;
  Bytes encoded_signature(signature.begin(), signature.end());
  bool pss = false;
  unsigned digest_size = 0;
  if (gost) {
    const uint16_t group = GostPublicKeyGroup(spki);
    if (!SupportsGost() || !group || scheme != 0x0709 + group - 34 ||
        signature.size() != (group <= 37 ? 64u : 128u) ||
        api.EVP_PKEY_is_a(key.get(), group <= 37 ? "gost2012_256" : "gost2012_512") != 1) return false;
    digest = group <= 37 ? "md_gost12_256" : "md_gost12_512";
    if (!certificate_encoding) std::reverse(encoded_signature.begin(), encoded_signature.end());
  } else if (scheme == 0x0808) {
    if (signature.size() != 114 || api.EVP_PKEY_is_a(key.get(), "ED448") != 1) return false;
  } else if (scheme >= 0x081a && scheme <= 0x081c) {
    std::array<char, 128> curve{}; size_t length = 0;
    const char* wanted = scheme == 0x081a ? "brainpoolP256r1" : scheme == 0x081b ? "brainpoolP384r1" : "brainpoolP512r1";
    if (api.EVP_PKEY_is_a(key.get(), "EC") != 1 ||
        api.EVP_PKEY_get_utf8_string_param(key.get(), "group", curve.data(), curve.size(), &length) != 1 ||
        length >= curve.size() || std::string_view(curve.data(), length) != wanted) return false;
    digest = scheme == 0x081a ? "SHA256" : scheme == 0x081b ? "SHA384" : "SHA512";
  } else if (scheme >= 0x0809 && scheme <= 0x080b) {
    if (api.EVP_PKEY_is_a(key.get(), "RSA-PSS") != 1 || api.EVP_PKEY_get_bits(key.get()) < 2048) return false;
    digest = scheme == 0x0809 ? "SHA256" : scheme == 0x080a ? "SHA384" : "SHA512";
    digest_size = scheme == 0x0809 ? 32 : scheme == 0x080a ? 48 : 64;
    pss = true;
  } else return false;
  Handle check(api.EVP_PKEY_CTX_new_from_pkey(api.context, key.get(), properties), api.EVP_PKEY_CTX_free);
  Handle md(api.EVP_MD_CTX_new(), api.EVP_MD_CTX_free);
  void* context = nullptr;
  bool ok = check && md && api.EVP_PKEY_public_check(check.get()) == 1 &&
      api.EVP_DigestVerifyInit_ex(md.get(), &context, digest, api.context, properties, key.get(), nullptr) == 1 &&
      (!pss || (api.EVP_PKEY_CTX_set_rsa_padding(context, 6) == 1 &&
                api.EVP_PKEY_CTX_set_rsa_pss_saltlen(context, static_cast<int>(digest_size)) == 1 &&
                api.EVP_PKEY_CTX_set_rsa_mgf1_md_name(context, digest, "provider=default") == 1));
  if (ok) ok = gost ? api.EVP_DigestVerifyUpdate(md.get(), message.data(), message.size()) == 1 &&
                    api.EVP_DigestVerifyFinal(md.get(), encoded_signature.data(), encoded_signature.size()) == 1
                   : api.EVP_DigestVerify(md.get(), encoded_signature.data(), encoded_signature.size(), message.data(), message.size()) == 1;
  if (!ok) api.ERR_clear_error();
  return ok;
}

std::optional<std::vector<std::string>> NativeProvider::VerifyCertificatePath(
    const std::vector<std::string>& chain, const std::vector<std::string>& roots,
    std::string_view hostname, bool server, bool partial_chain) const {
  Impl::ThreadScope cleanup(*impl_);
  if (chain.empty() || roots.empty() || chain.size() > 32 || roots.size() > 4096 ||
      (server && !ValidServiceIdentity(hostname)))
    return {};
  // Generic SSL purpose checks do not know TLS2's X25519 authentication role.
  // Enforce RFC8410 key usage as well, without accepting a CA as an endpoint.
  auto leaf_bytes = StringBytes(chain.front()); const uint8_t* leaf_cursor = leaf_bytes.data();
  bssl::UniquePtr<X509> leaf(d2i_X509(nullptr, &leaf_cursor, leaf_bytes.size()));
  Secret static_key;
  if (!leaf || X509_check_ca(leaf.get()) > 0) return {};
  if (ExtractServerPublicKey(chain.front(), &static_key) && X509_get_ext_by_NID(leaf.get(), NID_key_usage, -1) >= 0) {
    bssl::UniquePtr<ASN1_BIT_STRING> usage(static_cast<ASN1_BIT_STRING*>(X509_get_ext_d2i(leaf.get(), NID_key_usage, nullptr, nullptr)));
    if (!usage || !ASN1_BIT_STRING_get_bit(usage.get(), 4)) return {};
    for (int bit : {0, 1, 2, 3, 5, 6}) if (ASN1_BIT_STRING_get_bit(usage.get(), bit)) return {};
  }
  auto& api = *impl_;
  std::vector<Handle> certificates;
  const char* properties = api.gost_provider ? nullptr : "provider=default";
  auto parse = [&](const std::string& value) {
    if (value.empty() || value.size() > (1 << 20)) return false;
    auto bytes = StringBytes(value);
    const uint8_t* cursor = bytes.data();
    void* raw = api.X509_new_ex(api.context, properties);
    if (!raw) return false;
    auto* parsed = api.d2i_X509(&raw, &cursor, static_cast<long>(bytes.size()));
    Handle cert(raw, api.X509_free);
    if (!parsed || cursor != bytes.subspan(bytes.size()).data()) return false;
    if (api.X509_get_signature_nid(cert.get()) == api.OBJ_txt2nid("1.2.156.10197.1.501")) {
      Handle identity(api.ASN1_OCTET_STRING_new(), api.ASN1_OCTET_STRING_free);
      if (!identity || api.ASN1_OCTET_STRING_set(identity.get(), "1234567812345678", 16) != 1) return false;
      api.X509_set0_distinguishing_id(cert.get(), identity.release());
    }
    certificates.push_back(std::move(cert));
    return true;
  };
  for (const auto& cert : chain) if (!parse(cert)) return {};
  for (const auto& cert : roots) if (!parse(cert)) return {};
  Handle store(api.X509_STORE_new(), api.X509_STORE_free);
  Handle untrusted(api.OPENSSL_sk_new_null(), api.OPENSSL_sk_free);
  Handle context(api.X509_STORE_CTX_new_ex(api.context, properties), api.X509_STORE_CTX_free);
  if (!store || !untrusted || !context) return {};
  for (size_t i = chain.size(); i < certificates.size(); ++i)
    if (api.X509_STORE_add_cert(store.get(), certificates[i].get()) != 1) return {};
  for (size_t i = 1; i < chain.size(); ++i)
    if (api.OPENSSL_sk_push(untrusted.get(), certificates[i].get()) <= 0) return {};
  if (api.X509_STORE_CTX_init(context.get(), store.get(), certificates.front().get(), untrusted.get()) != 1 ||
      api.X509_STORE_CTX_set_purpose(context.get(), server ? 2 : 1) != 1) return {};
  auto* parameters = api.X509_STORE_CTX_get0_param(context.get());
  api.X509_VERIFY_PARAM_set_hostflags(parameters, 0x4 | 0x20);
  if (api.X509_VERIFY_PARAM_set_flags(parameters, 0x20 | 0x80 | 0x8000 | (partial_chain ? 0x80000 : 0)) != 1)
    return {};
  const std::string name(hostname);
  if (!name.empty() && (IsIpIdentity(name) ? api.X509_VERIFY_PARAM_set1_ip_asc(parameters, name.c_str())
      : api.X509_VERIFY_PARAM_set1_host(parameters, name.data(), name.size())) != 1) return {};
  if (certificate_provider) return {};  // No recursive verifier/provider state.
  if (api.gost_provider) api.X509_STORE_CTX_set_verify_cb(context.get(), [](int preverified, void* state) -> int {
    if (preverified) return 1;
    const auto* owner = certificate_provider;
    if (!owner || owner->impl_->X509_STORE_CTX_get_error(state) != 7) return 0;
    // Work around only the provider's missing OpenSSL ASN.1 digest dispatch.
    // This never overrides path/name/purpose/constraints/revocation failures.
    const auto& native = *owner->impl_;
    void* chain = native.X509_STORE_CTX_get0_chain(state);
    const int depth = native.X509_STORE_CTX_get_error_depth(state);
    if (!chain || depth < 0 || depth >= native.OPENSSL_sk_num(chain) - 1 ||
        native.X509_STORE_CTX_get_current_cert(state) != native.OPENSSL_sk_value(chain, depth)) return 0;
    const auto der = [&](void* object) -> Bytes {
      const int length = native.i2d_X509(object, nullptr);
      if (length < 1 || length > (1 << 20)) return {};
      Bytes encoded(static_cast<size_t>(length)); auto* cursor = encoded.data();
      return native.i2d_X509(object, &cursor) == length ? encoded : Bytes{};
    };
    const auto child_der = der(native.OPENSSL_sk_value(chain, depth));
    const auto issuer_der = der(native.OPENSSL_sk_value(chain, depth + 1));
    if (child_der.empty() || issuer_der.empty()) return 0;
    const uint8_t* child_cursor = child_der.data(); const uint8_t* issuer_cursor = issuer_der.data();
    bssl::UniquePtr<X509> child(d2i_X509(nullptr, &child_cursor, child_der.size())),
                         issuer(d2i_X509(nullptr, &issuer_cursor, issuer_der.size()));
    if (!child || !issuer || X509_NAME_cmp(X509_get_issuer_name(child.get()), X509_get_subject_name(issuer.get()))) return 0;
    const int spki_length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(issuer.get()), nullptr);
    if (spki_length < 1 || spki_length > 8192) return 0;
    Bytes spki(static_cast<size_t>(spki_length)); auto* spki_cursor = spki.data();
    if (i2d_X509_PUBKEY(X509_get_X509_PUBKEY(issuer.get()), &spki_cursor) != spki_length) return 0;
    const auto group = GostPublicKeyGroup(spki);
    if (!group) return 0;
    const uint16_t scheme = 0x0709 + group - 34;
    const ASN1_BIT_STRING* signature = nullptr;
    const X509_ALGOR* algorithm = nullptr;
    X509_get0_signature(&signature, &algorithm, child.get());
    const ASN1_OBJECT* oid = nullptr; int parameter_type = 0;
    if (!algorithm || X509_ALGOR_cmp(algorithm, X509_get0_tbs_sigalg(child.get()))) return 0;
    X509_ALGOR_get0(&oid, &parameter_type, nullptr, algorithm);
    bssl::UniquePtr<ASN1_OBJECT> expected(OBJ_txt2obj(group <= 37 ? "1.2.643.7.1.1.3.2" : "1.2.643.7.1.1.3.3", 1));
    if (!oid || !expected || OBJ_cmp(oid, expected.get()) || parameter_type != V_ASN1_UNDEF) return 0;
    const int tbs_length = i2d_re_X509_tbs(child.get(), nullptr);
    if (!signature || tbs_length < 1 || tbs_length > (1 << 20)) return 0;
    Bytes tbs(static_cast<size_t>(tbs_length)); auto* tbs_cursor = tbs.data();
    CBS encoded_signature;
    CBS_init(&encoded_signature, ASN1_STRING_get0_data(signature), ASN1_STRING_length(signature));
    const auto signature_bytes = static_cast<bssl::Span<const uint8_t>>(encoded_signature);
    if (i2d_re_X509_tbs(child.get(), &tbs_cursor) != tbs_length ||
        !owner->VerifyPublicSignature(spki, tbs, ByteSpan(signature_bytes), scheme, true)) return 0;
    native.X509_STORE_CTX_set_error(state, 0); native.ERR_clear_error(); return 1;
  });
  certificate_provider = this;
  const int verified = api.X509_verify_cert(context.get());
  certificate_provider = nullptr;
  if (verified != 1) { api.ERR_clear_error(); return {}; }
  Handle path(api.X509_STORE_CTX_get1_chain(context.get()), api.OPENSSL_sk_free);
  if (!path) return {};
  const int count = api.OPENSSL_sk_num(path.get());
  std::vector<Handle> owned_path;
  for (int i = 0; i < count; ++i)
    owned_path.emplace_back(api.OPENSSL_sk_value(path.get(), i), api.X509_free);
  if (count < 1 || count > 64) return {};
  std::vector<std::string> result;
  for (const auto& cert : owned_path) {
    const int length = api.i2d_X509(cert.get(), nullptr);
    if (length < 1 || length > (1 << 20)) return {};
    std::string encoded(static_cast<size_t>(length), '\0');
    auto* cursor = reinterpret_cast<uint8_t*>(encoded.data());
    if (api.i2d_X509(cert.get(), &cursor) != length) return {};
    result.push_back(std::move(encoded));
  }
  return result;
}

std::unique_ptr<NativeTrafficKey> NativeProvider::Generate(uint16_t group, Bytes* public_key) {
  Impl::ThreadScope cleanup(*impl_);
  if (!public_key || !SupportsGroup(group))
    return nullptr;
  auto& api = *impl_;
  auto key = api.Generate(group, false);
  if (!key)
    return nullptr;
  const bool gost = group >= 34 && group <= 40;
  const size_t size = group == 30 ? 56 : (gost ? 0 : 1) + 2 * GroupWidth(group);
  public_key->resize(size);
  size_t written = size;
  const int ok = group == 30 ? api.EVP_PKEY_get_raw_public_key(key.get(), public_key->data(), &written)
      : api.EVP_PKEY_get_octet_string_param(key.get(), gost ? "encoded-pub-key" : "pub", public_key->data(), size, &written);
  if (ok != 1 || written != size || (!gost && group != 30 && public_key->front() != 4)) {
    public_key->clear();
    api.ERR_clear_error();
    return nullptr;
  }
  return std::unique_ptr<NativeTrafficKey>(new NativeTrafficKey(shared_from_this(), group, key.release()));
}

struct NativePasswordState::Impl {
  std::shared_ptr<NativeProvider> provider;
  // Both objects are owned by external libraries, never PartitionAlloc.
  HTTPPS_FOREIGN_HANDLE void* module = nullptr;
  HTTPPS_FOREIGN_HANDLE void* state = nullptr;
  size_t width = 0;
  bool ffc = false;
  unsigned (*abi)() = nullptr;
  const char* (*function_name)(size_t) = nullptr;
  void* (*create)(void* const*, size_t, void*, int, const void*, const void*, unsigned) = nullptr;
  void* (*create_ff)(void* const*, size_t, void*, const void*, size_t, const void*, const void*, unsigned) = nullptr;
  int (*commit)(void*, void*, size_t) = nullptr;
  int (*finish)(void*, const void*, size_t, void*, size_t) = nullptr;
  void (*destroy)(void*) = nullptr;
  template<class T> bool Bind(T* function, const char* name) {
#if defined(_WIN32)
    *function = reinterpret_cast<T>(GetProcAddress(static_cast<HMODULE>(module), name));
#else
    *function = reinterpret_cast<T>(dlsym(module, name));
#endif
    return *function != nullptr;
  }
  ~Impl() {
    if (state) {
      NativeProvider::Impl::ThreadScope cleanup(*provider->impl_);
      destroy(state);
    }
    if (module) {
#if defined(_WIN32)
      FreeLibrary(static_cast<HMODULE>(module));
#else
      dlclose(module);
#endif
    }
  }
};
NativePasswordState::NativePasswordState() : impl_(std::make_unique<Impl>()) {}
NativePasswordState::~NativePasswordState() = default;

std::unique_ptr<NativePasswordState> NativeProvider::PasswordExchange(std::string_view path,
    ByteSpan base, ByteSpan client_random, uint16_t group, unsigned hash_bits) {
  Impl::ThreadScope cleanup(*impl_);
  if (base.size() != 32 || client_random.size() != 32 || ((group < 23 || group > 25) && (group < 256 || group > 260)) ||
      (hash_bits != 256 && hash_bits != 384) || path.empty() || path.find('\0') != std::string_view::npos)
    return {};
  auto result = std::unique_ptr<NativePasswordState>(new NativePasswordState());
  auto& helper = *result->impl_;
  helper.ffc = group >= 256;
#if defined(_WIN32)
  if (path.size() > 32767 || !(path.starts_with("\\\\") ||
      (path.size() > 2 && path[1] == ':' && (path[2] == '/' || path[2] == '\\')))) return {};
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()), nullptr, 0);
  if (length < 1) return {};
  std::wstring wide(static_cast<size_t>(length), '\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()), wide.data(), length) != length) return {};
  helper.module = LoadLibraryExW(wide.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
#else
  if (path.front() != '/') return {};
  helper.module = dlopen(std::string(path).c_str(), RTLD_LOCAL | RTLD_NOW);
#endif
  if (!helper.module || !helper.Bind(&helper.abi, "tls20_pwd_abi") || helper.abi() != 1 ||
      !helper.Bind(&helper.function_name, "tls20_pwd_function_name") ||
      !helper.Bind(&helper.create, "tls20_pwd_new") || !helper.Bind(&helper.create_ff, "tls20_pwd_ff_new") ||
      !helper.Bind(&helper.commit, helper.ffc ? "tls20_pwd_ff_commit" : "tls20_pwd_commit") ||
      !helper.Bind(&helper.finish, helper.ffc ? "tls20_pwd_ff_finish" : "tls20_pwd_finish") || !helper.Bind(&helper.destroy, "tls20_pwd_free"))
    return {};
  std::vector<void*> functions;
  for (size_t i = 0; i < 256; ++i) {
    const char* name = helper.function_name(i);
    if (!name) break;
    void* function = nullptr;
    if (!impl_->Bind(&function, name)) return {};
    functions.push_back(function);
  }
  if (functions.empty() || functions.size() == 256) return {};
  const char* curve = group == 23 ? "prime256v1" : group == 24 ? "secp384r1" : "secp521r1";
  helper.provider = shared_from_this();
  const auto prime = helper.ffc ? FfdhePrime(group) : Bytes{};
  helper.width = helper.ffc ? prime.size() : group == 23 ? 32 : group == 24 ? 48 : 66;
  helper.state = helper.ffc ? helper.create_ff(functions.data(), functions.size(), impl_->context,
      prime.data(), prime.size(), base.data(), client_random.data(), hash_bits)
      : helper.create(functions.data(), functions.size(), impl_->context, impl_->OBJ_txt2nid(curve),
                      base.data(), client_random.data(), hash_bits);
  return helper.state ? std::move(result) : nullptr;
}
bool NativePasswordState::Commit(Bytes* public_share) {
  if (!public_share || !impl_->state) return false;
  NativeProvider::Impl::ThreadScope cleanup(*impl_->provider->impl_);
  public_share->resize(impl_->ffc ? 2 * impl_->width + 2 : 3 * impl_->width + 1);
  const int length = impl_->commit(impl_->state, public_share->data(), public_share->size());
  if (length < 1 || static_cast<size_t>(length) > public_share->size()) { public_share->clear(); return false; }
  public_share->resize(static_cast<size_t>(length));
  return true;
}
bool NativePasswordState::Finish(ByteSpan peer, Bytes* shared_secret) {
  if (!shared_secret || !impl_->state) return false;
  NativeProvider::Impl::ThreadScope cleanup(*impl_->provider->impl_);
  shared_secret->resize(impl_->width);
  const int length = impl_->finish(impl_->state, peer.data(), peer.size(), shared_secret->data(), shared_secret->size());
  impl_->destroy(std::exchange(impl_->state, nullptr));
  if (length != static_cast<int>(impl_->width)) {
    OPENSSL_cleanse(shared_secret->data(), shared_secret->size());
    shared_secret->clear(); return false;
  }
  return true;
}

NativeTrafficKey::NativeTrafficKey(std::shared_ptr<NativeProvider> provider, uint16_t group, void* key)
    : provider_(std::move(provider)), group_(group), key_(key) {}
NativeTrafficKey::~NativeTrafficKey() {
  NativeProvider::Impl::ThreadScope cleanup(*provider_->impl_);
  provider_->impl_->EVP_PKEY_free(key_);
}

bool NativeTrafficKey::Agree(ByteSpan public_key, Bytes* shared) {
  NativeProvider::Impl::ThreadScope cleanup(*provider_->impl_);
  auto& api = *provider_->impl_;
  const size_t width = GroupWidth(group_);
  const bool gost = group_ >= 34 && group_ <= 40;
  if (!shared || public_key.size() != (group_ == 30 ? width : (gost ? 0 : 1) + 2 * width) ||
      (!gost && group_ != 30 && public_key[0] != 4))
    return false;
  shared->clear();
  Handle peer(nullptr, api.EVP_PKEY_free);
  if (group_ == 30) {
    peer.reset(api.EVP_PKEY_new_raw_public_key_ex(api.context, "X448", "provider=default", public_key.data(), public_key.size()));
  } else {
    peer = api.Generate(group_, true);
    if (peer && api.EVP_PKEY_set1_encoded_public_key(peer.get(), public_key.data(), public_key.size()) != 1)
      peer.reset();
  }
  if (!peer)
    return false;
  if (gost) {
    Bytes canonical(public_key.size()); size_t written = canonical.size();
    if (api.EVP_PKEY_get_octet_string_param(peer.get(), "encoded-pub-key", canonical.data(), canonical.size(), &written) != 1 ||
        written != canonical.size() || !std::equal(canonical.begin(), canonical.end(), public_key.begin())) return false;
  }
  Handle check(api.EVP_PKEY_CTX_new_from_pkey(api.context, peer.get(), gost ? nullptr : "provider=default"), api.EVP_PKEY_CTX_free);
  Handle exchange(api.EVP_PKEY_CTX_new_from_pkey(api.context, key_, gost ? nullptr : "provider=default"), api.EVP_PKEY_CTX_free);
  Bytes secret(width);
  size_t written = width;
  if (!check || !exchange || api.EVP_PKEY_public_check(check.get()) != 1 ||
      api.EVP_PKEY_derive_init(exchange.get()) != 1 ||
      api.EVP_PKEY_derive_set_peer(exchange.get(), peer.get()) != 1 ||
      api.EVP_PKEY_derive(exchange.get(), secret.data(), &written) != 1 || written != width ||
      std::all_of(secret.begin(), secret.end(), [](uint8_t value) { return value == 0; })) {
    // Non-optimizable wipe via the host BoringSSL is safe for ordinary buffers,
    // but never use it to free any provider-owned object.
    OPENSSL_cleanse(secret.data(), secret.size());
    api.ERR_clear_error();
    return false;
  }
  *shared = std::move(secret);
  return true;
}

size_t GostTagLength(uint16_t suite) {
  return suite == 0xc103 || suite == 0xc105 ? 16 : suite == 0xc104 || suite == 0xc106 ? 8 : 0;
}
uint64_t GostSequenceLimit(uint16_t suite) {
  return suite == 0xc105 ? (uint64_t{1} << 42) - 1 : suite == 0xc106 ? (uint64_t{1} << 39) - 1
      : suite == 0xc103 || suite == 0xc104 ? UINT64_MAX : 0;
}
NativeGostRecord::NativeGostRecord(std::shared_ptr<NativeProvider> provider, uint16_t suite, ByteSpan key)
    : provider_(std::move(provider)), suite_(suite), root_(key.begin(), key.end()) {
  failed_ = !provider_ || !provider_->SupportsGost() || !GostTagLength(suite_) || root_.size() != 32;
}
NativeGostRecord::~NativeGostRecord() {
  OPENSSL_cleanse(root_.data(), root_.size());
  for (auto& key : keys_) OPENSSL_cleanse(key.data(), key.size());
}
bool NativeGostRecord::Crypt(bool encrypt, uint64_t sequence, ByteSpan nonce, ByteSpan aad, ByteSpan input, Bytes* output) {
  if (!output) return false;
  if (failed_ || sequence != next_sequence_ || sequence > GostSequenceLimit(suite_) || nonce.size() != GostTagLength(suite_)) {
    failed_ = true; output->clear(); return false;
  }
  const std::array<uint64_t, 3> masks = suite_ == 0xc103 ? std::array<uint64_t, 3>{0xf800000000000000, 0xfffffff000000000, 0xffffffffffffe000}
      : suite_ == 0xc104 ? std::array<uint64_t, 3>{0xffe0000000000000, 0xffffffffc0000000, 0xffffffffffffff80}
      : suite_ == 0xc105 ? std::array<uint64_t, 3>{0xffffffffe0000000, 0xffffffffffff0000, 0xfffffffffffffff8}
      : std::array<uint64_t, 3>{0xfffffffffc000000, 0xffffffffffffe000, 0xffffffffffffffff};
  bool changed = !initialized_;
  ByteSpan key(root_);
  for (size_t level = 0; level < 3; ++level) {
    const auto value = sequence & masks[level];
    changed |= value != values_[level];
    if (changed) {
      Bytes input_bytes{1, 'l', 'e', 'v', 'e', 'l', static_cast<uint8_t>('1' + level), 0};
      for (int shift = 56; shift >= 0; shift -= 8) input_bytes.push_back(static_cast<uint8_t>(value >> shift));
      input_bytes.insert(input_bytes.end(), {1, 0});
      auto derived = provider_->GostMac(key, input_bytes);
      if (derived.size() != 32) { failed_ = true; output->clear(); return false; }
      OPENSSL_cleanse(keys_[level].data(), keys_[level].size());
      keys_[level] = std::move(derived);
      values_[level] = value;
    }
    key = keys_[level];
  }
  initialized_ = true;
  Bytes encoded_nonce(nonce.begin(), nonce.end()); encoded_nonce[0] &= 0x7f;
  if (!provider_->GostMgm(encrypt, suite_, key, encoded_nonce, aad, input, output)) { failed_ = true; return false; }
  if (next_sequence_ == UINT64_MAX) failed_ = true;
  else ++next_sequence_;
  return true;
}
}  // namespace net::httpps
#undef HTTPPS_FOREIGN_HANDLE
