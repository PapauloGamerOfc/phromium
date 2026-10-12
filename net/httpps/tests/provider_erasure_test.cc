// Isolated OpenSSL-allocation observer. These hooks are never installed in the
// browser or in the normal interoperability driver, and read only live memory.
#include "net/httpps/native_provider.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <string_view>

#include "third_party/boringssl/src/include/openssl/mem.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {
using net::httpps::Bytes;
using net::httpps::NativeProvider;

// All bytes are public test fixtures, not real credentials.
constexpr std::array<uint8_t, 32> kSecret = {
    0x93,0x67,0x2b,0x10,0x54,0x8c,0xde,0x71,0xa3,0x4d,0x96,0x2e,0xff,0x18,0x25,0x07,
    0xc9,0x6a,0xb4,0x41,0x33,0x89,0x12,0xf5,0x68,0x02,0x9f,0x6d,0x44,0xea,0x78,0xbc};
struct Allocation { void* pointer = nullptr; size_t size = 0; };
std::array<Allocation, 16384> allocations;
bool observing = false;
size_t exposed = 0;
size_t fail_cpp_allocation_size = 0;

void Check(bool success, const char* message) {
  if (!success) {
    std::fprintf(stderr, "Provider erasure failure: %s\n", message);
    std::exit(1);
  }
}

Allocation* Find(void* pointer) {
  for (auto& entry : allocations)
    if (entry.pointer == pointer)
      return &entry;
  Check(false, "all provider allocations are tracked");
  return nullptr;
}

void Observe(const Allocation& entry) {
  if (!observing || entry.size < kSecret.size())
    return;
  const auto* bytes = static_cast<const uint8_t*>(entry.pointer);
  for (size_t offset = 0; offset <= entry.size - kSecret.size(); ++offset) {
    if (std::memcmp(bytes + offset, kSecret.data(), kSecret.size()) == 0) {
      ++exposed;
      break;
    }
  }
}

void* Allocate(size_t size, const char*, int) {
  auto* pointer = std::calloc(size ? size : 1, 1);
  if (!pointer)
    return nullptr;
  auto* entry = Find(nullptr);
  *entry = {pointer, size};
  return pointer;
}

void Release(void* pointer, const char*, int) {
  if (!pointer)
    return;
  auto* entry = Find(pointer);
  Observe(*entry);  // Before free; never read allocator padding or stale memory.
  *entry = {};
  std::free(pointer);
}

void* Reallocate(void* pointer, size_t size, const char* file, int line) {
  if (!pointer)
    return Allocate(size, file, line);
  if (!size) {
    Release(pointer, file, line);
    return nullptr;
  }
  // Implement realloc without reading freed memory and preserve the old
  // allocation if allocation fails. Exact requested sizes are portable.
  const size_t old_size = Find(pointer)->size;
  auto* replacement = Allocate(size, file, line);
  if (!replacement)
    return nullptr;
  std::memcpy(replacement, pointer, std::min(old_size, size));
  Release(pointer, file, line);
  return replacement;
}

#if defined(_WIN32)
using Module = HMODULE;
Module LoadModule(std::string_view path) {
  Check(path.size() <= 32767, "explicit provider path length");
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      path.data(), static_cast<int>(path.size()), nullptr, 0);
  Check(length > 0, "provider path is UTF-8");
  std::wstring wide(length, L'\0');
  Check(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(),
      static_cast<int>(path.size()), wide.data(), length) == length, "provider path conversion");
  return LoadLibraryExW(wide.c_str(), nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
}
auto Symbol(Module module, const char* name) { return GetProcAddress(module, name); }
#else
using Module = void*;
Module LoadModule(std::string_view path) {
  int flags = RTLD_LOCAL | RTLD_NOW;
#if defined(RTLD_DEEPBIND)
  flags |= RTLD_DEEPBIND;
#endif
  return dlopen(std::string(path).c_str(), flags);
}
auto Symbol(Module module, const char* name) { return dlsym(module, name); }
#endif

Bytes ExpandOracle(const NativeProvider& provider, const Bytes& info, size_t size) {
  Bytes result, previous;
  for (size_t index = 1; result.size() < size; ++index) {
    Bytes input = previous;
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(static_cast<uint8_t>(index));
    previous = provider.Sm3Mac(kSecret, input);
    Check(previous.size() == 32, "independent HMAC expansion oracle");
    result.insert(result.end(), previous.begin(), previous.end());
  }
  result.resize(size);
  return result;
}
}  // namespace

// Force an exception specifically at Sm3Expand's output allocation, after the
// provider parameter copy exists. OpenSSL uses the independent hooks above.
void* operator new(size_t size) {
  if (size && size == fail_cpp_allocation_size) {
    fail_cpp_allocation_size = 0;
    throw std::bad_alloc();
  }
  if (void* pointer = std::malloc(size ? size : 1))
    return pointer;
  throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, size_t) noexcept { std::free(pointer); }

int main(int argc, char** argv) {
  Check(argc == 2 || argc == 3, "usage: provider_erasure_test absolute-provider [success|failure|exception]");
  const std::string path(argv[1]);
#if defined(_WIN32)
  Check(path.starts_with("\\\\") || (path.size() >= 3 && path[1] == ':' &&
      (path[2] == '\\' || path[2] == '/')), "only explicit absolute provider paths are accepted");
#else
  Check(path.starts_with('/'), "only explicit absolute provider paths are accepted");
#endif
  // Keep this handle through process exit: OpenSSL can still call the installed
  // hooks during its shutdown. No system/default library lookup is used.
  const auto module = LoadModule(path);
  Check(module != nullptr, "load explicitly configured provider");
  using Setter = int (*)(void* (*)(size_t, const char*, int),
      void* (*)(void*, size_t, const char*, int), void (*)(void*, const char*, int));
  const auto set = reinterpret_cast<Setter>(Symbol(module, "CRYPTO_set_mem_functions"));
  Check(set && set(Allocate, Reallocate, Release) == 1,
        "install isolated memory hooks before any OpenSSL allocation");
  auto provider = NativeProvider::Load(path);
  Check(provider && provider->SupportsSM(), "explicit provider supports SM3");

  observing = true;
  auto* probe = Allocate(kSecret.size(), nullptr, 0);
  std::memcpy(probe, kSecret.data(), kSecret.size());
  Release(probe, nullptr, 0);
  Check(exposed == 1, "positive observer control detects a live key at free");
  exposed = 0;
  probe = Allocate(kSecret.size(), nullptr, 0);
  std::memcpy(probe, kSecret.data(), kSecret.size());
  OPENSSL_cleanse(probe, kSecret.size());
  Release(probe, nullptr, 0);
  Check(exposed == 0, "negative observer control accepts a wiped allocation");
  const Bytes info{1, 2, 3};
  Check(provider->Sm3Mac(kSecret, info).size() == 32 && exposed == 0,
        "control: OpenSSL's HMAC key storage is already cleansed");
  observing = false;

  const std::string_view mode = argc == 3 ? argv[2] : "all";
  Check(mode == "all" || mode == "success" || mode == "failure" || mode == "exception",
        "known test mode");
  size_t cases = 0;
  if (mode == "all" || mode == "success") {
    for (size_t length : {1u, 31u, 32u, 33u, 64u, 255u, 8160u}) {
      for (const auto& context : {Bytes{1}, info}) {
        const auto expected = ExpandOracle(*provider, context, length);
        Bytes input(kSecret.begin(), kSecret.end());
        observing = true;
        const auto actual = provider->Sm3Expand(input, context, length);
        observing = false;
        if (actual != expected)
          std::fprintf(stderr, "HKDF case output=%zu info=%zu returned=%zu expected=%zu\n",
                       length, context.size(), actual.size(), expected.size());
        Check(actual == expected, "cleanup preserves HKDF output across block boundaries");
        Check(input == Bytes(kSecret.begin(), kSecret.end()), "caller-owned PRK is unchanged");
        Check(exposed == 0, "successful derivation erases all freed copies of PRK");
        ++cases;
      }
    }
  }
  if (mode == "all" || mode == "failure") {
    for (size_t length : {0u, 8161u}) {
      observing = true;
      const auto actual = provider->Sm3Expand(kSecret, info, length);
      observing = false;
      Check(actual.empty(), "zero or excessive output length is rejected");
      Check(exposed == 0, "failed derivation erases all freed copies of PRK");
      ++cases;
    }
  }
  if (mode == "all" || mode == "exception") {
    bool threw = false;
    fail_cpp_allocation_size = 819;
    observing = true;
    try {
      provider->Sm3Expand(kSecret, info, 819);
    } catch (const std::bad_alloc&) {
      threw = true;
    }
    observing = false;
    Check(threw && fail_cpp_allocation_size == 0, "output-allocation exception was exercised");
    Check(exposed == 0, "exception unwinding erases the already-allocated parameter PRK");
    ++cases;
  }
  std::printf("SM3 parameter erasure: %zu cases and 3 observer controls passed\n", cases);
  return 0;
}
