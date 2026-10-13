// Isolated OpenSSL-allocation observer. These hooks are never installed in the
// browser or in the normal interoperability driver, and read only live memory.
#include "net/httpps/native_provider.h"
#include "net/httpps/pinning.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <limits>
#include <string>
#include <string_view>

#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"

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
using net::httpps::ByteSpan;

// All bytes are public test fixtures, not real credentials.
constexpr std::array<uint8_t, 32> kSecret = {
    0x93,0x67,0x2b,0x10,0x54,0x8c,0xde,0x71,0xa3,0x4d,0x96,0x2e,0xff,0x18,0x25,0x07,
    0xc9,0x6a,0xb4,0x41,0x33,0x89,0x12,0xf5,0x68,0x02,0x9f,0x6d,0x44,0xea,0x78,0xbc};
struct Allocation { void* pointer = nullptr; size_t size = 0; };
std::array<Allocation, 16384> allocations;
bool observing = false;
size_t exposed = 0;
size_t fail_cpp_allocation_size = 0;
// Binder failures need a separate C++-allocation observer: the temporary
// early/binder/Finished keys belong to vectors, not OpenSSL's allocator.
std::array<Allocation, 2048> cpp_allocations;
std::array<std::array<uint8_t, 32>, 3> binder_patterns;
bool observing_binder = false;
bool injecting_provider = false;
size_t binder_exposed = 0;
size_t provider_calls = 0;
size_t fail_provider_call = 0;

bool RejectProviderAllocation() {
  if (!observing_binder && !injecting_provider) return false;
  ++provider_calls;
  return fail_provider_call && provider_calls == fail_provider_call;
}

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
  if (RejectProviderAllocation()) return nullptr;
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

void ReleaseCpp(void* pointer) {
  if (observing_binder && pointer) {
    for (auto& entry : cpp_allocations) {
      if (entry.pointer != pointer) continue;
      const auto* bytes = static_cast<const uint8_t*>(pointer);
      for (const auto& pattern : binder_patterns) {
        if (entry.size < pattern.size()) continue;
        for (size_t offset = 0; offset <= entry.size - pattern.size(); ++offset) {
          if (!std::memcmp(bytes + offset, pattern.data(), pattern.size())) {
            ++binder_exposed;
            break;
          }
        }
      }
      entry = {};
      break;
    }
  }
  std::free(pointer);  // The observer above reads only still-live allocations.
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

Bytes TestFrame(uint8_t type, ByteSpan body) {
  Bytes result{type, static_cast<uint8_t>(body.size() >> 16),
      static_cast<uint8_t>(body.size() >> 8), static_cast<uint8_t>(body.size())};
  result.insert(result.end(), body.begin(), body.end());
  return result;
}

Bytes ClientRequest() {
  net::httpps::Secret key{}, share{};
  key.fill(0x29);
  X25519_public_from_private(share.data(), key.data());
  Bytes body{1, 7, 0, 44, 0, 50, 0, 4, 0, 2, 8, 7, 0xff, 3, 0, 32};
  body.insert(body.end(), share.begin(), share.end());
  return TestFrame(13, body);
}

template <class F> bool Fault(size_t allocation, F&& operation) {
  provider_calls = 0;
  fail_provider_call = allocation;
  injecting_provider = true;
  const bool result = operation();
  injecting_provider = false;
  fail_provider_call = 0;
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
  if (void* pointer = std::calloc(size ? size : 1, 1)) {
    if (observing_binder) {
      bool registered = false;
      for (auto& entry : cpp_allocations) {
        if (!entry.pointer) {
          entry = {pointer, size};
          registered = true;
          break;
        }
      }
      Check(registered, "binder observer tracks all C++ allocations");
    }
    return pointer;
  }
  throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { ReleaseCpp(pointer); }
void operator delete(void* pointer, size_t) noexcept { ReleaseCpp(pointer); }

namespace net::httpps {
class ProtocolRegressionPeer {
 public:
  static void Prepare(Client& client, const std::shared_ptr<NativeProvider>& provider) {
    client.suite_ = client.early_suite_ = 0x00c6;
    client.state_ = Client::State::kEstablished;
    client.deadline_milliseconds_ = std::numeric_limits<int64_t>::max();
    client.s_hs_ = Bytes(32, 0x69);
    client.c_hs_ = client.c_app_ = Bytes(32, 0x23);
    client.root_ = Bytes(32, 0x31);
    client.exporter_ = client.early_exporter_ = Bytes(32, 0x45);
    client.transcript_ = client.initial_transcript_ = Bytes(80, 0x54);
    client.sender_ = std::make_unique<RecordCipher>(client.c_app_, 0x00c6, provider);
    client.post_handshake_auth_offered_ = true;
  }

  static bool Finished(const std::shared_ptr<NativeProvider>& provider,
                       size_t failure, Bytes* result) {
    ClientOptions options; options.native_provider = provider;
    Client client("example.test", {}, false, options);
    Prepare(client, provider);
    return Fault(failure, [&] {
      *result = client.Finished(client.s_hs_, client.transcript_);
      return result->size() == 32;
    });
  }

  static bool VerifyFinished(const std::shared_ptr<NativeProvider>& provider,
                             ByteSpan proof, size_t failure, Bytes* result) {
    ClientOptions options; options.native_provider = provider;
    Client client("example.test", {}, false, options);
    Prepare(client, provider);
    client.state_ = Client::State::kFinished;
    const auto frame = TestFrame(20, proof);
    const bool ok = Fault(failure, [&] { return client.AcceptFrame(frame); });
    if (ok) {
      *result = client.TakeOutput();
      for (const auto* secret : {&client.c_app_, &client.s_app_, &client.exporter_, &client.resumption_})
        result->insert(result->end(), secret->begin(), secret->end());
    } else {
      Check(client.state_ == Client::State::kFailed, "Finished failure is terminal");
      result->clear();
    }
    return ok;
  }

  static bool Export(const std::shared_ptr<NativeProvider>& provider, bool early,
                     size_t length, size_t failure, Bytes* result) {
    ClientOptions options; options.native_provider = provider;
    Client client("example.test", {}, false, options);
    Prepare(client, provider);
    client.state_ = Client::State::kHello;
    client.offered_psks_.emplace_back();
    *result = Bytes(40, 0x61);
    const bool ok = Fault(failure, [&] {
      // The output intentionally aliases its input context.
      return early ? client.ExportEarly("fixture", *result, length, result)
                   : client.Export("fixture", *result, length, result);
    });
    Check(ok || result->empty(), "export failure clears old output");
    return ok;
  }

  static bool ServerProof(const std::shared_ptr<NativeProvider>& provider,
                          size_t failure, Bytes* result) {
    ClientOptions options; options.native_provider = provider;
    Client client("example.test", {}, false, options);
    Prepare(client, provider);
    client.a_.fill(0x39);
    Secret server{}; server.fill(0x42);
    X25519_public_from_private(client.S_.data(), server.data());
    const bool ok = Fault(failure, [&] { return client.PrepareServerProof(); });
    *result = ok ? client.expected_proof_ : Bytes{};
    return ok;
  }

  static bool Pha(const std::shared_ptr<NativeProvider>& provider,
                  size_t failure, Bytes* result) {
    ClientOptions options; options.native_provider = provider;
    options.post_handshake_auth = true;
    Client client("example.test", {}, false, options);
    Prepare(client, provider);
    const auto request = ClientRequest();
    const bool ok = Fault(failure, [&] { return client.AcceptPostHandshake(request); });
    *result = ok ? client.TakeOutput() : Bytes{};
    return ok;
  }

  static bool ClientAuthenticator(const std::shared_ptr<NativeProvider>& provider,
                                  size_t failure, Bytes* result) {
    ClientOptions options; options.native_provider = provider;
    Client client("example.test", {}, false, options);
    Prepare(client, provider);
    const auto request = ClientRequest();
    return Fault(failure, [&] { return client.AuthenticateClient(request, nullptr, result); });
  }

  static bool VerifyRefusal(const std::shared_ptr<NativeProvider>& provider,
                            bool empty, size_t failure) {
    ClientOptions options; options.native_provider = provider;
    Client client("example.test", {}, false, options);
    Prepare(client, provider);
    Bytes request;
    Check(client.RequestServerAuthenticator(Bytes{7}, {}, &request), "server authenticator request");
    Bytes transcript, key;
    Check(client.AuthenticatorKeys(true, &transcript, &key), "authenticator oracle exporters");
    const auto certificate = TestFrame(11, Bytes{1, 7, 0, 0, 0});
    transcript.insert(transcript.end(), request.begin(), request.end());
    transcript.insert(transcript.end(), certificate.begin(), certificate.end());
    auto proof = SuiteMac(0x00c6, key, SuiteHash(0x00c6, transcript, provider.get()), provider.get());
    Check(proof.size() == 32, "authenticator refusal independent Finished oracle");
    const auto response = TestFrame(20, empty ? Bytes{} : proof);
    bool authenticated = true;
    const bool ok = Fault(failure, [&] {
      return client.ValidateServerAuthenticator(response, {}, &authenticated, request);
    });
    Check(!authenticated, "refusal or invalid authenticator never authenticates identity");
    return ok;
  }

  static bool Bind(const std::shared_ptr<NativeProvider>& provider, int identity,
                   bool retry, size_t failure, Bytes* result) {
    ClientOptions options;
    options.native_provider = provider;
    Client client("example.test", {}, false, options);
    ExternalPSK psk;
    psk.cipher_suite = 0x00c6;
    psk.secret = Bytes(kSecret.begin(), kSecret.end());
    psk.identity = Bytes{1};
    psk.imported = identity == 2;
    client.offered_psks_.push_back(psk);
    if (identity == 1) client.offered_ticket_.emplace();
    Bytes hello(100, 0x13);
    // The helper hashes the exact prefix and truncated CH bytes; full Hello
    // syntax is independently covered by the wire/protocol regression tests.
    const Bytes prefix = retry ? Bytes(72, 0x27) : Bytes{};
    binder_exposed = provider_calls = 0;
    fail_provider_call = failure;
    cpp_allocations = {};
    observing_binder = true;
    const bool accepted = client.BindClientHello(&hello, prefix);
    observing_binder = false;
    fail_provider_call = 0;
    cpp_allocations = {};
    *result = std::move(hello);
    return accepted;
  }
};
}  // namespace net::httpps

namespace {
void BinderErasure(const std::shared_ptr<NativeProvider>& provider) {
  using namespace net::httpps;
  size_t cases = 0, rejections = 0;
  for (int identity : {0, 1, 2}) {
    const std::string_view label = identity == 0 ? "ext binder"
        : identity == 1 ? "res binder" : "imp binder";
    auto early = SuiteMac(0x00c6, Bytes(32), kSecret, provider.get());
    auto binder = SuiteLabel(0x00c6, early, label,
        SuiteHash(0x00c6, {}, provider.get()), 32, provider.get());
    auto finished = SuiteLabel(0x00c6, binder, "finished", {}, 32, provider.get());
    size_t index = 0;
    for (auto* value : {&early, &binder, &finished}) {
      Check(value->size() == 32, "binder erasure oracle derives exact keys");
      std::copy(value->begin(), value->end(), binder_patterns[index++].begin());
      OPENSSL_cleanse(value->data(), value->size());
    }
    for (bool erase : {false, true}) {
      cpp_allocations = {};
      binder_exposed = 0;
      observing_binder = true;
      void* probe = ::operator new(32);
      std::memcpy(probe, binder_patterns[0].data(), 32);
      if (erase) OPENSSL_cleanse(probe, 32);
      ::operator delete(probe);
      observing_binder = false;
      Check(binder_exposed == (erase ? 0u : 1u),
            "C++ observer detects live derived keys and accepts their wiped buffers");
    }
    for (bool retry : {false, true}) {
      Bytes transcript(retry ? 72 : 0, 0x27);
      transcript.insert(transcript.end(), 65, 0x13);
      const auto proof = SuiteMac(0x00c6, binder_patterns[2],
          SuiteHash(0x00c6, transcript, provider.get()), provider.get());
      Check(proof.size() == 32, "independent binder MAC oracle");
      Bytes expected(100, 0x13), actual;
      std::copy(proof.begin(), proof.end(), expected.end() - 32);
      Check(ProtocolRegressionPeer::Bind(provider, identity, retry, 0, &actual) &&
                actual == expected && binder_exposed == 0,
            "successful binders match the oracle and erase their temporary keys");
      const size_t calls = provider_calls;
      Check(calls > 0 && calls < 1024, "bounded native binder fault-injection schedule");
      for (size_t failure = 1; failure <= calls; ++failure) {
        Bytes actual;
        const bool accepted = ProtocolRegressionPeer::Bind(provider, identity, retry, failure, &actual);
        rejections += !accepted;
        ++cases;
        Check(binder_exposed == 0, "failed binder derivation erases all temporary keys before free");
        Check(!accepted || actual == expected, "provider failure cannot produce a different successful binder");
      }
    }
  }
  OPENSSL_cleanse(binder_patterns.data(), sizeof(binder_patterns));
  Check(rejections > 0, "provider failures exercise binder rejection, not only successful controls");
  std::printf("Binder erasure: %zu injected allocations, %zu rejections, 6 successful controls passed\n",
              cases, rejections);
}

template <class F> size_t CheckFaults(const char* name, F&& operation,
                                     const Bytes* oracle = nullptr) {
  Bytes expected;
  Check(operation(0, &expected), name);
  const size_t calls = provider_calls;
  Check(calls > 0 && calls < 8192, "bounded dynamic provider fault schedule");
  Check(!oracle || expected == *oracle, "healthy result matches independent oracle");
  size_t rejected = 0;
  for (size_t failure = 1; failure <= calls; ++failure) {
    Bytes actual;
    const bool ok = operation(failure, &actual);
    rejected += !ok;
    Check(!ok || actual == expected, name);
  }
  Check(rejected > 0, "each provider chain actually rejects injected failures");
  std::printf("Provider fail-closed %s: %zu allocations, %zu rejections\n", name, calls, rejected);
  return calls;
}

Bytes PinReply(ByteSpan proof) {
  Bytes reply{static_cast<uint8_t>(proof.size())};
  reply.insert(reply.end(), proof.begin(), proof.end());
  reply.insert(reply.end(), {0, 1, 0x43, 0, 0, 0, 100});
  return reply;
}

void FailClosed(const std::shared_ptr<NativeProvider>& provider) {
  using namespace net::httpps;
  const Bytes secret(32, 0x69), transcript(80, 0x54);
  const auto hash = SuiteHash(0x00c6, transcript, provider.get());
  const auto key = SuiteLabel(0x00c6, secret, "finished", {}, 32, provider.get());
  const auto proof = SuiteMac(0x00c6, key, hash, provider.get());
  const auto empty_key_proof = SuiteMac(0x00c6, {}, hash, provider.get());
  const auto empty_hash_proof = SuiteMac(0x00c6, key, {}, provider.get());
  Check(proof.size() == 32 && empty_key_proof.size() == 32 && empty_hash_proof.size() == 32,
        "raw primitive still permits legitimate empty keys/messages");
  CheckFaults("Finished", [&](size_t failure, Bytes* out) {
    return ProtocolRegressionPeer::Finished(provider, failure, out);
  }, &proof);
  const size_t handshake_calls = CheckFaults("handshake Finished and application keys", [&](size_t failure, Bytes* out) {
    return ProtocolRegressionPeer::VerifyFinished(provider, proof, failure, out);
  });
  for (const auto& invalid : {empty_key_proof, empty_hash_proof}) {
    for (size_t failure = 0; failure <= handshake_calls; ++failure) {
      Bytes out;
      Check(!ProtocolRegressionPeer::VerifyFinished(provider, invalid, failure, &out),
            "state machine rejects Finished derived with missing key or transcript hash");
    }
  }
  for (bool early : {false, true}) {
    for (size_t length : {0u, 1u, 32u, 64u}) {
      const auto derived = SuiteLabel(0x00c6, Bytes(32, 0x45), "fixture",
          SuiteHash(0x00c6, {}, provider.get()), 32, provider.get());
      const auto expected = SuiteLabel(0x00c6, derived, "exporter",
          SuiteHash(0x00c6, Bytes(40, 0x61), provider.get()), length, provider.get());
      CheckFaults(early ? "early exporter" : "exporter", [&](size_t failure, Bytes* out) {
        return ProtocolRegressionPeer::Export(provider, early, length, failure, out);
      }, &expected);
    }
  }
  CheckFaults("server CertificateVerify", [&](size_t failure, Bytes* out) {
    return ProtocolRegressionPeer::ServerProof(provider, failure, out);
  });
  CheckFaults("post-handshake client Finished", [&](size_t failure, Bytes* out) {
    return ProtocolRegressionPeer::Pha(provider, failure, out);
  });
  CheckFaults("client exported authenticator refusal", [&](size_t failure, Bytes* out) {
    return ProtocolRegressionPeer::ClientAuthenticator(provider, failure, out);
  });
  Check(ProtocolRegressionPeer::VerifyRefusal(provider, false, 0), "healthy server authenticator refusal");
  const size_t refusal_calls = provider_calls;
  size_t refusal_rejected = 0;
  for (size_t failure = 0; failure <= refusal_calls; ++failure) {
    Check(!ProtocolRegressionPeer::VerifyRefusal(provider, true, failure),
          "empty Finished is never accepted during a provider failure");
    if (failure) refusal_rejected += !ProtocolRegressionPeer::VerifyRefusal(provider, false, failure);
  }
  Check(refusal_rejected > 0, "valid refusal verification rejects injected crypto failures");
  std::printf("Provider fail-closed server exported authenticator: %zu allocations, %zu rejections\n",
              refusal_calls, refusal_rejected);

  Secret private_key{}, public_key{};
  private_key.fill(0x29);
  X25519_public_from_private(public_key.data(), private_key.data());
  Bytes spki{0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 3, 0x21, 0};
  spki.insert(spki.end(), public_key.begin(), public_key.end());
  const Bytes root(32, 0x31), pin_transcript(80, 0x54);
  const auto pin_hash = SuiteHash(0x00c6, pin_transcript, provider.get());
  const auto pin_secret = SuiteLabel(0x00c6, root, "pinning secret", pin_hash, 32, provider.get());
  const auto proof_secret = SuiteLabel(0x00c6, root, "pinning proof 1", pin_hash, 32, provider.get());
  Bytes pin_input(StringBytes("pinning proof 2").begin(), StringBytes("pinning proof 2").end());
  const auto spki_hash = SuiteHash(0x00c6, spki, provider.get());
  Bytes truncated_input = pin_input;
  truncated_input.insert(truncated_input.end(), spki_hash.begin(), spki_hash.end());
  pin_input.insert(pin_input.end(), proof_secret.begin(), proof_secret.end());
  pin_input.insert(pin_input.end(), spki_hash.begin(), spki_hash.end());
  const auto pin_proof = SuiteMac(0x00c6, pin_secret, pin_input, provider.get());
  const auto truncated_proof = SuiteMac(0x00c6, pin_secret, truncated_input, provider.get());
  const auto enroll = PinReply({}), renewal = PinReply(pin_proof), invalid_renewal = PinReply(truncated_proof);
  CheckFaults("pin enrollment", [&](size_t failure, Bytes* out) {
    PinningCache cache(1, [] { return int64_t{1000}; });
    auto first = cache.Begin("example.test", 343, "partition");
    const bool ok = Fault(failure, [&] {
      return first->Verify(ByteSpan(enroll), 0x00c6, root, pin_transcript, spki, provider.get());
    });
    Check(first->Commit() == ok, "failed pin derivation cannot be committed");
    auto next = cache.Begin("example.test", 343, "partition");
    Check(next->had_pin() == ok, "failed enrollment leaves no persistent pin");
    if (ok) Check(next->Verify(ByteSpan(renewal), 0x00c6, root, pin_transcript, spki, provider.get()),
                  "enrolled secret matches independent oracle");
    return ok;
  });
  size_t renewal_calls = CheckFaults("pin renewal", [&](size_t failure, Bytes* out) {
    PinningCache cache(1, [] { return int64_t{1000}; });
    auto first = cache.Begin("example.test", 343, "partition");
    Check(first->Verify(ByteSpan(enroll), 0x00c6, root, pin_transcript, spki, provider.get()) && first->Commit(), "pin fixture enrollment");
    auto next = cache.Begin("example.test", 343, "partition");
    const bool ok = Fault(failure, [&] {
      return next->Verify(ByteSpan(renewal), 0x00c6, root, pin_transcript, spki, provider.get());
    });
    Check(next->Commit() == ok, "failed renewal cannot be committed");
    auto renewed = cache.Begin("example.test", 343, "partition");
    Check(renewed->had_pin() &&
          renewed->Verify(ByteSpan(renewal), 0x00c6, root, pin_transcript, spki, provider.get()),
          "successful renewal or preserved original pin matches independent oracle");
    return ok;
  });
  for (size_t failure = 0; failure <= renewal_calls; ++failure) {
    PinningCache cache(1, [] { return int64_t{1000}; });
    auto first = cache.Begin("example.test", 343, "partition");
    Check(first->Verify(ByteSpan(enroll), 0x00c6, root, pin_transcript, spki, provider.get()) && first->Commit(), "negative pin fixture enrollment");
    auto next = cache.Begin("example.test", 343, "partition");
    Check(!Fault(failure, [&] {
      return next->Verify(ByteSpan(invalid_renewal), 0x00c6, root, pin_transcript, spki, provider.get());
    }) && !next->Commit(), "truncated pin proof cannot become valid after a provider failure");
  }
}
}  // namespace

int main(int argc, char** argv) {
  Check(argc == 2 || argc == 3, "usage: provider_erasure_test absolute-provider [success|failure|exception|binders|chains]");
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
  Check(mode == "all" || mode == "success" || mode == "failure" || mode == "exception" || mode == "binders" || mode == "chains",
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
  if (mode == "all" || mode == "binders") BinderErasure(provider);
  if (mode == "all" || mode == "chains") FailClosed(provider);
  return 0;
}
