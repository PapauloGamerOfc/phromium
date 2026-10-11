// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/pinning.h"

#include <limits>
#include <map>
#include <mutex>
#include <utility>

#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net::httpps {
namespace {

void Append(Bytes* output, ByteSpan value) {
  output->insert(output->end(), value.begin(), value.end());
}

std::string Scope(std::string hostname, uint16_t port,
                  const std::string& partition) {
  if (!ValidServiceIdentity(hostname) || !port || partition.empty() ||
      partition.size() > 65535)
    return {};
  for (char& value : hostname) {
    if (value >= 'A' && value <= 'Z')
      value = static_cast<char>(value + ('a' - 'A'));
  }
  // Hostnames cannot contain NUL, and port has an exact width. Partition is an
  // opaque, length-delimited remainder; separators inside it cannot alias keys.
  hostname.push_back('\0');
  hostname.push_back(static_cast<char>(port >> 8));
  hostname.push_back(static_cast<char>(port));
  return hostname + partition;
}

size_t Read16(ByteSpan value) {
  return (size_t{value[0]} << 8) | value[1];
}

uint32_t Read32(ByteSpan value) {
  return (uint32_t{value[0]} << 24) | (uint32_t{value[1]} << 16) |
         (uint32_t{value[2]} << 8) | value[3];
}

Bytes Derive(uint16_t suite, ByteSpan root, std::string_view label,
             ByteSpan transcript, const NativeProvider* provider) {
  return SuiteLabel(suite, root, label, SuiteHash(suite, transcript, provider),
                    SuiteHashLength(suite), provider);
}

}  // namespace

struct PinEntry {
  Bytes ticket;
  Bytes secret;
  int64_t expires = 0;
  size_t AccountedSize(const std::string& key) const {
    return key.size() + ticket.size() + secret.size() + 256;
  }
  ~PinEntry() { OPENSSL_cleanse(secret.data(), secret.size()); }
};

struct PinStore {
  size_t capacity;
  size_t max_bytes;
  size_t retained_bytes = 0;
  std::function<int64_t()> clock;
  std::mutex mutex;
  std::map<std::string, std::shared_ptr<const PinEntry>> pins;
};

PinningCache::PinningCache(size_t capacity, std::function<int64_t()> clock,
                         size_t max_bytes)
    : store_(std::make_shared<PinStore>()) {
  store_->capacity = capacity;
  store_->max_bytes = max_bytes;
  store_->clock = std::move(clock);
}
PinningCache::~PinningCache() = default;

std::shared_ptr<PinAttempt> PinningCache::Begin(std::string hostname,
    uint16_t port, std::string partition) {
  auto key = Scope(std::move(hostname), port, partition);
  if (key.empty() || !store_->capacity || !store_->max_bytes || !store_->clock)
    return nullptr;
  std::lock_guard lock(store_->mutex);
  auto found = store_->pins.find(key);
  if (found != store_->pins.end() && store_->clock() >= found->second->expires) {
    store_->retained_bytes -= found->second->AccountedSize(found->first);
    store_->pins.erase(found);
    found = store_->pins.end();
  }
  auto previous = found == store_->pins.end() ? nullptr : found->second;
  return std::shared_ptr<PinAttempt>(
      new PinAttempt(store_, std::move(key), std::move(previous)));
}

bool PinningCache::Forget(std::string hostname, uint16_t port,
    std::string partition, bool trusted_recovery) {
  auto key = Scope(std::move(hostname), port, partition);
  if (!trusted_recovery || key.empty())
    return false;
  std::lock_guard lock(store_->mutex);
  auto found = store_->pins.find(key);
  if (found != store_->pins.end()) {
    store_->retained_bytes -= found->second->AccountedSize(found->first);
    store_->pins.erase(found);
  }
  return true;
}

PinAttempt::PinAttempt(std::shared_ptr<PinStore> store, std::string key,
    std::shared_ptr<const PinEntry> previous)
    : store_(std::move(store)), key_(std::move(key)),
      previous_(std::move(previous)) {}
PinAttempt::~PinAttempt() = default;

Bytes PinAttempt::extension() const {
  if (!previous_)
    return {};
  Bytes result{static_cast<uint8_t>(previous_->ticket.size() >> 8),
               static_cast<uint8_t>(previous_->ticket.size())};
  Append(&result, previous_->ticket);
  return result;
}

bool PinAttempt::had_pin() const { return previous_ != nullptr; }

bool PinAttempt::Verify(std::optional<ByteSpan> server_extension,
    uint16_t suite, ByteSpan handshake_secret, ByteSpan transcript_through_sh,
    ByteSpan effective_spki, const NativeProvider* provider) {
  if (used_ || completed_)
    return false;
  used_ = true;  // A failed attempt cannot be retried with another response.
  const auto hash_length = SuiteHashLength(suite);
  Secret public_key;
  if ((hash_length != 32 && hash_length != 48) ||
      handshake_secret.size() != hash_length ||
      !ExtractRawPublicKey(effective_spki, &public_key))
    return false;
  if (!server_extension) {
    verified_ = !previous_;
    return verified_;
  }
  auto data = *server_extension;
  if (data.size() < 7)
    return false;
  const size_t proof_size = data[0];
  const size_t cursor = 1 + proof_size;
  if (cursor + 6 > data.size())
    return false;
  const size_t ticket_size = Read16(data.subspan(cursor, 2u));
  if (cursor + 2 + ticket_size + 4 != data.size())
    return false;
  const uint32_t lifetime = Read32(data.last(4u));
  if (!ticket_size && lifetime)
    return false;
  auto proof = data.subspan(1u, proof_size);
  if (!previous_) {
    if (!proof.empty())
      return false;
  } else {
    auto proof_secret = Derive(suite, handshake_secret, "pinning proof 1",
                               transcript_through_sh, provider);
    Bytes proof_input;
    Append(&proof_input, StringBytes("pinning proof 2"));
    Append(&proof_input, proof_secret);
    Append(&proof_input, SuiteHash(suite, effective_spki, provider));
    auto expected = SuiteMac(suite, previous_->secret, proof_input, provider);
    const bool valid = expected.size() == hash_length &&
        proof.size() == expected.size() &&
        CRYPTO_memcmp(proof.data(), expected.data(), expected.size()) == 0;
    OPENSSL_cleanse(proof_secret.data(), proof_secret.size());
    OPENSSL_cleanse(proof_input.data(), proof_input.size());
    OPENSSL_cleanse(expected.data(), expected.size());
    if (!valid)
      return false;
  }
  if (ticket_size && lifetime) {
    auto replacement = std::make_shared<PinEntry>();
    auto ticket = data.subspan(cursor + 2, ticket_size);
    replacement->ticket.assign(ticket.begin(), ticket.end());
    replacement->secret = Derive(suite, handshake_secret, "pinning secret",
                                 transcript_through_sh, provider);
    if (replacement->secret.size() != hash_length)
      return false;
    const int64_t now = store_->clock();
    const int64_t milliseconds = int64_t{lifetime} * 1000;
    if (now > std::numeric_limits<int64_t>::max() - milliseconds)
      return false;
    replacement->expires = now + milliseconds;
    replacement_ = std::move(replacement);
  }
  supported_ = verified_ = true;
  return true;
}

bool PinAttempt::Commit() {
  if (!verified_ || completed_)
    return false;
  completed_ = true;
  if (!supported_)
    return true;
  std::lock_guard lock(store_->mutex);
  auto found = store_->pins.find(key_);
  auto current = found == store_->pins.end() ? nullptr : found->second;
  if (current != previous_)
    return true;  // A newer parallel authenticated exchange wins.
  if (!replacement_) {
    if (current)
      store_->retained_bytes -= current->AccountedSize(key_);
    store_->pins.erase(key_);
    return true;
  }
  const size_t replaced_bytes = current ? current->AccountedSize(key_) : 0;
  const size_t required_bytes = replacement_->AccountedSize(key_);
  if ((!current && store_->pins.size() >= store_->capacity) ||
      required_bytes > store_->max_bytes - (store_->retained_bytes - replaced_bytes)) {
    const int64_t now = store_->clock();
    for (auto it = store_->pins.begin(); it != store_->pins.end();) {
      // Keep this exchange's snapshot while accounting a replacement below.
      if (it->first != key_ && now >= it->second->expires) {
        store_->retained_bytes -= it->second->AccountedSize(it->first);
        it = store_->pins.erase(it);
      } else {
        ++it;
      }
    }
    if ((!current && store_->pins.size() >= store_->capacity) ||
        required_bytes > store_->max_bytes - (store_->retained_bytes - replaced_bytes))
      return false;  // Keep all live pins, never silently downgrade continuity.
  }
  store_->retained_bytes = store_->retained_bytes - replaced_bytes + required_bytes;
  store_->pins[key_] = replacement_;
  return true;
}

}  // namespace net::httpps
