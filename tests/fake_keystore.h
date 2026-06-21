// InMemoryKeyStore: a faithful std::map-backed KeyStore so the enroll/rotate
// engines are testable with no DB. The one-txn methods mutate maps atomically
// (build the new state, then swap). Raw state is exposed for assertions.
#pragma once
#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "sharing/rewrap.h"

namespace tf {

class InMemoryKeyStore final : public pwmgr::sharing::KeyStore {
 public:
  using Device = pwmgr::db::Device;
  using Entry = pwmgr::db::Entry;
  using WrappedKey = pwmgr::db::WrappedKey;

  // ---- seeding / raw state (public on purpose: tests assert on it) ----
  std::map<std::int64_t, Device> devices;                    // by id
  std::map<std::int64_t, Entry> entries;                     // by id
  std::map<std::pair<std::int64_t, std::int64_t>, std::string> wraps;
  std::int64_t next_device_id = 1, next_entry_id = 1;

  std::int64_t seed_device(const std::string& name, const std::string& fpr,
                           const std::string& public_key,
                           const std::string& status = "active") {
    Device d{next_device_id++, name, fpr, public_key, status, "now"};
    devices[d.id] = d;
    return d.id;
  }

  std::size_t wrap_count_for(std::int64_t device_id) const {
    std::size_t n = 0;
    for (const auto& [k, v] : wraps)
      if (k.second == device_id) ++n;
    return n;
  }

  // ---- KeyStore ----
  std::vector<Device> active_devices() override {
    std::vector<Device> out;
    for (const auto& [id, d] : devices)
      if (d.status == "active") out.push_back(d);
    return out;  // map iteration is id-ordered
  }

  std::optional<Device> founding_device() override {
    if (devices.empty()) return std::nullopt;
    return devices.begin()->second;
  }

  std::vector<std::int64_t> all_entry_ids() override {
    std::vector<std::int64_t> out;
    for (const auto& [id, e] : entries) out.push_back(id);
    return out;
  }

  std::vector<std::int64_t> entry_ids_wrapped_for(std::int64_t device_id) override {
    std::vector<std::int64_t> out;
    for (const auto& [k, v] : wraps)
      if (k.second == device_id) out.push_back(k.first);
    std::sort(out.begin(), out.end());
    return out;
  }

  std::vector<std::int64_t> device_ids_for_entry(std::int64_t id) override {
    std::vector<std::int64_t> out;
    for (const auto& [k, v] : wraps) {
      if (k.first != id) continue;
      auto d = devices.find(k.second);
      if (d != devices.end() && d->second.status == "active")
        out.push_back(k.second);
    }
    std::sort(out.begin(), out.end());
    return out;
  }

  std::string wrapped_key_for(std::int64_t id,
                              std::string_view fingerprint) override {
    const std::string fpr =
        pwmgr::db::normalize_fingerprint(fingerprint);
    for (const auto& [did, d] : devices) {
      if (d.fingerprint == fpr && d.status == "active") {
        auto it = wraps.find({id, did});
        if (it != wraps.end()) return it->second;
      }
    }
    auto it = entries.find(id);  // legacy aes_key fallback
    if (it == entries.end())
      throw std::runtime_error("entry " + std::to_string(id) + " gone");
    return it->second.aes_key_armored;
  }

  Entry get_entry(std::int64_t id) override {
    auto it = entries.find(id);
    if (it == entries.end())
      throw std::runtime_error("entry " + std::to_string(id) + " gone");
    return it->second;
  }

  void insert_wrapped_key(std::int64_t id, std::int64_t device_id,
                          std::string_view armored) override {
    wraps.emplace(std::make_pair(id, device_id), std::string(armored));
  }

  std::int64_t insert_entry_with_keys(
      std::string_view blob, std::string_view founding_wrap_armored,
      std::string_view note, int enc_version,
      const std::vector<WrappedKey>& wraps_in) override {
    Entry e{next_entry_id++, std::string(blob), std::string(note),
            std::string(founding_wrap_armored), enc_version};
    entries[e.id] = e;
    for (const auto& w : wraps_in)
      wraps[{e.id, w.device_id}] = w.armored;
    return e.id;
  }

  void replace_entry_keys(std::int64_t id, std::string_view blob,
                          std::string_view founding_wrap_armored,
                          int enc_version,
                          const std::vector<WrappedKey>& wraps_in) override {
    auto it = entries.find(id);
    if (it == entries.end())
      throw std::runtime_error("replace_entry_keys: entry " +
                               std::to_string(id) + " does not exist");
    it->second.password_blob = std::string(blob);
    it->second.aes_key_armored = std::string(founding_wrap_armored);
    it->second.enc_version = enc_version;
    for (auto w = wraps.begin(); w != wraps.end();)
      w = (w->first.first == id) ? wraps.erase(w) : std::next(w);
    for (const auto& w : wraps_in)
      wraps[{id, w.device_id}] = w.armored;
  }
};

}  // namespace tf
