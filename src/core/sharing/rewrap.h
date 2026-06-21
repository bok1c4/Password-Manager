#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "db/device.h"
#include "db/repository.h"

namespace pwmgr::sharing {

using ProgressFn =
    std::function<void(std::size_t done, std::size_t total, const std::string&)>;

// The seam between the enroll/rotate engines and storage: prod wires a
// RepositoryKeyStore, tests an InMemoryKeyStore — so the full multi-device
// lifecycle is provable under plain `make test` with no DB and no real keys.
class KeyStore {
 public:
  virtual ~KeyStore() = default;
  virtual std::vector<db::Device> active_devices() = 0;
  virtual std::optional<db::Device> founding_device() = 0;
  virtual std::vector<std::int64_t> all_entry_ids() = 0;
  // Sorted ascending (the enroll engine binary-searches it).
  virtual std::vector<std::int64_t> entry_ids_wrapped_for(
      std::int64_t device_id) = 0;
  // The active devices that currently hold a wrap for this entry (its recipient
  // set), ascending by id. Lets rotate preserve per-entry membership.
  virtual std::vector<std::int64_t> device_ids_for_entry(std::int64_t id) = 0;
  // Throws if the entry is gone (repo nullopt -> throw).
  virtual std::string wrapped_key_for(std::int64_t id,
                                      std::string_view fingerprint) = 0;
  virtual db::Entry get_entry(std::int64_t id) = 0;
  virtual void insert_wrapped_key(std::int64_t id, std::int64_t device_id,
                                  std::string_view armored) = 0;  // idempotent
  virtual std::int64_t insert_entry_with_keys(
      std::string_view blob, std::string_view founding_wrap_armored,
      std::string_view note, int enc_version,
      const std::vector<db::WrappedKey>& wraps) = 0;  // one txn
  virtual void replace_entry_keys(std::int64_t id, std::string_view blob,
                                  std::string_view founding_wrap_armored,
                                  int enc_version,
                                  const std::vector<db::WrappedKey>& wraps) = 0;
};

// Pure delegation to db::Repository (method names match by design).
class RepositoryKeyStore final : public KeyStore {
 public:
  explicit RepositoryKeyStore(db::Repository& repo) : repo_(&repo) {}
  std::vector<db::Device> active_devices() override {
    return repo_->active_devices();
  }
  std::optional<db::Device> founding_device() override {
    return repo_->founding_device();
  }
  std::vector<std::int64_t> all_entry_ids() override {
    return repo_->all_entry_ids();
  }
  std::vector<std::int64_t> entry_ids_wrapped_for(std::int64_t device_id) override {
    return repo_->entry_ids_wrapped_for(device_id);
  }
  std::vector<std::int64_t> device_ids_for_entry(std::int64_t id) override {
    return repo_->device_ids_for_entry(id);
  }
  std::string wrapped_key_for(std::int64_t id,
                              std::string_view fingerprint) override;
  db::Entry get_entry(std::int64_t id) override;
  void insert_wrapped_key(std::int64_t id, std::int64_t device_id,
                          std::string_view armored) override {
    repo_->insert_wrapped_key(id, device_id, armored);
  }
  std::int64_t insert_entry_with_keys(
      std::string_view blob, std::string_view founding_wrap_armored,
      std::string_view note, int enc_version,
      const std::vector<db::WrappedKey>& wraps) override {
    return repo_->insert_entry_with_keys(blob, founding_wrap_armored, note,
                                         enc_version, wraps);
  }
  void replace_entry_keys(std::int64_t id, std::string_view blob,
                          std::string_view founding_wrap_armored,
                          int enc_version,
                          const std::vector<db::WrappedKey>& wraps) override {
    repo_->replace_entry_keys(id, blob, founding_wrap_armored, enc_version,
                              wraps);
  }

 private:
  db::Repository* repo_;
};

struct RewrapStats {
  std::size_t total = 0, wrapped = 0, skipped = 0;
};
struct RotateStats {
  std::size_t total = 0, rotated = 0, upgraded_v1 = 0;
};

// Imports every device's stored public key into the local keyring and pins
// the result against the stored fingerprint (tamper check on EVERY call —
// import is idempotent). A device with no stored public key passes only if
// its key is already present locally (the founding device on its own box).
void ensure_device_keys_local(const std::vector<db::Device>& devices);

// Enroll engine: for every entry not yet wrapped to `target`, unwrap K with
// my key, wrap K to target, insert the password_keys row. Plaintext passwords
// are never touched — only 32-byte keys, cleansed on every path. Resumable:
// existing (entry, target) pairs skip without any GPG call.
RewrapStats rewrap_all_to_device(KeyStore& store, const db::Device& target,
                                 std::string_view my_fingerprint,
                                 const ProgressFn& progress = {});

// Per-entry grant: make `target` able to read ONE entry (the single-pair core
// of rewrap_all_to_device). Idempotent. The operator must currently be able to
// read the entry (you can only share what you can decrypt). Imports + pins
// target's key first.
void grant_entry_to_device(KeyStore& store, std::string_view my_fingerprint,
                           std::int64_t id, const db::Device& target);

// Rotate ONE entry to EXACTLY `recipients`: fresh K, re-encrypt v2 GCM, wrap to
// the legacy recipient (lowest-id device in the set) + each recipient, replace
// the entry's wraps. The single-entry core of rotate_all; per-entry `revoke`
// calls it with (current set − the removed device). Refuses an empty set (an
// entry with no readers is unrecoverable). Operator must be able to read it.
void rotate_entry(KeyStore& store, std::string_view my_fingerprint,
                  std::int64_t id, std::vector<db::Device> recipients);

// Rotate engine: per entry (one txn each — a crash between entries leaves
// every entry self-consistent): decrypt, fresh K, re-encrypt as v2 GCM, wrap
// K to the legacy recipient (D5: founding-if-active else lowest-id active)
// and every active device, replace the entry's wraps. Also upgrades v1 rows
// to v2 for free. Refuses on zero active devices.
RotateStats rotate_all(KeyStore& store, std::string_view my_fingerprint,
                       const ProgressFn& progress = {});

// Write path: fresh K, v2 GCM, wrap to the legacy recipient (-> aes_key, D5)
// and every active device. With no devices (pre-migration DB) this is
// byte-equivalent to today's single-wrap write: legacy recipient =
// `my_fingerprint`, empty wraps.
std::int64_t store_new_entry(KeyStore& store, std::string_view my_fingerprint,
                             std::string_view plaintext, std::string_view note);
void replace_entry_password(KeyStore& store, std::string_view my_fingerprint,
                            std::int64_t id, std::string_view plaintext);

// Subset write path: like store_new_entry but encrypts to a CHOSEN recipient
// set (group encryption). Legacy aes_key targets the lowest-id device in the
// set, so a device outside the set genuinely cannot read it (no founding
// backdoor). An empty set degrades to the legacy-only write (pre-migration).
std::int64_t store_new_entry_for(KeyStore& store, std::string_view my_fingerprint,
                                 std::string_view plaintext, std::string_view note,
                                 std::vector<db::Device> recipients);

}  // namespace pwmgr::sharing
