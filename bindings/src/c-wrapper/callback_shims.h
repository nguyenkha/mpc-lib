#pragma once

#include "mpc_cosigner_c_api.h"

#include "cosigner/platform_service.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cmp_setup_service.h"
#include "cosigner/cmp_ecdsa_online_signing_service.h"
#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/eddsa_online_signing_service.h"
#include "cosigner/cmp_offline_refresh_service.h"
#include "cosigner/cmp_signature_preprocessed_data.h"

namespace mpc_bindings {

using namespace fireblocks::common::cosigner;

// ============================================================================
// Platform service shim
// ============================================================================

class platform_service_shim : public platform_service {
public:
    explicit platform_service_shim(const mpc_platform_callbacks_t& cbs);
    ~platform_service_shim() override = default;

    void gen_random(size_t len, uint8_t* random_data) const override;
    const std::string get_current_tenantid() const override;
    uint64_t get_id_from_keyid(const std::string& key_id) const override;
    void derive_initial_share(const share_derivation_args& derive_from,
        cosigner_sign_algorithm algorithm,
        elliptic_curve256_scalar_t* key) const override;
    byte_vector_t encrypt_for_player(uint64_t id,
        const byte_vector_t& data) const override;
    byte_vector_t decrypt_message(
        const byte_vector_t& encrypted_data) const override;
    bool backup_key(const std::string& key_id,
        cosigner_sign_algorithm algorithm,
        const elliptic_curve256_scalar_t& private_key,
        const cmp_key_metadata& metadata,
        const auxiliary_keys& aux) override;
    void on_start_signing(const std::string& key_id,
        const std::string& txid, const signing_data& data,
        const std::string& metadata_json,
        const std::set<std::string>& players,
        const signing_type signature_type) override;
    void fill_signing_info_from_metadata(const std::string& metadata,
        std::vector<uint32_t>& flags) const override;
    bool is_client_id(uint64_t player_id) const override;
    uint64_t now_msec() const override;

private:
    mpc_platform_callbacks_t _cbs;
};

// ============================================================================
// Key persistency shim
// ============================================================================

class key_persistency_shim : public cmp_key_persistency {
public:
    explicit key_persistency_shim(const mpc_key_persistency_callbacks_t& cbs);
    ~key_persistency_shim() override = default;

    bool key_exist(const std::string& key_id) const override;
    void load_key(const std::string& key_id,
        cosigner_sign_algorithm& algorithm,
        elliptic_curve256_scalar_t& private_key) const override;
    const std::string get_tenantid_from_keyid(
        const std::string& key_id) const override;
    void load_key_metadata(const std::string& key_id,
        cmp_key_metadata& metadata, bool full_load) const override;
    void load_auxiliary_keys(const std::string& key_id,
        auxiliary_keys& aux) const override;

protected:
    mpc_key_persistency_callbacks_t _cbs;
};

// ============================================================================
// Setup key persistency shim
// ============================================================================

class setup_key_persistency_shim : public cmp_setup_service::setup_key_persistency {
public:
    explicit setup_key_persistency_shim(
        const mpc_setup_persistency_callbacks_t& cbs);
    ~setup_key_persistency_shim() override = default;

    // From cmp_key_persistency
    bool key_exist(const std::string& key_id) const override;
    void load_key(const std::string& key_id,
        cosigner_sign_algorithm& algorithm,
        elliptic_curve256_scalar_t& private_key) const override;
    const std::string get_tenantid_from_keyid(
        const std::string& key_id) const override;
    void load_key_metadata(const std::string& key_id,
        cmp_key_metadata& metadata, bool full_load) const override;
    void load_auxiliary_keys(const std::string& key_id,
        auxiliary_keys& aux) const override;

    // From setup_key_persistency
    void store_key(const std::string& key_id,
        cosigner_sign_algorithm algorithm,
        const elliptic_curve256_scalar_t& private_key,
        uint64_t ttl) override;
    void store_key_metadata(const std::string& key_id,
        const cmp_key_metadata& metadata, bool allow_override) override;
    void store_auxiliary_keys(const std::string& key_id,
        const auxiliary_keys& aux) override;
    void store_keyid_tenant_id(const std::string& key_id,
        const std::string& tenant_id) override;
    void store_setup_data(const std::string& key_id,
        const setup_data& metadata) override;
    void load_setup_data(const std::string& key_id,
        setup_data& metadata) override;
    void store_setup_commitments(const std::string& key_id,
        const std::map<uint64_t, commitment>& commitments) override;
    void load_setup_commitments(const std::string& key_id,
        std::map<uint64_t, commitment>& commitments) override;
    void delete_temporary_key_data(const std::string& key_id,
        bool delete_key) override;

private:
    mpc_setup_persistency_callbacks_t _cbs;
};

// ============================================================================
// ECDSA signing persistency shim
// ============================================================================

class ecdsa_signing_persistency_shim
    : public cmp_ecdsa_online_signing_service::signing_persistency {
public:
    explicit ecdsa_signing_persistency_shim(
        const mpc_ecdsa_signing_persistency_callbacks_t& cbs);
    ~ecdsa_signing_persistency_shim() override = default;

    void store_cmp_signing_data(const std::string& txid,
        const cmp_signing_metadata& data) override;
    void load_cmp_signing_data(const std::string& txid,
        cmp_signing_metadata& data) const override;
    void update_cmp_signing_data(const std::string& txid,
        const cmp_signing_metadata& data) override;
    void delete_temporary_signing_data(const std::string& txid) override;

private:
    mpc_ecdsa_signing_persistency_callbacks_t _cbs;
};

// ============================================================================
// EdDSA signing persistency shim
// ============================================================================

class eddsa_signing_persistency_shim
    : public eddsa_online_signing_service::signing_persistency {
public:
    explicit eddsa_signing_persistency_shim(
        const mpc_eddsa_signing_persistency_callbacks_t& cbs);
    ~eddsa_signing_persistency_shim() override = default;

    void store_signing_data(const std::string& txid,
        const eddsa_signing_metadata& data) override;
    void load_signing_data(const std::string& txid,
        eddsa_signing_metadata& data) const override;
    void update_signing_data(const std::string& txid,
        const eddsa_signing_metadata& data) override;
    void store_signing_commitments(const std::string& txid,
        const std::map<uint64_t, std::vector<commitment>>& commitments) override;
    void load_signing_commitments(const std::string& txid,
        std::map<uint64_t, std::vector<commitment>>& commitments) override;
    void delete_temporary_signing_data(const std::string& txid) override;

private:
    mpc_eddsa_signing_persistency_callbacks_t _cbs;
};

// ============================================================================
// Preprocessing persistency shim
// ============================================================================

class preprocessing_persistency_shim
    : public cmp_ecdsa_offline_signing_service::preprocessing_persistency {
public:
    explicit preprocessing_persistency_shim(
        const mpc_preprocessing_persistency_callbacks_t& cbs);
    ~preprocessing_persistency_shim() override = default;

    void store_preprocessing_metadata(const std::string& request_id,
        const preprocessing_metadata& data, bool override_flag) override;
    void load_preprocessing_metadata(const std::string& request_id,
        preprocessing_metadata& data) const override;
    void store_preprocessing_data(const std::string& request_id,
        uint64_t index, const ecdsa_preprocessing_data& data) override;
    void load_preprocessing_data(const std::string& request_id,
        uint64_t index, ecdsa_preprocessing_data& data) const override;
    void delete_preprocessing_data(const std::string& request_id) override;
    void create_preprocessed_data(const std::string& key_id,
        uint64_t size) override;
    void store_preprocessed_data(const std::string& key_id,
        uint64_t index,
        const cmp_signature_preprocessed_data& data) override;
    void load_preprocessed_data(const std::string& key_id,
        uint64_t index,
        cmp_signature_preprocessed_data& data) override;
    void delete_preprocessed_data(const std::string& key_id) override;

private:
    mpc_preprocessing_persistency_callbacks_t _cbs;
};

// ============================================================================
// Refresh key persistency shim
// ============================================================================

class refresh_key_persistency_shim
    : public cmp_offline_refresh_service::offline_refresh_key_persistency {
public:
    explicit refresh_key_persistency_shim(
        const mpc_refresh_persistency_callbacks_t& cbs);
    ~refresh_key_persistency_shim() override = default;

    void load_refresh_key_seeds(const std::string& request_id,
        std::map<uint64_t, byte_vector_t>& player_id_to_seed) const override;
    void store_refresh_key_seeds(const std::string& request_id,
        const std::map<uint64_t, byte_vector_t>& player_id_to_seed) override;
    void transform_preprocessed_data_and_store_temporary(
        const std::string& key_id, const std::string& request_id,
        const cmp_offline_refresh_service::preprocessed_data_handler& fn) override;
    void commit(const std::string& key_id,
        const std::string& request_id) override;
    void delete_refresh_key_seeds(const std::string& request_id) override;
    void delete_temporary_key(const std::string& key_id) override;
    void store_temporary_key(const std::string& key_id,
        cosigner_sign_algorithm algorithm,
        const elliptic_curve_scalar& private_key) override;

private:
    mpc_refresh_persistency_callbacks_t _cbs;
};

// ============================================================================
// Service holder structs (stored behind mpc_handle_t)
// ============================================================================

struct setup_service_holder {
    platform_service_shim platform;
    setup_key_persistency_shim persistency;
    cmp_setup_service service;

    setup_service_holder(const mpc_platform_callbacks_t& p,
                         const mpc_setup_persistency_callbacks_t& k)
        : platform(p), persistency(k), service(platform, persistency) {}
};

struct ecdsa_online_holder {
    platform_service_shim platform;
    key_persistency_shim key_persistency;
    ecdsa_signing_persistency_shim signing_persistency;
    cmp_ecdsa_online_signing_service service;

    ecdsa_online_holder(const mpc_platform_callbacks_t& p,
                        const mpc_key_persistency_callbacks_t& k,
                        const mpc_ecdsa_signing_persistency_callbacks_t& s)
        : platform(p), key_persistency(k), signing_persistency(s),
          service(platform, key_persistency, signing_persistency) {}
};

struct ecdsa_offline_holder {
    platform_service_shim platform;
    key_persistency_shim key_persistency;
    preprocessing_persistency_shim preprocessing_persistency;
    cmp_ecdsa_offline_signing_service service;

    ecdsa_offline_holder(const mpc_platform_callbacks_t& p,
                         const mpc_key_persistency_callbacks_t& k,
                         const mpc_preprocessing_persistency_callbacks_t& pp)
        : platform(p), key_persistency(k), preprocessing_persistency(pp),
          service(platform, key_persistency, preprocessing_persistency) {}
};

struct eddsa_online_holder {
    platform_service_shim platform;
    key_persistency_shim key_persistency;
    eddsa_signing_persistency_shim signing_persistency;
    eddsa_online_signing_service service;

    eddsa_online_holder(const mpc_platform_callbacks_t& p,
                        const mpc_key_persistency_callbacks_t& k,
                        const mpc_eddsa_signing_persistency_callbacks_t& s)
        : platform(p), key_persistency(k), signing_persistency(s),
          service(platform, key_persistency, signing_persistency) {}
};

struct refresh_holder {
    platform_service_shim platform;
    key_persistency_shim key_persistency;
    refresh_key_persistency_shim refresh_persistency;
    cmp_offline_refresh_service service;

    refresh_holder(const mpc_platform_callbacks_t& p,
                   const mpc_key_persistency_callbacks_t& k,
                   const mpc_refresh_persistency_callbacks_t& r)
        : platform(p), key_persistency(k), refresh_persistency(r),
          service(platform, key_persistency, refresh_persistency) {}
};

} // namespace mpc_bindings
