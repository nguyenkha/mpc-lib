#include "callback_shims.h"
#include "cosigner/cosigner_exception.h"

#include <cstring>
#include <sstream>
#include <stdexcept>

namespace mpc_bindings {

using namespace fireblocks::common::cosigner;

// ============================================================================
// Platform service shim
// ============================================================================

platform_service_shim::platform_service_shim(const mpc_platform_callbacks_t& cbs)
    : _cbs(cbs) {}

void platform_service_shim::gen_random(size_t len, uint8_t* random_data) const {
    _cbs.gen_random(_cbs.user_ctx, len, random_data);
}

const std::string platform_service_shim::get_current_tenantid() const {
    char buf[256];
    size_t len = _cbs.get_tenant_id(_cbs.user_ctx, buf, sizeof(buf));
    return std::string(buf, len);
}

uint64_t platform_service_shim::get_id_from_keyid(const std::string& key_id) const {
    return _cbs.get_id_from_keyid(_cbs.user_ctx, key_id.c_str());
}

void platform_service_shim::derive_initial_share(
    const share_derivation_args& derive_from,
    cosigner_sign_algorithm algorithm,
    elliptic_curve256_scalar_t* key) const {
    _cbs.derive_initial_share(_cbs.user_ctx,
        derive_from.master_key_id.c_str(),
        derive_from.chaincode.data(), derive_from.chaincode.size(),
        static_cast<int32_t>(algorithm),
        reinterpret_cast<uint8_t*>(key));
}

byte_vector_t platform_service_shim::encrypt_for_player(
    uint64_t id, const byte_vector_t& data) const {
    mpc_buffer_t buf = _cbs.encrypt_for_player(_cbs.user_ctx, id,
        data.data(), data.size());
    byte_vector_t result(buf.data, buf.data + buf.len);
    mpc_free_buffer(&buf);
    return result;
}

byte_vector_t platform_service_shim::decrypt_message(
    const byte_vector_t& encrypted_data) const {
    mpc_buffer_t buf = _cbs.decrypt_message(_cbs.user_ctx,
        encrypted_data.data(), encrypted_data.size());
    byte_vector_t result(buf.data, buf.data + buf.len);
    mpc_free_buffer(&buf);
    return result;
}

bool platform_service_shim::backup_key(
    const std::string& key_id,
    cosigner_sign_algorithm algorithm,
    const elliptic_curve256_scalar_t& private_key,
    const cmp_key_metadata& metadata,
    const auxiliary_keys& aux) {
    // Serialize metadata and aux as opaque blobs
    // For MVP, pass raw bytes of the structs that the JS side stores opaquely
    return _cbs.backup_key(_cbs.user_ctx, key_id.c_str(),
        static_cast<int32_t>(algorithm),
        reinterpret_cast<const uint8_t*>(&private_key),
        reinterpret_cast<const uint8_t*>(&metadata), sizeof(metadata),
        reinterpret_cast<const uint8_t*>(&aux), sizeof(aux)) != 0;
}

void platform_service_shim::on_start_signing(
    const std::string& key_id, const std::string& txid,
    const signing_data& data, const std::string& metadata_json,
    const std::set<std::string>& players,
    const signing_type signature_type) {
    // Serialize players as JSON array
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto& p : players) {
        if (!first) ss << ",";
        ss << "\"" << p << "\"";
        first = false;
    }
    ss << "]";
    std::string players_json = ss.str();

    // Serialize signing_data as opaque buffer
    _cbs.on_start_signing(_cbs.user_ctx, key_id.c_str(), txid.c_str(),
        reinterpret_cast<const uint8_t*>(&data), sizeof(data),
        metadata_json.c_str(), players_json.c_str(),
        static_cast<int32_t>(signature_type));
}

void platform_service_shim::fill_signing_info_from_metadata(
    const std::string& metadata, std::vector<uint32_t>& flags) const {
    _cbs.fill_signing_info(_cbs.user_ctx, metadata.c_str(),
        flags.data(), flags.size());
}

bool platform_service_shim::is_client_id(uint64_t player_id) const {
    return _cbs.is_client_id(_cbs.user_ctx, player_id) != 0;
}

uint64_t platform_service_shim::now_msec() const {
    if (_cbs.now_msec) {
        return _cbs.now_msec(_cbs.user_ctx);
    }
    return 0;
}

// ============================================================================
// Key persistency shim
// ============================================================================

key_persistency_shim::key_persistency_shim(
    const mpc_key_persistency_callbacks_t& cbs) : _cbs(cbs) {}

bool key_persistency_shim::key_exist(const std::string& key_id) const {
    return _cbs.key_exist(_cbs.user_ctx, key_id.c_str()) != 0;
}

void key_persistency_shim::load_key(const std::string& key_id,
    cosigner_sign_algorithm& algorithm,
    elliptic_curve256_scalar_t& private_key) const {
    int32_t algo;
    _cbs.load_key(_cbs.user_ctx, key_id.c_str(), &algo,
        reinterpret_cast<uint8_t*>(&private_key));
    algorithm = static_cast<cosigner_sign_algorithm>(algo);
}

const std::string key_persistency_shim::get_tenantid_from_keyid(
    const std::string& key_id) const {
    char buf[256];
    size_t len = _cbs.get_tenantid_from_keyid(_cbs.user_ctx,
        key_id.c_str(), buf, sizeof(buf));
    return std::string(buf, len);
}

void key_persistency_shim::load_key_metadata(const std::string& key_id,
    cmp_key_metadata& metadata, bool full_load) const {
    mpc_buffer_t buf = _cbs.load_key_metadata(_cbs.user_ctx,
        key_id.c_str(), full_load ? 1 : 0);
    if (buf.data && buf.len >= sizeof(cmp_key_metadata)) {
        memcpy(&metadata, buf.data, sizeof(cmp_key_metadata));
    }
    mpc_free_buffer(&buf);
}

void key_persistency_shim::load_auxiliary_keys(const std::string& key_id,
    auxiliary_keys& aux) const {
    mpc_buffer_t buf = _cbs.load_auxiliary_keys(_cbs.user_ctx,
        key_id.c_str());
    if (buf.data && buf.len >= sizeof(auxiliary_keys)) {
        memcpy(&aux, buf.data, sizeof(auxiliary_keys));
    }
    mpc_free_buffer(&buf);
}

// ============================================================================
// Setup key persistency shim
// ============================================================================

setup_key_persistency_shim::setup_key_persistency_shim(
    const mpc_setup_persistency_callbacks_t& cbs) : _cbs(cbs) {}

bool setup_key_persistency_shim::key_exist(const std::string& key_id) const {
    return _cbs.base.key_exist(_cbs.base.user_ctx, key_id.c_str()) != 0;
}

void setup_key_persistency_shim::load_key(const std::string& key_id,
    cosigner_sign_algorithm& algorithm,
    elliptic_curve256_scalar_t& private_key) const {
    int32_t algo;
    _cbs.base.load_key(_cbs.base.user_ctx, key_id.c_str(), &algo,
        reinterpret_cast<uint8_t*>(&private_key));
    algorithm = static_cast<cosigner_sign_algorithm>(algo);
}

const std::string setup_key_persistency_shim::get_tenantid_from_keyid(
    const std::string& key_id) const {
    char buf[256];
    size_t len = _cbs.base.get_tenantid_from_keyid(_cbs.base.user_ctx,
        key_id.c_str(), buf, sizeof(buf));
    return std::string(buf, len);
}

void setup_key_persistency_shim::load_key_metadata(const std::string& key_id,
    cmp_key_metadata& metadata, bool full_load) const {
    mpc_buffer_t buf = _cbs.base.load_key_metadata(_cbs.base.user_ctx,
        key_id.c_str(), full_load ? 1 : 0);
    if (buf.data && buf.len >= sizeof(cmp_key_metadata)) {
        memcpy(&metadata, buf.data, sizeof(cmp_key_metadata));
    }
    mpc_free_buffer(&buf);
}

void setup_key_persistency_shim::load_auxiliary_keys(const std::string& key_id,
    auxiliary_keys& aux) const {
    mpc_buffer_t buf = _cbs.base.load_auxiliary_keys(_cbs.base.user_ctx,
        key_id.c_str());
    if (buf.data && buf.len >= sizeof(auxiliary_keys)) {
        memcpy(&aux, buf.data, sizeof(auxiliary_keys));
    }
    mpc_free_buffer(&buf);
}

void setup_key_persistency_shim::store_key(const std::string& key_id,
    cosigner_sign_algorithm algorithm,
    const elliptic_curve256_scalar_t& private_key, uint64_t ttl) {
    _cbs.store_key(_cbs.user_ctx, key_id.c_str(),
        static_cast<int32_t>(algorithm),
        reinterpret_cast<const uint8_t*>(&private_key), ttl);
}

void setup_key_persistency_shim::store_key_metadata(const std::string& key_id,
    const cmp_key_metadata& metadata, bool allow_override) {
    _cbs.store_key_metadata(_cbs.user_ctx, key_id.c_str(),
        reinterpret_cast<const uint8_t*>(&metadata), sizeof(metadata),
        allow_override ? 1 : 0);
}

void setup_key_persistency_shim::store_auxiliary_keys(const std::string& key_id,
    const auxiliary_keys& aux) {
    _cbs.store_auxiliary_keys(_cbs.user_ctx, key_id.c_str(),
        reinterpret_cast<const uint8_t*>(&aux), sizeof(aux));
}

void setup_key_persistency_shim::store_keyid_tenant_id(
    const std::string& key_id, const std::string& tenant_id) {
    _cbs.store_keyid_tenant_id(_cbs.user_ctx,
        key_id.c_str(), tenant_id.c_str());
}

void setup_key_persistency_shim::store_setup_data(const std::string& key_id,
    const setup_data& data) {
    _cbs.store_setup_data(_cbs.user_ctx, key_id.c_str(),
        reinterpret_cast<const uint8_t*>(&data), sizeof(data));
}

void setup_key_persistency_shim::load_setup_data(const std::string& key_id,
    setup_data& data) {
    mpc_buffer_t buf = _cbs.load_setup_data(_cbs.user_ctx, key_id.c_str());
    if (buf.data && buf.len >= sizeof(setup_data)) {
        memcpy(&data, buf.data, sizeof(setup_data));
    }
    mpc_free_buffer(&buf);
}

void setup_key_persistency_shim::store_setup_commitments(
    const std::string& key_id,
    const std::map<uint64_t, commitment>& commitments) {
    // Serialize as: [count:u32][key:u64, data:64bytes]...
    size_t buf_len = 4 + commitments.size() * (8 + sizeof(commitments_commitment_t));
    std::vector<uint8_t> buf(buf_len);
    uint8_t* p = buf.data();
    uint32_t count = static_cast<uint32_t>(commitments.size());
    memcpy(p, &count, 4); p += 4;
    for (const auto& [id, c] : commitments) {
        memcpy(p, &id, 8); p += 8;
        memcpy(p, &c.data, sizeof(commitments_commitment_t));
        p += sizeof(commitments_commitment_t);
    }
    _cbs.store_setup_commitments(_cbs.user_ctx, key_id.c_str(),
        buf.data(), buf.size());
}

void setup_key_persistency_shim::load_setup_commitments(
    const std::string& key_id,
    std::map<uint64_t, commitment>& commitments) {
    mpc_buffer_t buf = _cbs.load_setup_commitments(_cbs.user_ctx,
        key_id.c_str());
    if (buf.data && buf.len >= 4) {
        const uint8_t* p = buf.data;
        uint32_t count;
        memcpy(&count, p, 4); p += 4;
        for (uint32_t i = 0; i < count && (size_t)(p - buf.data) + 8 + sizeof(commitments_commitment_t) <= buf.len; i++) {
            uint64_t id;
            memcpy(&id, p, 8); p += 8;
            commitment c;
            memcpy(&c.data, p, sizeof(commitments_commitment_t));
            p += sizeof(commitments_commitment_t);
            commitments[id] = c;
        }
    }
    mpc_free_buffer(&buf);
}

void setup_key_persistency_shim::delete_temporary_key_data(
    const std::string& key_id, bool delete_key) {
    _cbs.delete_temporary_key_data(_cbs.user_ctx, key_id.c_str(),
        delete_key ? 1 : 0);
}

// ============================================================================
// ECDSA signing persistency shim
// ============================================================================

ecdsa_signing_persistency_shim::ecdsa_signing_persistency_shim(
    const mpc_ecdsa_signing_persistency_callbacks_t& cbs) : _cbs(cbs) {}

void ecdsa_signing_persistency_shim::store_cmp_signing_data(
    const std::string& txid, const cmp_signing_metadata& data) {
    _cbs.store_cmp_signing_data(_cbs.user_ctx, txid.c_str(),
        reinterpret_cast<const uint8_t*>(&data), sizeof(data));
}

void ecdsa_signing_persistency_shim::load_cmp_signing_data(
    const std::string& txid, cmp_signing_metadata& data) const {
    mpc_buffer_t buf = _cbs.load_cmp_signing_data(_cbs.user_ctx, txid.c_str());
    if (buf.data && buf.len >= sizeof(cmp_signing_metadata)) {
        memcpy(&data, buf.data, sizeof(cmp_signing_metadata));
    }
    mpc_free_buffer(&buf);
}

void ecdsa_signing_persistency_shim::update_cmp_signing_data(
    const std::string& txid, const cmp_signing_metadata& data) {
    _cbs.update_cmp_signing_data(_cbs.user_ctx, txid.c_str(),
        reinterpret_cast<const uint8_t*>(&data), sizeof(data));
}

void ecdsa_signing_persistency_shim::delete_temporary_signing_data(
    const std::string& txid) {
    _cbs.delete_temporary_signing_data(_cbs.user_ctx, txid.c_str());
}

// ============================================================================
// EdDSA signing persistency shim
// ============================================================================

eddsa_signing_persistency_shim::eddsa_signing_persistency_shim(
    const mpc_eddsa_signing_persistency_callbacks_t& cbs) : _cbs(cbs) {}

void eddsa_signing_persistency_shim::store_signing_data(
    const std::string& txid, const eddsa_signing_metadata& data) {
    _cbs.store_signing_data(_cbs.user_ctx, txid.c_str(),
        reinterpret_cast<const uint8_t*>(&data), sizeof(data));
}

void eddsa_signing_persistency_shim::load_signing_data(
    const std::string& txid, eddsa_signing_metadata& data) const {
    mpc_buffer_t buf = _cbs.load_signing_data(_cbs.user_ctx, txid.c_str());
    if (buf.data && buf.len >= sizeof(eddsa_signing_metadata)) {
        memcpy(&data, buf.data, sizeof(eddsa_signing_metadata));
    }
    mpc_free_buffer(&buf);
}

void eddsa_signing_persistency_shim::update_signing_data(
    const std::string& txid, const eddsa_signing_metadata& data) {
    _cbs.update_signing_data(_cbs.user_ctx, txid.c_str(),
        reinterpret_cast<const uint8_t*>(&data), sizeof(data));
}

void eddsa_signing_persistency_shim::store_signing_commitments(
    const std::string& txid,
    const std::map<uint64_t, std::vector<commitment>>& commitments) {
    // Serialize: [map_count:u32] [id:u64, vec_count:u32, [commitment:64]...]...
    size_t total = 4;
    for (const auto& [id, vec] : commitments) {
        total += 8 + 4 + vec.size() * sizeof(commitments_commitment_t);
    }
    std::vector<uint8_t> buf(total);
    uint8_t* p = buf.data();
    uint32_t map_count = static_cast<uint32_t>(commitments.size());
    memcpy(p, &map_count, 4); p += 4;
    for (const auto& [id, vec] : commitments) {
        memcpy(p, &id, 8); p += 8;
        uint32_t vec_count = static_cast<uint32_t>(vec.size());
        memcpy(p, &vec_count, 4); p += 4;
        for (const auto& c : vec) {
            memcpy(p, &c.data, sizeof(commitments_commitment_t));
            p += sizeof(commitments_commitment_t);
        }
    }
    _cbs.store_signing_commitments(_cbs.user_ctx, txid.c_str(),
        buf.data(), buf.size());
}

void eddsa_signing_persistency_shim::load_signing_commitments(
    const std::string& txid,
    std::map<uint64_t, std::vector<commitment>>& commitments) {
    mpc_buffer_t buf = _cbs.load_signing_commitments(_cbs.user_ctx,
        txid.c_str());
    if (buf.data && buf.len >= 4) {
        const uint8_t* p = buf.data;
        uint32_t map_count;
        memcpy(&map_count, p, 4); p += 4;
        for (uint32_t i = 0; i < map_count; i++) {
            uint64_t id;
            memcpy(&id, p, 8); p += 8;
            uint32_t vec_count;
            memcpy(&vec_count, p, 4); p += 4;
            std::vector<commitment> vec(vec_count);
            for (uint32_t j = 0; j < vec_count; j++) {
                memcpy(&vec[j].data, p, sizeof(commitments_commitment_t));
                p += sizeof(commitments_commitment_t);
            }
            commitments[id] = std::move(vec);
        }
    }
    mpc_free_buffer(&buf);
}

void eddsa_signing_persistency_shim::delete_temporary_signing_data(
    const std::string& txid) {
    _cbs.delete_temporary_signing_data(_cbs.user_ctx, txid.c_str());
}

// ============================================================================
// Preprocessing persistency shim
// ============================================================================

preprocessing_persistency_shim::preprocessing_persistency_shim(
    const mpc_preprocessing_persistency_callbacks_t& cbs) : _cbs(cbs) {}

void preprocessing_persistency_shim::store_preprocessing_metadata(
    const std::string& request_id,
    const preprocessing_metadata& data, bool override_flag) {
    _cbs.store_preprocessing_metadata(_cbs.user_ctx, request_id.c_str(),
        reinterpret_cast<const uint8_t*>(&data), sizeof(data),
        override_flag ? 1 : 0);
}

void preprocessing_persistency_shim::load_preprocessing_metadata(
    const std::string& request_id, preprocessing_metadata& data) const {
    mpc_buffer_t buf = _cbs.load_preprocessing_metadata(_cbs.user_ctx,
        request_id.c_str());
    if (buf.data && buf.len >= sizeof(preprocessing_metadata)) {
        memcpy(&data, buf.data, sizeof(preprocessing_metadata));
    }
    mpc_free_buffer(&buf);
}

void preprocessing_persistency_shim::store_preprocessing_data(
    const std::string& request_id, uint64_t index,
    const ecdsa_preprocessing_data& data) {
    _cbs.store_preprocessing_data(_cbs.user_ctx, request_id.c_str(), index,
        reinterpret_cast<const uint8_t*>(&data), sizeof(data));
}

void preprocessing_persistency_shim::load_preprocessing_data(
    const std::string& request_id, uint64_t index,
    ecdsa_preprocessing_data& data) const {
    mpc_buffer_t buf = _cbs.load_preprocessing_data(_cbs.user_ctx,
        request_id.c_str(), index);
    if (buf.data && buf.len >= sizeof(ecdsa_preprocessing_data)) {
        memcpy(&data, buf.data, sizeof(ecdsa_preprocessing_data));
    }
    mpc_free_buffer(&buf);
}

void preprocessing_persistency_shim::delete_preprocessing_data(
    const std::string& request_id) {
    _cbs.delete_preprocessing_data(_cbs.user_ctx, request_id.c_str());
}

void preprocessing_persistency_shim::create_preprocessed_data(
    const std::string& key_id, uint64_t size) {
    _cbs.create_preprocessed_data(_cbs.user_ctx, key_id.c_str(), size);
}

void preprocessing_persistency_shim::store_preprocessed_data(
    const std::string& key_id, uint64_t index,
    const cmp_signature_preprocessed_data& data) {
    _cbs.store_preprocessed_data(_cbs.user_ctx, key_id.c_str(), index,
        reinterpret_cast<const uint8_t*>(&data), sizeof(data));
}

void preprocessing_persistency_shim::load_preprocessed_data(
    const std::string& key_id, uint64_t index,
    cmp_signature_preprocessed_data& data) {
    mpc_buffer_t buf = _cbs.load_preprocessed_data(_cbs.user_ctx,
        key_id.c_str(), index);
    if (buf.data && buf.len >= sizeof(cmp_signature_preprocessed_data)) {
        memcpy(&data, buf.data, sizeof(cmp_signature_preprocessed_data));
    }
    mpc_free_buffer(&buf);
}

void preprocessing_persistency_shim::delete_preprocessed_data(
    const std::string& key_id) {
    _cbs.delete_preprocessed_data(_cbs.user_ctx, key_id.c_str());
}

// ============================================================================
// Refresh key persistency shim
// ============================================================================

refresh_key_persistency_shim::refresh_key_persistency_shim(
    const mpc_refresh_persistency_callbacks_t& cbs) : _cbs(cbs) {}

void refresh_key_persistency_shim::load_refresh_key_seeds(
    const std::string& request_id,
    std::map<uint64_t, byte_vector_t>& player_id_to_seed) const {
    mpc_buffer_t buf = _cbs.load_refresh_key_seeds(_cbs.user_ctx,
        request_id.c_str());
    if (buf.data && buf.len >= 4) {
        const uint8_t* p = buf.data;
        uint32_t count;
        memcpy(&count, p, 4); p += 4;
        for (uint32_t i = 0; i < count; i++) {
            uint64_t id;
            memcpy(&id, p, 8); p += 8;
            uint32_t seed_len;
            memcpy(&seed_len, p, 4); p += 4;
            byte_vector_t seed(p, p + seed_len);
            p += seed_len;
            player_id_to_seed[id] = std::move(seed);
        }
    }
    mpc_free_buffer(&buf);
}

void refresh_key_persistency_shim::store_refresh_key_seeds(
    const std::string& request_id,
    const std::map<uint64_t, byte_vector_t>& player_id_to_seed) {
    // Serialize: [count:u32][id:u64, seed_len:u32, seed_data...]...
    size_t total = 4;
    for (const auto& [id, seed] : player_id_to_seed) {
        total += 8 + 4 + seed.size();
    }
    std::vector<uint8_t> buf(total);
    uint8_t* p = buf.data();
    uint32_t count = static_cast<uint32_t>(player_id_to_seed.size());
    memcpy(p, &count, 4); p += 4;
    for (const auto& [id, seed] : player_id_to_seed) {
        memcpy(p, &id, 8); p += 8;
        uint32_t seed_len = static_cast<uint32_t>(seed.size());
        memcpy(p, &seed_len, 4); p += 4;
        memcpy(p, seed.data(), seed.size()); p += seed.size();
    }
    _cbs.store_refresh_key_seeds(_cbs.user_ctx, request_id.c_str(),
        buf.data(), buf.size());
}

void refresh_key_persistency_shim::transform_preprocessed_data_and_store_temporary(
    const std::string& key_id, const std::string& request_id,
    const cmp_offline_refresh_service::preprocessed_data_handler& fn) {
    // This callback is complex: the JS side needs to iterate preprocessed data
    // and call fn(index, data) for each entry. We pass the handler through
    // the C callback mechanism.
    auto handler_wrapper = [](void* handler_ctx, uint64_t index,
        uint8_t* data_buf, size_t data_len,
        uint8_t* out_buf, size_t* out_len) {
        auto* fn_ptr = static_cast<const cmp_offline_refresh_service::preprocessed_data_handler*>(handler_ctx);
        cmp_signature_preprocessed_data data;
        if (data_buf && data_len >= sizeof(data)) {
            memcpy(&data, data_buf, sizeof(data));
        }
        (*fn_ptr)(index, data);
        if (out_buf && out_len) {
            memcpy(out_buf, &data, sizeof(data));
            *out_len = sizeof(data);
        }
    };

    _cbs.transform_preprocessed_data(_cbs.user_ctx,
        key_id.c_str(), request_id.c_str(),
        const_cast<void*>(static_cast<const void*>(&fn)),
        handler_wrapper);
}

void refresh_key_persistency_shim::commit(
    const std::string& key_id, const std::string& request_id) {
    _cbs.commit(_cbs.user_ctx, key_id.c_str(), request_id.c_str());
}

void refresh_key_persistency_shim::delete_refresh_key_seeds(
    const std::string& request_id) {
    _cbs.delete_refresh_key_seeds(_cbs.user_ctx, request_id.c_str());
}

void refresh_key_persistency_shim::delete_temporary_key(
    const std::string& key_id) {
    _cbs.delete_temporary_key(_cbs.user_ctx, key_id.c_str());
}

void refresh_key_persistency_shim::store_temporary_key(
    const std::string& key_id, cosigner_sign_algorithm algorithm,
    const elliptic_curve_scalar& private_key) {
    _cbs.store_temporary_key(_cbs.user_ctx, key_id.c_str(),
        static_cast<int32_t>(algorithm),
        reinterpret_cast<const uint8_t*>(&private_key.data));
}

} // namespace mpc_bindings
