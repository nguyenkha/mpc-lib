#include "mpc_cosigner_c_api.h"
#include "callback_shims.h"

#include "cosigner/cosigner_exception.h"

#include <cstdlib>
#include <cstring>
#include <new>

using namespace fireblocks::common::cosigner;
using namespace mpc_bindings;

// ============================================================================
// Helpers
// ============================================================================

static mpc_status_t translate_exception_code(
    cosigner_exception::exception_code code) {
    switch (code) {
        case cosigner_exception::GENERIC_ERROR:       return MPC_ERR_GENERIC;
        case cosigner_exception::INTERNAL_ERROR:      return MPC_ERR_INTERNAL;
        case cosigner_exception::INVALID_PARAMETERS:  return MPC_ERR_INVALID_PARAMS;
        case cosigner_exception::BAD_KEY:             return MPC_ERR_BAD_KEY;
        case cosigner_exception::INVALID_TRANSACTION: return MPC_ERR_INVALID_TRANSACTION;
        case cosigner_exception::NOT_ALIGNED_DATA:    return MPC_ERR_NOT_ALIGNED_DATA;
        case cosigner_exception::NOT_IMPLEMENTED:     return MPC_ERR_NOT_IMPLEMENTED;
        case cosigner_exception::UNKNOWN_ALGORITHM:   return MPC_ERR_UNKNOWN_ALGORITHM;
        case cosigner_exception::NO_MEM:              return MPC_ERR_NO_MEM;
        case cosigner_exception::UNAUTHORIZED:        return MPC_ERR_UNAUTHORIZED;
        case cosigner_exception::REJECTED:            return MPC_ERR_REJECTED;
        case cosigner_exception::BUSY:                return MPC_ERR_BUSY;
        case cosigner_exception::BACKUP_FAILED:       return MPC_ERR_BACKUP_FAILED;
        case cosigner_exception::AUTHORIZATION_FAILED:return MPC_ERR_AUTH_FAILED;
        case cosigner_exception::DISABLED_DEVICE:     return MPC_ERR_DISABLED_DEVICE;
        case cosigner_exception::INVALID_PRESIGNING_INDEX: return MPC_ERR_INVALID_PRESIGN_IDX;
        default: return MPC_ERR_GENERIC;
    }
}

static mpc_buffer_t make_buffer(const uint8_t* data, size_t len) {
    mpc_buffer_t buf;
    buf.data = static_cast<uint8_t*>(malloc(len));
    buf.len = len;
    if (buf.data && data) {
        memcpy(buf.data, data, len);
    }
    return buf;
}

static mpc_buffer_t make_buffer(const std::vector<uint8_t>& vec) {
    return make_buffer(vec.data(), vec.size());
}

// ============================================================================
// Buffer management
// ============================================================================

extern "C" void mpc_free_buffer(mpc_buffer_t* buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = nullptr;
        buf->len = 0;
    }
}

// ============================================================================
// Setup service
// ============================================================================

extern "C" mpc_status_t mpc_setup_service_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_setup_persistency_callbacks_t* persistency,
    mpc_handle_t* out_handle) {
    try {
        auto* holder = new setup_service_holder(*platform, *persistency);
        *out_handle = static_cast<mpc_handle_t>(holder);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" void mpc_setup_service_destroy(mpc_handle_t handle) {
    delete static_cast<setup_service_holder*>(handle);
}

extern "C" mpc_status_t mpc_setup_generate_commitments(
    mpc_handle_t handle,
    const char* key_id,
    const char* tenant_id,
    int32_t algorithm,
    const uint64_t* player_ids, size_t num_players,
    uint8_t t,
    uint64_t ttl,
    const char* derive_master_key_id,
    const uint8_t* derive_chaincode, size_t derive_chaincode_len,
    mpc_buffer_t* out_commitment) {
    try {
        auto* h = static_cast<setup_service_holder*>(handle);
        std::vector<uint64_t> players(player_ids, player_ids + num_players);
        share_derivation_args derive_from;
        if (derive_master_key_id) {
            derive_from.master_key_id = derive_master_key_id;
        }
        if (derive_chaincode && derive_chaincode_len > 0) {
            derive_from.chaincode.assign(derive_chaincode,
                derive_chaincode + derive_chaincode_len);
        }
        commitment result;
        h->service.generate_setup_commitments(key_id, tenant_id,
            static_cast<cosigner_sign_algorithm>(algorithm),
            players, t, ttl, derive_from, result);
        *out_commitment = make_buffer(
            reinterpret_cast<const uint8_t*>(&result.data),
            sizeof(commitments_commitment_t));
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_setup_store_commitments(
    mpc_handle_t handle,
    const char* key_id,
    const uint8_t* commitments_buf, size_t commitments_buf_len,
    mpc_buffer_t* out_decommitment) {
    try {
        auto* h = static_cast<setup_service_holder*>(handle);

        // Deserialize commitments: [count:u32][id:u64, data:64bytes]...
        std::map<uint64_t, commitment> commitments;
        if (commitments_buf && commitments_buf_len >= 4) {
            const uint8_t* p = commitments_buf;
            uint32_t count;
            memcpy(&count, p, 4); p += 4;
            for (uint32_t i = 0; i < count; i++) {
                uint64_t id;
                memcpy(&id, p, 8); p += 8;
                commitment c;
                memcpy(&c.data, p, sizeof(commitments_commitment_t));
                p += sizeof(commitments_commitment_t);
                commitments[id] = c;
            }
        }

        setup_decommitment result;
        h->service.store_setup_commitments(key_id, commitments, result);

        // Serialize decommitment
        size_t total = sizeof(commitments_sha256_t) * 2 +
            sizeof(elliptic_curve256_point_t) * 2 +
            4 + result.paillier_public_key.size() +
            4 + result.ring_pedersen_public_key.size();
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        memcpy(bp, result.ack, sizeof(commitments_sha256_t));
        bp += sizeof(commitments_sha256_t);
        memcpy(bp, result.seed, sizeof(commitments_sha256_t));
        bp += sizeof(commitments_sha256_t);
        memcpy(bp, &result.share.X.data, sizeof(elliptic_curve256_point_t));
        bp += sizeof(elliptic_curve256_point_t);
        memcpy(bp, &result.share.schnorr_R.data, sizeof(elliptic_curve256_point_t));
        bp += sizeof(elliptic_curve256_point_t);
        uint32_t plen = static_cast<uint32_t>(result.paillier_public_key.size());
        memcpy(bp, &plen, 4); bp += 4;
        memcpy(bp, result.paillier_public_key.data(), plen); bp += plen;
        uint32_t rlen = static_cast<uint32_t>(result.ring_pedersen_public_key.size());
        memcpy(bp, &rlen, 4); bp += 4;
        memcpy(bp, result.ring_pedersen_public_key.data(), rlen); bp += rlen;

        *out_decommitment = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_setup_generate_proofs(
    mpc_handle_t handle,
    const char* key_id,
    const uint8_t* decommitments_buf, size_t decommitments_buf_len,
    mpc_buffer_t* out_proofs) {
    try {
        auto* h = static_cast<setup_service_holder*>(handle);

        // Deserialize map of decommitments (opaque round-trip from store_commitments)
        std::map<uint64_t, setup_decommitment> decommitments;
        // TODO: implement full deserialization matching the serialization above
        (void)decommitments_buf;
        (void)decommitments_buf_len;

        setup_zk_proofs result;
        h->service.generate_setup_proofs(key_id, decommitments, result);

        // Serialize proofs
        size_t total = sizeof(elliptic_curve256_scalar_t) +
            4 + result.paillier_blum_zkp.size() +
            4 + result.ring_pedersen_param_zkp.size();
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        memcpy(bp, &result.schnorr_s.data, sizeof(elliptic_curve256_scalar_t));
        bp += sizeof(elliptic_curve256_scalar_t);
        uint32_t plen = static_cast<uint32_t>(result.paillier_blum_zkp.size());
        memcpy(bp, &plen, 4); bp += 4;
        memcpy(bp, result.paillier_blum_zkp.data(), plen); bp += plen;
        uint32_t rlen = static_cast<uint32_t>(result.ring_pedersen_param_zkp.size());
        memcpy(bp, &rlen, 4); bp += 4;
        memcpy(bp, result.ring_pedersen_param_zkp.data(), rlen); bp += rlen;

        *out_proofs = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_setup_verify_proofs(
    mpc_handle_t handle,
    const char* key_id,
    const uint8_t* proofs_buf, size_t proofs_buf_len,
    mpc_buffer_t* out_paillier_proofs) {
    try {
        auto* h = static_cast<setup_service_holder*>(handle);

        std::map<uint64_t, setup_zk_proofs> proofs;
        (void)proofs_buf;
        (void)proofs_buf_len;

        std::map<uint64_t, byte_vector_t> paillier_proofs;
        h->service.verify_setup_proofs(key_id, proofs, paillier_proofs);

        // Serialize map: [count:u32][id:u64, len:u32, data...]...
        size_t total = 4;
        for (const auto& [id, proof] : paillier_proofs) {
            total += 8 + 4 + proof.size();
        }
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(paillier_proofs.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& [id, proof] : paillier_proofs) {
            memcpy(bp, &id, 8); bp += 8;
            uint32_t plen = static_cast<uint32_t>(proof.size());
            memcpy(bp, &plen, 4); bp += 4;
            memcpy(bp, proof.data(), proof.size()); bp += proof.size();
        }

        *out_paillier_proofs = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_setup_create_secret(
    mpc_handle_t handle,
    const char* key_id,
    const uint8_t* paillier_proofs_buf, size_t paillier_proofs_buf_len,
    char* out_public_key, size_t out_public_key_cap,
    int32_t* out_algorithm) {
    try {
        auto* h = static_cast<setup_service_holder*>(handle);

        std::map<uint64_t, std::map<uint64_t, byte_vector_t>> paillier_proofs;
        (void)paillier_proofs_buf;
        (void)paillier_proofs_buf_len;

        std::string public_key;
        cosigner_sign_algorithm algorithm;
        h->service.create_secret(key_id, paillier_proofs, public_key, algorithm);

        size_t copy_len = std::min(public_key.size(), out_public_key_cap - 1);
        memcpy(out_public_key, public_key.c_str(), copy_len);
        out_public_key[copy_len] = '\0';
        *out_algorithm = static_cast<int32_t>(algorithm);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_setup_add_user_request(
    mpc_handle_t handle,
    const char* key_id,
    int32_t algorithm,
    const char* new_key_id,
    const uint64_t* player_ids, size_t num_players,
    uint8_t t,
    mpc_buffer_t* out_data) {
    try {
        auto* h = static_cast<setup_service_holder*>(handle);
        std::vector<uint64_t> players(player_ids, player_ids + num_players);
        add_user_data result;
        h->service.add_user_request(key_id,
            static_cast<cosigner_sign_algorithm>(algorithm),
            new_key_id, players, t, result);

        // Serialize: public_key(33) + [count:u32][id:u64, len:u32, data...]...
        size_t total = sizeof(elliptic_curve256_point_t) + 4;
        for (const auto& [id, share] : result.encrypted_shares) {
            total += 8 + 4 + share.size();
        }
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        memcpy(bp, &result.public_key.data, sizeof(elliptic_curve256_point_t));
        bp += sizeof(elliptic_curve256_point_t);
        uint32_t count = static_cast<uint32_t>(result.encrypted_shares.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& [id, share] : result.encrypted_shares) {
            memcpy(bp, &id, 8); bp += 8;
            uint32_t slen = static_cast<uint32_t>(share.size());
            memcpy(bp, &slen, 4); bp += 4;
            memcpy(bp, share.data(), share.size()); bp += share.size();
        }

        *out_data = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_setup_add_user(
    mpc_handle_t handle,
    const char* tenant_id,
    const char* key_id,
    int32_t algorithm,
    uint8_t t,
    const uint8_t* data_buf, size_t data_buf_len,
    uint64_t ttl,
    mpc_buffer_t* out_commitment) {
    try {
        auto* h = static_cast<setup_service_holder*>(handle);
        std::map<uint64_t, add_user_data> data;
        (void)data_buf;
        (void)data_buf_len;

        commitment result;
        h->service.add_user(tenant_id, key_id,
            static_cast<cosigner_sign_algorithm>(algorithm),
            t, data, ttl, result);

        *out_commitment = make_buffer(
            reinterpret_cast<const uint8_t*>(&result.data),
            sizeof(commitments_commitment_t));
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

// ============================================================================
// ECDSA online signing service
// ============================================================================

extern "C" mpc_status_t mpc_ecdsa_online_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_key_persistency_callbacks_t* key_persistency,
    const mpc_ecdsa_signing_persistency_callbacks_t* signing_persistency,
    mpc_handle_t* out_handle) {
    try {
        auto* holder = new ecdsa_online_holder(
            *platform, *key_persistency, *signing_persistency);
        *out_handle = static_cast<mpc_handle_t>(holder);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" void mpc_ecdsa_online_destroy(mpc_handle_t handle) {
    delete static_cast<ecdsa_online_holder*>(handle);
}

extern "C" mpc_status_t mpc_ecdsa_online_start_signing(
    mpc_handle_t handle,
    const char* key_id,
    const char* txid,
    int32_t algorithm,
    const uint8_t* signing_data_buf, size_t signing_data_buf_len,
    const char* metadata_json,
    const char* players_json,
    const uint64_t* player_ids, size_t num_player_ids,
    mpc_buffer_t* out_mta_requests) {
    try {
        auto* h = static_cast<ecdsa_online_holder*>(handle);

        // TODO: deserialize signing_data and players from JSON/binary
        signing_data data;
        (void)signing_data_buf;
        (void)signing_data_buf_len;

        std::set<std::string> players;
        (void)players_json;

        std::set<uint64_t> pids(player_ids, player_ids + num_player_ids);

        std::vector<cmp_mta_request> mta_requests;
        h->service.start_signing(key_id, txid,
            static_cast<cosigner_sign_algorithm>(algorithm),
            data, metadata_json, players, pids, mta_requests);

        // Serialize MTA requests as opaque blob
        size_t total = 4 + mta_requests.size() * sizeof(cmp_mta_request);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(mta_requests.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& req : mta_requests) {
            memcpy(bp, &req, sizeof(cmp_mta_request));
            bp += sizeof(cmp_mta_request);
        }
        *out_mta_requests = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_online_mta_response(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* requests_buf, size_t requests_buf_len,
    uint32_t version,
    uint64_t* out_player_id,
    mpc_buffer_t* out_response) {
    try {
        auto* h = static_cast<ecdsa_online_holder*>(handle);
        std::map<uint64_t, std::vector<cmp_mta_request>> requests;
        (void)requests_buf;
        (void)requests_buf_len;

        cmp_mta_responses response;
        *out_player_id = h->service.mta_response(txid, requests, version, response);
        *out_response = make_buffer(
            reinterpret_cast<const uint8_t*>(&response), sizeof(response));
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_online_mta_verify(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* responses_buf, size_t responses_buf_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_deltas) {
    try {
        auto* h = static_cast<ecdsa_online_holder*>(handle);
        std::map<uint64_t, cmp_mta_responses> responses;
        (void)responses_buf;
        (void)responses_buf_len;

        std::vector<cmp_mta_deltas> deltas;
        *out_player_id = h->service.mta_verify(txid, responses, deltas);

        size_t total = 4 + deltas.size() * sizeof(cmp_mta_deltas);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(deltas.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& d : deltas) {
            memcpy(bp, &d, sizeof(cmp_mta_deltas));
            bp += sizeof(cmp_mta_deltas);
        }
        *out_deltas = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_online_get_si(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* deltas_buf, size_t deltas_buf_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_sis) {
    try {
        auto* h = static_cast<ecdsa_online_holder*>(handle);
        std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
        (void)deltas_buf;
        (void)deltas_buf_len;

        std::vector<elliptic_curve_scalar> sis;
        *out_player_id = h->service.get_si(txid, deltas, sis);

        size_t total = 4 + sis.size() * sizeof(elliptic_curve256_scalar_t);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(sis.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& s : sis) {
            memcpy(bp, &s.data, sizeof(elliptic_curve256_scalar_t));
            bp += sizeof(elliptic_curve256_scalar_t);
        }
        *out_sis = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_online_get_signature(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* s_buf, size_t s_buf_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_signatures) {
    try {
        auto* h = static_cast<ecdsa_online_holder*>(handle);
        std::map<uint64_t, std::vector<elliptic_curve_scalar>> s;
        (void)s_buf;
        (void)s_buf_len;

        std::vector<recoverable_signature> sigs;
        *out_player_id = h->service.get_cmp_signature(txid, s, sigs);

        size_t total = 4 + sigs.size() * sizeof(recoverable_signature);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(sigs.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& sig : sigs) {
            memcpy(bp, &sig, sizeof(recoverable_signature));
            bp += sizeof(recoverable_signature);
        }
        *out_signatures = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_online_cancel(
    mpc_handle_t handle, const char* txid) {
    try {
        auto* h = static_cast<ecdsa_online_holder*>(handle);
        h->service.cancel_signing(txid);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

// ============================================================================
// ECDSA offline signing service
// ============================================================================

extern "C" mpc_status_t mpc_ecdsa_offline_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_key_persistency_callbacks_t* key_persistency,
    const mpc_preprocessing_persistency_callbacks_t* preprocessing_persistency,
    mpc_handle_t* out_handle) {
    try {
        auto* holder = new ecdsa_offline_holder(
            *platform, *key_persistency, *preprocessing_persistency);
        *out_handle = static_cast<mpc_handle_t>(holder);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" void mpc_ecdsa_offline_destroy(mpc_handle_t handle) {
    delete static_cast<ecdsa_offline_holder*>(handle);
}

extern "C" mpc_status_t mpc_ecdsa_offline_start_preprocessing(
    mpc_handle_t handle,
    const char* tenant_id, const char* key_id, const char* request_id,
    uint32_t start_index, uint32_t count, uint32_t total_count,
    const uint64_t* player_ids, size_t num_player_ids,
    mpc_buffer_t* out_mta_requests) {
    try {
        auto* h = static_cast<ecdsa_offline_holder*>(handle);
        std::set<uint64_t> pids(player_ids, player_ids + num_player_ids);
        std::vector<cmp_mta_request> mta_requests;
        h->service.start_ecdsa_signature_preprocessing(
            tenant_id, key_id, request_id,
            start_index, count, total_count, pids, mta_requests);

        size_t total = 4 + mta_requests.size() * sizeof(cmp_mta_request);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t cnt = static_cast<uint32_t>(mta_requests.size());
        memcpy(bp, &cnt, 4); bp += 4;
        for (const auto& req : mta_requests) {
            memcpy(bp, &req, sizeof(cmp_mta_request)); bp += sizeof(cmp_mta_request);
        }
        *out_mta_requests = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_offline_mta_response(
    mpc_handle_t handle,
    const char* request_id,
    const uint8_t* requests_buf, size_t requests_buf_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_response) {
    try {
        auto* h = static_cast<ecdsa_offline_holder*>(handle);
        std::map<uint64_t, std::vector<cmp_mta_request>> requests;
        (void)requests_buf; (void)requests_buf_len;

        cmp_mta_responses response;
        *out_player_id = h->service.offline_mta_response(request_id, requests, response);
        *out_response = make_buffer(
            reinterpret_cast<const uint8_t*>(&response), sizeof(response));
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_offline_mta_verify(
    mpc_handle_t handle,
    const char* request_id,
    const uint8_t* responses_buf, size_t responses_buf_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_deltas) {
    try {
        auto* h = static_cast<ecdsa_offline_holder*>(handle);
        std::map<uint64_t, cmp_mta_responses> responses;
        (void)responses_buf; (void)responses_buf_len;

        std::vector<cmp_mta_deltas> deltas;
        *out_player_id = h->service.offline_mta_verify(request_id, responses, deltas);

        size_t total = 4 + deltas.size() * sizeof(cmp_mta_deltas);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(deltas.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& d : deltas) {
            memcpy(bp, &d, sizeof(cmp_mta_deltas)); bp += sizeof(cmp_mta_deltas);
        }
        *out_deltas = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_offline_store_presigning(
    mpc_handle_t handle,
    const char* request_id,
    const uint8_t* deltas_buf, size_t deltas_buf_len,
    uint64_t* out_player_id,
    char* out_key_id, size_t out_key_id_cap) {
    try {
        auto* h = static_cast<ecdsa_offline_holder*>(handle);
        std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
        (void)deltas_buf; (void)deltas_buf_len;

        std::string key_id;
        *out_player_id = h->service.store_presigning_data(request_id, deltas, key_id);

        size_t copy_len = std::min(key_id.size(), out_key_id_cap - 1);
        memcpy(out_key_id, key_id.c_str(), copy_len);
        out_key_id[copy_len] = '\0';
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_offline_sign(
    mpc_handle_t handle,
    const char* key_id, const char* txid,
    const uint8_t* signing_data_buf, size_t signing_data_buf_len,
    const char* metadata_json, const char* players_json,
    const uint64_t* player_ids, size_t num_player_ids,
    uint64_t preprocessed_data_index, int32_t protocol_version,
    mpc_buffer_t* out_partial_sigs) {
    try {
        auto* h = static_cast<ecdsa_offline_holder*>(handle);
        signing_data data;
        (void)signing_data_buf; (void)signing_data_buf_len;
        std::set<std::string> players;
        (void)players_json;
        std::set<uint64_t> pids(player_ids, player_ids + num_player_ids);

        std::vector<recoverable_signature> partial_sigs;
        h->service.ecdsa_sign(key_id, txid, data, metadata_json, players, pids,
            preprocessed_data_index, protocol_version, partial_sigs);

        size_t total = 4 + partial_sigs.size() * sizeof(recoverable_signature);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(partial_sigs.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& sig : partial_sigs) {
            memcpy(bp, &sig, sizeof(recoverable_signature)); bp += sizeof(recoverable_signature);
        }
        *out_partial_sigs = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_offline_signature(
    mpc_handle_t handle,
    const char* key_id, const char* txid, int32_t algorithm,
    const uint8_t* partial_sigs_buf, size_t partial_sigs_buf_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_signatures) {
    try {
        auto* h = static_cast<ecdsa_offline_holder*>(handle);
        std::map<uint64_t, std::vector<recoverable_signature>> partial_sigs;
        (void)partial_sigs_buf; (void)partial_sigs_buf_len;

        std::vector<recoverable_signature> sigs;
        *out_player_id = h->service.ecdsa_offline_signature(
            key_id, txid, static_cast<cosigner_sign_algorithm>(algorithm),
            partial_sigs, sigs);

        size_t total = 4 + sigs.size() * sizeof(recoverable_signature);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(sigs.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& sig : sigs) {
            memcpy(bp, &sig, sizeof(recoverable_signature)); bp += sizeof(recoverable_signature);
        }
        *out_signatures = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_ecdsa_offline_cancel(
    mpc_handle_t handle, const char* request_id) {
    try {
        auto* h = static_cast<ecdsa_offline_holder*>(handle);
        h->service.cancel_preprocessing(request_id);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

// ============================================================================
// EdDSA online signing service
// ============================================================================

extern "C" mpc_status_t mpc_eddsa_online_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_key_persistency_callbacks_t* key_persistency,
    const mpc_eddsa_signing_persistency_callbacks_t* signing_persistency,
    mpc_handle_t* out_handle) {
    try {
        auto* holder = new eddsa_online_holder(
            *platform, *key_persistency, *signing_persistency);
        *out_handle = static_cast<mpc_handle_t>(holder);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" void mpc_eddsa_online_destroy(mpc_handle_t handle) {
    delete static_cast<eddsa_online_holder*>(handle);
}

extern "C" mpc_status_t mpc_eddsa_online_start_signing(
    mpc_handle_t handle,
    const char* key_id, const char* txid,
    const uint8_t* signing_data_buf, size_t signing_data_buf_len,
    const char* metadata_json, const char* players_json,
    const uint64_t* player_ids, size_t num_player_ids,
    mpc_buffer_t* out_commitments) {
    try {
        auto* h = static_cast<eddsa_online_holder*>(handle);
        signing_data data;
        (void)signing_data_buf; (void)signing_data_buf_len;
        std::set<std::string> players;
        (void)players_json;
        std::set<uint64_t> pids(player_ids, player_ids + num_player_ids);

        std::vector<commitment> commitments;
        h->service.start_signing(key_id, txid, data, metadata_json,
            players, pids, commitments);

        size_t total = 4 + commitments.size() * sizeof(commitments_commitment_t);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(commitments.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& c : commitments) {
            memcpy(bp, &c.data, sizeof(commitments_commitment_t));
            bp += sizeof(commitments_commitment_t);
        }
        *out_commitments = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_eddsa_online_store_commitments(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* commitments_buf, size_t commitments_buf_len,
    uint32_t version,
    uint64_t* out_player_id,
    mpc_buffer_t* out_Rs) {
    try {
        auto* h = static_cast<eddsa_online_holder*>(handle);
        std::map<uint64_t, std::vector<commitment>> commitments;
        (void)commitments_buf; (void)commitments_buf_len;

        std::vector<elliptic_curve_point> Rs;
        *out_player_id = h->service.store_commitments(txid, commitments, version, Rs);

        size_t total = 4 + Rs.size() * sizeof(elliptic_curve256_point_t);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(Rs.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& r : Rs) {
            memcpy(bp, &r.data, sizeof(elliptic_curve256_point_t));
            bp += sizeof(elliptic_curve256_point_t);
        }
        *out_Rs = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_eddsa_online_broadcast_si(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* Rs_buf, size_t Rs_buf_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_si) {
    try {
        auto* h = static_cast<eddsa_online_holder*>(handle);
        std::map<uint64_t, std::vector<elliptic_curve_point>> Rs;
        (void)Rs_buf; (void)Rs_buf_len;

        std::vector<elliptic_curve_scalar> si;
        *out_player_id = h->service.broadcast_si(txid, Rs, si);

        size_t total = 4 + si.size() * sizeof(elliptic_curve256_scalar_t);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(si.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& s : si) {
            memcpy(bp, &s.data, sizeof(elliptic_curve256_scalar_t));
            bp += sizeof(elliptic_curve256_scalar_t);
        }
        *out_si = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_eddsa_online_get_signature(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* s_buf, size_t s_buf_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_signatures) {
    try {
        auto* h = static_cast<eddsa_online_holder*>(handle);
        std::map<uint64_t, std::vector<elliptic_curve_scalar>> s;
        (void)s_buf; (void)s_buf_len;

        std::vector<eddsa_signature> sigs;
        *out_player_id = h->service.get_eddsa_signature(txid, s, sigs);

        size_t total = 4 + sigs.size() * sizeof(eddsa_signature);
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(sigs.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& sig : sigs) {
            memcpy(bp, &sig, sizeof(eddsa_signature));
            bp += sizeof(eddsa_signature);
        }
        *out_signatures = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (const unknown_txid_exception&) {
        return MPC_ERR_UNKNOWN_TXID;
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_eddsa_online_cancel(
    mpc_handle_t handle, const char* request_id) {
    try {
        auto* h = static_cast<eddsa_online_holder*>(handle);
        h->service.cancel_signing(request_id);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

// ============================================================================
// Offline refresh service
// ============================================================================

extern "C" mpc_status_t mpc_refresh_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_key_persistency_callbacks_t* key_persistency,
    const mpc_refresh_persistency_callbacks_t* refresh_persistency,
    mpc_handle_t* out_handle) {
    try {
        auto* holder = new refresh_holder(
            *platform, *key_persistency, *refresh_persistency);
        *out_handle = static_cast<mpc_handle_t>(holder);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" void mpc_refresh_destroy(mpc_handle_t handle) {
    delete static_cast<refresh_holder*>(handle);
}

extern "C" mpc_status_t mpc_refresh_key_request(
    mpc_handle_t handle,
    const char* tenant_id, const char* key_id, const char* request_id,
    const uint64_t* player_ids, size_t num_player_ids,
    mpc_buffer_t* out_encrypted_seeds) {
    try {
        auto* h = static_cast<refresh_holder*>(handle);
        std::set<uint64_t> pids(player_ids, player_ids + num_player_ids);
        std::map<uint64_t, byte_vector_t> encrypted_seeds;
        h->service.refresh_key_request(tenant_id, key_id, request_id,
            pids, encrypted_seeds);

        // Serialize: [count:u32][id:u64, len:u32, data...]...
        size_t total = 4;
        for (const auto& [id, seed] : encrypted_seeds) {
            total += 8 + 4 + seed.size();
        }
        std::vector<uint8_t> buf(total);
        uint8_t* bp = buf.data();
        uint32_t count = static_cast<uint32_t>(encrypted_seeds.size());
        memcpy(bp, &count, 4); bp += 4;
        for (const auto& [id, seed] : encrypted_seeds) {
            memcpy(bp, &id, 8); bp += 8;
            uint32_t slen = static_cast<uint32_t>(seed.size());
            memcpy(bp, &slen, 4); bp += 4;
            memcpy(bp, seed.data(), seed.size()); bp += seed.size();
        }
        *out_encrypted_seeds = make_buffer(buf.data(), bp - buf.data());
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_refresh_key(
    mpc_handle_t handle,
    const char* key_id, const char* request_id,
    const uint8_t* encrypted_seeds_buf, size_t encrypted_seeds_buf_len,
    char* out_public_key, size_t out_public_key_cap) {
    try {
        auto* h = static_cast<refresh_holder*>(handle);
        std::map<uint64_t, std::map<uint64_t, byte_vector_t>> encrypted_seeds;
        (void)encrypted_seeds_buf; (void)encrypted_seeds_buf_len;

        std::string public_key;
        h->service.refresh_key(key_id, request_id, encrypted_seeds, public_key);

        size_t copy_len = std::min(public_key.size(), out_public_key_cap - 1);
        memcpy(out_public_key, public_key.c_str(), copy_len);
        out_public_key[copy_len] = '\0';
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_refresh_key_fast_ack(
    mpc_handle_t handle,
    const char* tenant_id, const char* key_id, const char* request_id) {
    try {
        auto* h = static_cast<refresh_holder*>(handle);
        h->service.refresh_key_fast_ack(tenant_id, key_id, request_id);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}

extern "C" mpc_status_t mpc_refresh_cancel(
    mpc_handle_t handle, const char* request_id) {
    try {
        auto* h = static_cast<refresh_holder*>(handle);
        h->service.cancel_refresh_key(request_id);
        return MPC_OK;
    } catch (const cosigner_exception& e) {
        return translate_exception_code(e.error_code());
    } catch (...) {
        return MPC_ERR_INTERNAL;
    }
}
