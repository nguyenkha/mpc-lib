#ifndef MPC_COSIGNER_C_API_H
#define MPC_COSIGNER_C_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Common types
// ============================================================================

typedef void* mpc_handle_t;
typedef int32_t mpc_status_t;

#define MPC_OK                          0
#define MPC_ERR_GENERIC                -1
#define MPC_ERR_INTERNAL               -2
#define MPC_ERR_INVALID_PARAMS         -3
#define MPC_ERR_BAD_KEY                -4
#define MPC_ERR_INVALID_TRANSACTION    -5
#define MPC_ERR_NOT_ALIGNED_DATA       -6
#define MPC_ERR_NOT_IMPLEMENTED        -7
#define MPC_ERR_UNKNOWN_ALGORITHM      -8
#define MPC_ERR_NO_MEM                 -9
#define MPC_ERR_UNAUTHORIZED           -10
#define MPC_ERR_REJECTED               -11
#define MPC_ERR_BUSY                   -12
#define MPC_ERR_BACKUP_FAILED          -13
#define MPC_ERR_AUTH_FAILED            -14
#define MPC_ERR_DISABLED_DEVICE        -15
#define MPC_ERR_INVALID_PRESIGN_IDX    -16
#define MPC_ERR_UNKNOWN_TXID           -100

// Serialized buffer returned by C API. Caller must free with mpc_free_buffer.
typedef struct {
    uint8_t* data;
    size_t   len;
} mpc_buffer_t;

void mpc_free_buffer(mpc_buffer_t* buf);

// ============================================================================
// Platform service callbacks
// ============================================================================

typedef void     (*mpc_gen_random_fn)(void* ctx, size_t len, uint8_t* out);
typedef size_t   (*mpc_get_tenant_id_fn)(void* ctx, char* out, size_t out_cap);
typedef uint64_t (*mpc_get_id_from_keyid_fn)(void* ctx, const char* key_id);
typedef void     (*mpc_derive_initial_share_fn)(void* ctx,
                    const char* master_key_id,
                    const uint8_t* chaincode, size_t cc_len,
                    int32_t algorithm,
                    uint8_t out_key[32]);
typedef mpc_buffer_t (*mpc_encrypt_for_player_fn)(void* ctx, uint64_t id,
                    const uint8_t* data, size_t data_len);
typedef mpc_buffer_t (*mpc_decrypt_message_fn)(void* ctx,
                    const uint8_t* data, size_t data_len);
typedef int32_t  (*mpc_backup_key_fn)(void* ctx,
                    const char* key_id, int32_t algorithm,
                    const uint8_t private_key[32],
                    const uint8_t* metadata_buf, size_t metadata_len,
                    const uint8_t* aux_buf, size_t aux_len);
typedef void     (*mpc_on_start_signing_fn)(void* ctx,
                    const char* key_id, const char* txid,
                    const uint8_t* signing_data_buf, size_t signing_data_len,
                    const char* metadata_json,
                    const char* players_json,
                    int32_t sig_type);
typedef void     (*mpc_fill_signing_info_fn)(void* ctx,
                    const char* metadata,
                    uint32_t* flags_out, size_t count);
typedef int32_t  (*mpc_is_client_id_fn)(void* ctx, uint64_t player_id);
typedef uint64_t (*mpc_now_msec_fn)(void* ctx);

typedef struct {
    void* user_ctx;
    mpc_gen_random_fn           gen_random;
    mpc_get_tenant_id_fn        get_tenant_id;
    mpc_get_id_from_keyid_fn    get_id_from_keyid;
    mpc_derive_initial_share_fn derive_initial_share;
    mpc_encrypt_for_player_fn   encrypt_for_player;
    mpc_decrypt_message_fn      decrypt_message;
    mpc_backup_key_fn           backup_key;
    mpc_on_start_signing_fn     on_start_signing;
    mpc_fill_signing_info_fn    fill_signing_info;
    mpc_is_client_id_fn         is_client_id;
    mpc_now_msec_fn             now_msec;  // nullable
} mpc_platform_callbacks_t;

// ============================================================================
// Key persistency callbacks
// ============================================================================

typedef int32_t  (*mpc_key_exist_fn)(void* ctx, const char* key_id);
typedef void     (*mpc_load_key_fn)(void* ctx, const char* key_id,
                    int32_t* out_algorithm, uint8_t out_private_key[32]);
typedef size_t   (*mpc_get_tenantid_from_keyid_fn)(void* ctx,
                    const char* key_id, char* out, size_t out_cap);
typedef mpc_buffer_t (*mpc_load_key_metadata_fn)(void* ctx,
                    const char* key_id, int32_t full_load);
typedef mpc_buffer_t (*mpc_load_auxiliary_keys_fn)(void* ctx,
                    const char* key_id);

typedef struct {
    void* user_ctx;
    mpc_key_exist_fn              key_exist;
    mpc_load_key_fn               load_key;
    mpc_get_tenantid_from_keyid_fn get_tenantid_from_keyid;
    mpc_load_key_metadata_fn      load_key_metadata;
    mpc_load_auxiliary_keys_fn    load_auxiliary_keys;
} mpc_key_persistency_callbacks_t;

// ============================================================================
// Setup key persistency callbacks (extends key persistency)
// ============================================================================

typedef void (*mpc_store_key_fn)(void* ctx, const char* key_id,
                int32_t algorithm, const uint8_t private_key[32], uint64_t ttl);
typedef void (*mpc_store_key_metadata_fn)(void* ctx, const char* key_id,
                const uint8_t* metadata_buf, size_t metadata_len,
                int32_t allow_override);
typedef void (*mpc_store_auxiliary_keys_fn)(void* ctx, const char* key_id,
                const uint8_t* aux_buf, size_t aux_len);
typedef void (*mpc_store_keyid_tenant_id_fn)(void* ctx,
                const char* key_id, const char* tenant_id);
typedef void (*mpc_store_setup_data_fn)(void* ctx, const char* key_id,
                const uint8_t* data_buf, size_t data_len);
typedef mpc_buffer_t (*mpc_load_setup_data_fn)(void* ctx, const char* key_id);
typedef void (*mpc_store_setup_commitments_fn)(void* ctx, const char* key_id,
                const uint8_t* commitments_buf, size_t commitments_len);
typedef mpc_buffer_t (*mpc_load_setup_commitments_fn)(void* ctx,
                const char* key_id);
typedef void (*mpc_delete_temporary_key_data_fn)(void* ctx,
                const char* key_id, int32_t delete_key);

typedef struct {
    mpc_key_persistency_callbacks_t base;
    void* user_ctx;
    mpc_store_key_fn                  store_key;
    mpc_store_key_metadata_fn         store_key_metadata;
    mpc_store_auxiliary_keys_fn       store_auxiliary_keys;
    mpc_store_keyid_tenant_id_fn      store_keyid_tenant_id;
    mpc_store_setup_data_fn           store_setup_data;
    mpc_load_setup_data_fn            load_setup_data;
    mpc_store_setup_commitments_fn    store_setup_commitments;
    mpc_load_setup_commitments_fn     load_setup_commitments;
    mpc_delete_temporary_key_data_fn  delete_temporary_key_data;
} mpc_setup_persistency_callbacks_t;

// ============================================================================
// ECDSA signing persistency callbacks
// ============================================================================

typedef void (*mpc_store_cmp_signing_data_fn)(void* ctx, const char* txid,
                const uint8_t* data_buf, size_t data_len);
typedef mpc_buffer_t (*mpc_load_cmp_signing_data_fn)(void* ctx,
                const char* txid);
typedef void (*mpc_update_cmp_signing_data_fn)(void* ctx, const char* txid,
                const uint8_t* data_buf, size_t data_len);
typedef void (*mpc_delete_signing_data_fn)(void* ctx, const char* txid);

typedef struct {
    void* user_ctx;
    mpc_store_cmp_signing_data_fn   store_cmp_signing_data;
    mpc_load_cmp_signing_data_fn    load_cmp_signing_data;
    mpc_update_cmp_signing_data_fn  update_cmp_signing_data;
    mpc_delete_signing_data_fn      delete_temporary_signing_data;
} mpc_ecdsa_signing_persistency_callbacks_t;

// ============================================================================
// EdDSA signing persistency callbacks
// ============================================================================

typedef void (*mpc_store_eddsa_signing_data_fn)(void* ctx, const char* txid,
                const uint8_t* data_buf, size_t data_len);
typedef mpc_buffer_t (*mpc_load_eddsa_signing_data_fn)(void* ctx,
                const char* txid);
typedef void (*mpc_update_eddsa_signing_data_fn)(void* ctx, const char* txid,
                const uint8_t* data_buf, size_t data_len);
typedef void (*mpc_store_eddsa_signing_commitments_fn)(void* ctx,
                const char* txid,
                const uint8_t* commitments_buf, size_t commitments_len);
typedef mpc_buffer_t (*mpc_load_eddsa_signing_commitments_fn)(void* ctx,
                const char* txid);
typedef void (*mpc_delete_eddsa_signing_data_fn)(void* ctx, const char* txid);

typedef struct {
    void* user_ctx;
    mpc_store_eddsa_signing_data_fn         store_signing_data;
    mpc_load_eddsa_signing_data_fn          load_signing_data;
    mpc_update_eddsa_signing_data_fn        update_signing_data;
    mpc_store_eddsa_signing_commitments_fn  store_signing_commitments;
    mpc_load_eddsa_signing_commitments_fn   load_signing_commitments;
    mpc_delete_eddsa_signing_data_fn        delete_temporary_signing_data;
} mpc_eddsa_signing_persistency_callbacks_t;

// ============================================================================
// Preprocessing persistency callbacks
// ============================================================================

typedef void (*mpc_store_preprocessing_metadata_fn)(void* ctx,
                const char* request_id,
                const uint8_t* data_buf, size_t data_len, int32_t override_flag);
typedef mpc_buffer_t (*mpc_load_preprocessing_metadata_fn)(void* ctx,
                const char* request_id);
typedef void (*mpc_store_preprocessing_data_fn)(void* ctx,
                const char* request_id, uint64_t index,
                const uint8_t* data_buf, size_t data_len);
typedef mpc_buffer_t (*mpc_load_preprocessing_data_fn)(void* ctx,
                const char* request_id, uint64_t index);
typedef void (*mpc_delete_preprocessing_data_fn)(void* ctx,
                const char* request_id);
typedef void (*mpc_create_preprocessed_data_fn)(void* ctx,
                const char* key_id, uint64_t size);
typedef void (*mpc_store_preprocessed_data_fn)(void* ctx,
                const char* key_id, uint64_t index,
                const uint8_t* data_buf, size_t data_len);
typedef mpc_buffer_t (*mpc_load_preprocessed_data_fn)(void* ctx,
                const char* key_id, uint64_t index);
typedef void (*mpc_delete_preprocessed_data_fn)(void* ctx,
                const char* key_id);

typedef struct {
    void* user_ctx;
    mpc_store_preprocessing_metadata_fn   store_preprocessing_metadata;
    mpc_load_preprocessing_metadata_fn    load_preprocessing_metadata;
    mpc_store_preprocessing_data_fn       store_preprocessing_data;
    mpc_load_preprocessing_data_fn        load_preprocessing_data;
    mpc_delete_preprocessing_data_fn      delete_preprocessing_data;
    mpc_create_preprocessed_data_fn       create_preprocessed_data;
    mpc_store_preprocessed_data_fn        store_preprocessed_data;
    mpc_load_preprocessed_data_fn         load_preprocessed_data;
    mpc_delete_preprocessed_data_fn       delete_preprocessed_data;
} mpc_preprocessing_persistency_callbacks_t;

// ============================================================================
// Refresh key persistency callbacks
// ============================================================================

typedef mpc_buffer_t (*mpc_load_refresh_key_seeds_fn)(void* ctx,
                const char* request_id);
typedef void (*mpc_store_refresh_key_seeds_fn)(void* ctx,
                const char* request_id,
                const uint8_t* seeds_buf, size_t seeds_len);
typedef void (*mpc_transform_preprocessed_fn)(void* ctx,
                const char* key_id, const char* request_id,
                void* handler_ctx, void (*handler_fn)(void* handler_ctx,
                    uint64_t index,
                    uint8_t* data_buf, size_t data_len,
                    uint8_t* out_buf, size_t* out_len));
typedef void (*mpc_refresh_commit_fn)(void* ctx,
                const char* key_id, const char* request_id);
typedef void (*mpc_delete_refresh_key_seeds_fn)(void* ctx,
                const char* request_id);
typedef void (*mpc_delete_temporary_key_fn)(void* ctx, const char* key_id);
typedef void (*mpc_store_temporary_key_fn)(void* ctx,
                const char* key_id, int32_t algorithm,
                const uint8_t private_key[32]);

typedef struct {
    void* user_ctx;
    mpc_load_refresh_key_seeds_fn         load_refresh_key_seeds;
    mpc_store_refresh_key_seeds_fn        store_refresh_key_seeds;
    mpc_transform_preprocessed_fn         transform_preprocessed_data;
    mpc_refresh_commit_fn                 commit;
    mpc_delete_refresh_key_seeds_fn       delete_refresh_key_seeds;
    mpc_delete_temporary_key_fn           delete_temporary_key;
    mpc_store_temporary_key_fn            store_temporary_key;
} mpc_refresh_persistency_callbacks_t;

// ============================================================================
// Setup service
// ============================================================================

mpc_status_t mpc_setup_service_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_setup_persistency_callbacks_t* persistency,
    mpc_handle_t* out_handle);

void mpc_setup_service_destroy(mpc_handle_t handle);

mpc_status_t mpc_setup_generate_commitments(
    mpc_handle_t handle,
    const char* key_id,
    const char* tenant_id,
    int32_t algorithm,
    const uint64_t* player_ids, size_t num_players,
    uint8_t t,
    uint64_t ttl,
    const char* derive_master_key_id,
    const uint8_t* derive_chaincode, size_t derive_chaincode_len,
    mpc_buffer_t* out_commitment);

mpc_status_t mpc_setup_store_commitments(
    mpc_handle_t handle,
    const char* key_id,
    const uint8_t* commitments_json, size_t commitments_json_len,
    mpc_buffer_t* out_decommitment);

mpc_status_t mpc_setup_generate_proofs(
    mpc_handle_t handle,
    const char* key_id,
    const uint8_t* decommitments_json, size_t decommitments_json_len,
    mpc_buffer_t* out_proofs);

mpc_status_t mpc_setup_verify_proofs(
    mpc_handle_t handle,
    const char* key_id,
    const uint8_t* proofs_json, size_t proofs_json_len,
    mpc_buffer_t* out_paillier_proofs);

mpc_status_t mpc_setup_create_secret(
    mpc_handle_t handle,
    const char* key_id,
    const uint8_t* paillier_proofs_json, size_t paillier_proofs_json_len,
    char* out_public_key, size_t out_public_key_cap,
    int32_t* out_algorithm);

mpc_status_t mpc_setup_add_user_request(
    mpc_handle_t handle,
    const char* key_id,
    int32_t algorithm,
    const char* new_key_id,
    const uint64_t* player_ids, size_t num_players,
    uint8_t t,
    mpc_buffer_t* out_data);

mpc_status_t mpc_setup_add_user(
    mpc_handle_t handle,
    const char* tenant_id,
    const char* key_id,
    int32_t algorithm,
    uint8_t t,
    const uint8_t* data_json, size_t data_json_len,
    uint64_t ttl,
    mpc_buffer_t* out_commitment);

// ============================================================================
// ECDSA online signing service
// ============================================================================

mpc_status_t mpc_ecdsa_online_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_key_persistency_callbacks_t* key_persistency,
    const mpc_ecdsa_signing_persistency_callbacks_t* signing_persistency,
    mpc_handle_t* out_handle);

void mpc_ecdsa_online_destroy(mpc_handle_t handle);

mpc_status_t mpc_ecdsa_online_start_signing(
    mpc_handle_t handle,
    const char* key_id,
    const char* txid,
    int32_t algorithm,
    const uint8_t* signing_data_json, size_t signing_data_json_len,
    const char* metadata_json,
    const char* players_json,
    const uint64_t* player_ids, size_t num_player_ids,
    mpc_buffer_t* out_mta_requests);

mpc_status_t mpc_ecdsa_online_mta_response(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* requests_json, size_t requests_json_len,
    uint32_t version,
    uint64_t* out_player_id,
    mpc_buffer_t* out_response);

mpc_status_t mpc_ecdsa_online_mta_verify(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* responses_json, size_t responses_json_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_deltas);

mpc_status_t mpc_ecdsa_online_get_si(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* deltas_json, size_t deltas_json_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_sis);

mpc_status_t mpc_ecdsa_online_get_signature(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* s_json, size_t s_json_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_signatures);

mpc_status_t mpc_ecdsa_online_cancel(
    mpc_handle_t handle,
    const char* txid);

// ============================================================================
// ECDSA offline signing service
// ============================================================================

mpc_status_t mpc_ecdsa_offline_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_key_persistency_callbacks_t* key_persistency,
    const mpc_preprocessing_persistency_callbacks_t* preprocessing_persistency,
    mpc_handle_t* out_handle);

void mpc_ecdsa_offline_destroy(mpc_handle_t handle);

mpc_status_t mpc_ecdsa_offline_start_preprocessing(
    mpc_handle_t handle,
    const char* tenant_id,
    const char* key_id,
    const char* request_id,
    uint32_t start_index,
    uint32_t count,
    uint32_t total_count,
    const uint64_t* player_ids, size_t num_player_ids,
    mpc_buffer_t* out_mta_requests);

mpc_status_t mpc_ecdsa_offline_mta_response(
    mpc_handle_t handle,
    const char* request_id,
    const uint8_t* requests_json, size_t requests_json_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_response);

mpc_status_t mpc_ecdsa_offline_mta_verify(
    mpc_handle_t handle,
    const char* request_id,
    const uint8_t* responses_json, size_t responses_json_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_deltas);

mpc_status_t mpc_ecdsa_offline_store_presigning(
    mpc_handle_t handle,
    const char* request_id,
    const uint8_t* deltas_json, size_t deltas_json_len,
    uint64_t* out_player_id,
    char* out_key_id, size_t out_key_id_cap);

mpc_status_t mpc_ecdsa_offline_sign(
    mpc_handle_t handle,
    const char* key_id,
    const char* txid,
    const uint8_t* signing_data_json, size_t signing_data_json_len,
    const char* metadata_json,
    const char* players_json,
    const uint64_t* player_ids, size_t num_player_ids,
    uint64_t preprocessed_data_index,
    int32_t protocol_version,
    mpc_buffer_t* out_partial_sigs);

mpc_status_t mpc_ecdsa_offline_signature(
    mpc_handle_t handle,
    const char* key_id,
    const char* txid,
    int32_t algorithm,
    const uint8_t* partial_sigs_json, size_t partial_sigs_json_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_signatures);

mpc_status_t mpc_ecdsa_offline_cancel(
    mpc_handle_t handle,
    const char* request_id);

// ============================================================================
// EdDSA online signing service
// ============================================================================

mpc_status_t mpc_eddsa_online_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_key_persistency_callbacks_t* key_persistency,
    const mpc_eddsa_signing_persistency_callbacks_t* signing_persistency,
    mpc_handle_t* out_handle);

void mpc_eddsa_online_destroy(mpc_handle_t handle);

mpc_status_t mpc_eddsa_online_start_signing(
    mpc_handle_t handle,
    const char* key_id,
    const char* txid,
    const uint8_t* signing_data_json, size_t signing_data_json_len,
    const char* metadata_json,
    const char* players_json,
    const uint64_t* player_ids, size_t num_player_ids,
    mpc_buffer_t* out_commitments);

mpc_status_t mpc_eddsa_online_store_commitments(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* commitments_json, size_t commitments_json_len,
    uint32_t version,
    uint64_t* out_player_id,
    mpc_buffer_t* out_Rs);

mpc_status_t mpc_eddsa_online_broadcast_si(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* Rs_json, size_t Rs_json_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_si);

mpc_status_t mpc_eddsa_online_get_signature(
    mpc_handle_t handle,
    const char* txid,
    const uint8_t* s_json, size_t s_json_len,
    uint64_t* out_player_id,
    mpc_buffer_t* out_signatures);

mpc_status_t mpc_eddsa_online_cancel(
    mpc_handle_t handle,
    const char* request_id);

// ============================================================================
// Offline refresh service
// ============================================================================

mpc_status_t mpc_refresh_create(
    const mpc_platform_callbacks_t* platform,
    const mpc_key_persistency_callbacks_t* key_persistency,
    const mpc_refresh_persistency_callbacks_t* refresh_persistency,
    mpc_handle_t* out_handle);

void mpc_refresh_destroy(mpc_handle_t handle);

mpc_status_t mpc_refresh_key_request(
    mpc_handle_t handle,
    const char* tenant_id,
    const char* key_id,
    const char* request_id,
    const uint64_t* player_ids, size_t num_player_ids,
    mpc_buffer_t* out_encrypted_seeds);

mpc_status_t mpc_refresh_key(
    mpc_handle_t handle,
    const char* key_id,
    const char* request_id,
    const uint8_t* encrypted_seeds_json, size_t encrypted_seeds_json_len,
    char* out_public_key, size_t out_public_key_cap);

mpc_status_t mpc_refresh_key_fast_ack(
    mpc_handle_t handle,
    const char* tenant_id,
    const char* key_id,
    const char* request_id);

mpc_status_t mpc_refresh_cancel(
    mpc_handle_t handle,
    const char* request_id);

#ifdef __cplusplus
}
#endif

#endif // MPC_COSIGNER_C_API_H
