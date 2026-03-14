#include <napi.h>
#include "../c-wrapper/mpc_cosigner_c_api.h"

#include <cstring>
#include <string>
#include <vector>

// ============================================================================
// Helpers: convert between Napi types and C API types
// ============================================================================

static void throw_mpc_error(Napi::Env env, mpc_status_t status) {
    const char* msg;
    switch (status) {
        case MPC_ERR_GENERIC:           msg = "Generic error"; break;
        case MPC_ERR_INTERNAL:          msg = "Internal error"; break;
        case MPC_ERR_INVALID_PARAMS:    msg = "Invalid parameters"; break;
        case MPC_ERR_BAD_KEY:           msg = "Bad key"; break;
        case MPC_ERR_INVALID_TRANSACTION: msg = "Invalid transaction"; break;
        case MPC_ERR_UNKNOWN_ALGORITHM: msg = "Unknown algorithm"; break;
        case MPC_ERR_UNAUTHORIZED:      msg = "Unauthorized"; break;
        case MPC_ERR_REJECTED:          msg = "Rejected"; break;
        case MPC_ERR_BUSY:              msg = "Busy"; break;
        case MPC_ERR_UNKNOWN_TXID:      msg = "Unknown transaction ID"; break;
        default:                         msg = "Unknown error"; break;
    }
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
}

static Napi::Buffer<uint8_t> buffer_from_mpc(Napi::Env env, mpc_buffer_t& buf) {
    auto result = Napi::Buffer<uint8_t>::Copy(env, buf.data, buf.len);
    mpc_free_buffer(&buf);
    return result;
}

// ============================================================================
// Platform callbacks: bridge JS objects to C function pointers
// ============================================================================

struct NapiPlatformCtx {
    Napi::ObjectReference ref;  // prevent GC
};

static void napi_gen_random(void* ctx, size_t len, uint8_t* out) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto fn = obj.Get("genRandom").As<Napi::Function>();
    auto result = fn.Call(obj, {Napi::Number::New(obj.Env(), static_cast<double>(len))});
    auto buf = result.As<Napi::Buffer<uint8_t>>();
    memcpy(out, buf.Data(), std::min(len, buf.Length()));
}

static size_t napi_get_tenant_id(void* ctx, char* out, size_t out_cap) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto fn = obj.Get("getCurrentTenantId").As<Napi::Function>();
    auto result = fn.Call(obj, {}).As<Napi::String>().Utf8Value();
    size_t len = std::min(result.size(), out_cap - 1);
    memcpy(out, result.c_str(), len);
    return len;
}

static uint64_t napi_get_id_from_keyid(void* ctx, const char* key_id) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto fn = obj.Get("getIdFromKeyId").As<Napi::Function>();
    auto result = fn.Call(obj, {Napi::String::New(obj.Env(), key_id)});
    return result.As<Napi::BigInt>().Uint64Value(nullptr);
}

static void napi_derive_initial_share(void* ctx,
    const char* master_key_id,
    const uint8_t* chaincode, size_t cc_len,
    int32_t algorithm, uint8_t out_key[32]) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto env = obj.Env();
    auto fn = obj.Get("deriveInitialShare").As<Napi::Function>();

    auto derive_obj = Napi::Object::New(env);
    derive_obj.Set("masterKeyId", Napi::String::New(env, master_key_id ? master_key_id : ""));
    derive_obj.Set("chaincode", Napi::Buffer<uint8_t>::Copy(env, chaincode, cc_len));

    auto result = fn.Call(obj, {derive_obj, Napi::Number::New(env, algorithm)});
    auto buf = result.As<Napi::Buffer<uint8_t>>();
    memcpy(out_key, buf.Data(), std::min((size_t)32, buf.Length()));
}

static mpc_buffer_t napi_encrypt_for_player(void* ctx, uint64_t id,
    const uint8_t* data, size_t data_len) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto env = obj.Env();
    auto fn = obj.Get("encryptForPlayer").As<Napi::Function>();

    bool lossless;
    auto result = fn.Call(obj, {
        Napi::BigInt::New(env, id),
        Napi::Buffer<uint8_t>::Copy(env, data, data_len)
    });
    auto buf = result.As<Napi::Buffer<uint8_t>>();
    mpc_buffer_t out;
    out.data = static_cast<uint8_t*>(malloc(buf.Length()));
    out.len = buf.Length();
    memcpy(out.data, buf.Data(), buf.Length());
    return out;
}

static mpc_buffer_t napi_decrypt_message(void* ctx,
    const uint8_t* data, size_t data_len) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto env = obj.Env();
    auto fn = obj.Get("decryptMessage").As<Napi::Function>();

    auto result = fn.Call(obj, {Napi::Buffer<uint8_t>::Copy(env, data, data_len)});
    auto buf = result.As<Napi::Buffer<uint8_t>>();
    mpc_buffer_t out;
    out.data = static_cast<uint8_t*>(malloc(buf.Length()));
    out.len = buf.Length();
    memcpy(out.data, buf.Data(), buf.Length());
    return out;
}

static int32_t napi_backup_key(void* ctx,
    const char* key_id, int32_t algorithm,
    const uint8_t private_key[32],
    const uint8_t* metadata_buf, size_t metadata_len,
    const uint8_t* aux_buf, size_t aux_len) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto env = obj.Env();
    auto fn = obj.Get("backupKey").As<Napi::Function>();

    auto result = fn.Call(obj, {
        Napi::String::New(env, key_id),
        Napi::Number::New(env, algorithm),
        Napi::Buffer<uint8_t>::Copy(env, private_key, 32),
        Napi::Buffer<uint8_t>::Copy(env, metadata_buf, metadata_len),
        Napi::Buffer<uint8_t>::Copy(env, aux_buf, aux_len)
    });
    return result.As<Napi::Boolean>().Value() ? 1 : 0;
}

static void napi_on_start_signing(void* ctx,
    const char* key_id, const char* txid,
    const uint8_t* signing_data_buf, size_t signing_data_len,
    const char* metadata_json, const char* players_json,
    int32_t sig_type) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto env = obj.Env();
    auto fn = obj.Get("onStartSigning").As<Napi::Function>();

    fn.Call(obj, {
        Napi::String::New(env, key_id),
        Napi::String::New(env, txid),
        Napi::Buffer<uint8_t>::Copy(env, signing_data_buf, signing_data_len),
        Napi::String::New(env, metadata_json),
        Napi::String::New(env, players_json),
        Napi::Number::New(env, sig_type)
    });
}

static void napi_fill_signing_info(void* ctx,
    const char* metadata, uint32_t* flags_out, size_t count) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto env = obj.Env();
    auto fn = obj.Get("fillSigningInfoFromMetadata").As<Napi::Function>();

    auto result = fn.Call(obj, {
        Napi::String::New(env, metadata),
        Napi::Number::New(env, static_cast<double>(count))
    });
    auto arr = result.As<Napi::Uint32Array>();
    size_t copy_count = std::min(count, arr.ElementLength());
    memcpy(flags_out, arr.Data(), copy_count * sizeof(uint32_t));
}

static int32_t napi_is_client_id(void* ctx, uint64_t player_id) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto env = obj.Env();
    auto fn = obj.Get("isClientId").As<Napi::Function>();
    auto result = fn.Call(obj, {Napi::BigInt::New(env, player_id)});
    return result.As<Napi::Boolean>().Value() ? 1 : 0;
}

static uint64_t napi_now_msec(void* ctx) {
    auto* nc = static_cast<NapiPlatformCtx*>(ctx);
    auto obj = nc->ref.Value();
    if (!obj.Has("nowMsec")) return 0;
    auto fn = obj.Get("nowMsec").As<Napi::Function>();
    auto result = fn.Call(obj, {});
    return result.As<Napi::BigInt>().Uint64Value(nullptr);
}

static mpc_platform_callbacks_t make_platform_callbacks(NapiPlatformCtx* ctx) {
    mpc_platform_callbacks_t cbs = {};
    cbs.user_ctx = ctx;
    cbs.gen_random = napi_gen_random;
    cbs.get_tenant_id = napi_get_tenant_id;
    cbs.get_id_from_keyid = napi_get_id_from_keyid;
    cbs.derive_initial_share = napi_derive_initial_share;
    cbs.encrypt_for_player = napi_encrypt_for_player;
    cbs.decrypt_message = napi_decrypt_message;
    cbs.backup_key = napi_backup_key;
    cbs.on_start_signing = napi_on_start_signing;
    cbs.fill_signing_info = napi_fill_signing_info;
    cbs.is_client_id = napi_is_client_id;
    cbs.now_msec = napi_now_msec;
    return cbs;
}

// ============================================================================
// Key persistency callbacks
// ============================================================================

struct NapiKeyPersistencyCtx {
    Napi::ObjectReference ref;
};

static int32_t napi_key_exist(void* ctx, const char* key_id) {
    auto* nc = static_cast<NapiKeyPersistencyCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto fn = obj.Get("keyExist").As<Napi::Function>();
    return fn.Call(obj, {Napi::String::New(obj.Env(), key_id)})
        .As<Napi::Boolean>().Value() ? 1 : 0;
}

static void napi_load_key(void* ctx, const char* key_id,
    int32_t* out_algorithm, uint8_t out_private_key[32]) {
    auto* nc = static_cast<NapiKeyPersistencyCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto env = obj.Env();
    auto fn = obj.Get("loadKey").As<Napi::Function>();
    auto result = fn.Call(obj, {Napi::String::New(env, key_id)}).As<Napi::Object>();
    *out_algorithm = result.Get("algorithm").As<Napi::Number>().Int32Value();
    auto pk = result.Get("privateKey").As<Napi::Buffer<uint8_t>>();
    memcpy(out_private_key, pk.Data(), std::min((size_t)32, pk.Length()));
}

static size_t napi_get_tenantid_from_keyid(void* ctx,
    const char* key_id, char* out, size_t out_cap) {
    auto* nc = static_cast<NapiKeyPersistencyCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto fn = obj.Get("getTenantIdFromKeyId").As<Napi::Function>();
    auto result = fn.Call(obj, {Napi::String::New(obj.Env(), key_id)})
        .As<Napi::String>().Utf8Value();
    size_t len = std::min(result.size(), out_cap - 1);
    memcpy(out, result.c_str(), len);
    return len;
}

static mpc_buffer_t napi_load_key_metadata(void* ctx,
    const char* key_id, int32_t full_load) {
    auto* nc = static_cast<NapiKeyPersistencyCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto env = obj.Env();
    auto fn = obj.Get("loadKeyMetadata").As<Napi::Function>();
    auto result = fn.Call(obj, {
        Napi::String::New(env, key_id),
        Napi::Boolean::New(env, full_load != 0)
    }).As<Napi::Buffer<uint8_t>>();
    mpc_buffer_t out;
    out.data = static_cast<uint8_t*>(malloc(result.Length()));
    out.len = result.Length();
    memcpy(out.data, result.Data(), result.Length());
    return out;
}

static mpc_buffer_t napi_load_auxiliary_keys(void* ctx, const char* key_id) {
    auto* nc = static_cast<NapiKeyPersistencyCtx*>(ctx);
    auto obj = nc->ref.Value();
    auto fn = obj.Get("loadAuxiliaryKeys").As<Napi::Function>();
    auto result = fn.Call(obj, {Napi::String::New(obj.Env(), key_id)})
        .As<Napi::Buffer<uint8_t>>();
    mpc_buffer_t out;
    out.data = static_cast<uint8_t*>(malloc(result.Length()));
    out.len = result.Length();
    memcpy(out.data, result.Data(), result.Length());
    return out;
}

static mpc_key_persistency_callbacks_t make_key_persistency_callbacks(
    NapiKeyPersistencyCtx* ctx) {
    mpc_key_persistency_callbacks_t cbs = {};
    cbs.user_ctx = ctx;
    cbs.key_exist = napi_key_exist;
    cbs.load_key = napi_load_key;
    cbs.get_tenantid_from_keyid = napi_get_tenantid_from_keyid;
    cbs.load_key_metadata = napi_load_key_metadata;
    cbs.load_auxiliary_keys = napi_load_auxiliary_keys;
    return cbs;
}

// ============================================================================
// Setup service wrapper
// ============================================================================

class NapiSetupService : public Napi::ObjectWrap<NapiSetupService> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "SetupService", {
            InstanceMethod("generateSetupCommitments", &NapiSetupService::GenerateSetupCommitments),
            InstanceMethod("storeSetupCommitments", &NapiSetupService::StoreSetupCommitments),
            InstanceMethod("generateSetupProofs", &NapiSetupService::GenerateSetupProofs),
            InstanceMethod("verifySetupProofs", &NapiSetupService::VerifySetupProofs),
            InstanceMethod("createSecret", &NapiSetupService::CreateSecret),
            InstanceMethod("destroy", &NapiSetupService::Destroy),
        });
        exports.Set("SetupService", func);
        return exports;
    }

    NapiSetupService(const Napi::CallbackInfo& info)
        : Napi::ObjectWrap<NapiSetupService>(info) {
        auto env = info.Env();
        if (info.Length() < 2) {
            Napi::TypeError::New(env, "Expected platform and persistency objects")
                .ThrowAsJavaScriptException();
            return;
        }

        _platform_ctx = new NapiPlatformCtx{Napi::Persistent(info[0].As<Napi::Object>())};
        _persistency_ctx = new NapiKeyPersistencyCtx{Napi::Persistent(info[1].As<Napi::Object>())};

        auto platform_cbs = make_platform_callbacks(_platform_ctx);

        // Build setup persistency callbacks
        // For MVP, use key persistency callbacks for the base
        mpc_setup_persistency_callbacks_t setup_cbs = {};
        setup_cbs.base = make_key_persistency_callbacks(_persistency_ctx);
        setup_cbs.user_ctx = _persistency_ctx;

        // TODO: wire up the remaining setup persistency callbacks
        // (store_key, store_key_metadata, etc.)

        mpc_status_t status = mpc_setup_service_create(
            &platform_cbs, &setup_cbs, &_handle);
        if (status != MPC_OK) {
            throw_mpc_error(env, status);
        }
    }

    ~NapiSetupService() {
        if (_handle) {
            mpc_setup_service_destroy(_handle);
            _handle = nullptr;
        }
        delete _platform_ctx;
        delete _persistency_ctx;
    }

private:
    Napi::Value GenerateSetupCommitments(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        auto key_id = info[0].As<Napi::String>().Utf8Value();
        auto tenant_id = info[1].As<Napi::String>().Utf8Value();
        auto algorithm = info[2].As<Napi::Number>().Int32Value();

        auto player_ids_arr = info[3].As<Napi::Array>();
        std::vector<uint64_t> player_ids(player_ids_arr.Length());
        for (uint32_t i = 0; i < player_ids_arr.Length(); i++) {
            player_ids[i] = player_ids_arr.Get(i).As<Napi::BigInt>().Uint64Value(nullptr);
        }

        auto t = info[4].As<Napi::Number>().Uint32Value();
        auto ttl = info[5].As<Napi::BigInt>().Uint64Value(nullptr);

        const char* derive_key_id = nullptr;
        const uint8_t* derive_cc = nullptr;
        size_t derive_cc_len = 0;
        std::string derive_key_str;
        if (info.Length() > 6 && info[6].IsObject()) {
            auto derive = info[6].As<Napi::Object>();
            if (derive.Has("masterKeyId")) {
                derive_key_str = derive.Get("masterKeyId").As<Napi::String>().Utf8Value();
                derive_key_id = derive_key_str.c_str();
            }
            if (derive.Has("chaincode")) {
                auto cc = derive.Get("chaincode").As<Napi::Buffer<uint8_t>>();
                derive_cc = cc.Data();
                derive_cc_len = cc.Length();
            }
        }

        mpc_buffer_t out_commitment = {};
        mpc_status_t status = mpc_setup_generate_commitments(
            _handle, key_id.c_str(), tenant_id.c_str(), algorithm,
            player_ids.data(), player_ids.size(),
            static_cast<uint8_t>(t), ttl,
            derive_key_id, derive_cc, derive_cc_len,
            &out_commitment);

        if (status != MPC_OK) {
            throw_mpc_error(env, status);
            return env.Undefined();
        }
        return buffer_from_mpc(env, out_commitment);
    }

    Napi::Value StoreSetupCommitments(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        auto key_id = info[0].As<Napi::String>().Utf8Value();
        auto commitments_buf = info[1].As<Napi::Buffer<uint8_t>>();

        mpc_buffer_t out_decommitment = {};
        mpc_status_t status = mpc_setup_store_commitments(
            _handle, key_id.c_str(),
            commitments_buf.Data(), commitments_buf.Length(),
            &out_decommitment);

        if (status != MPC_OK) {
            throw_mpc_error(env, status);
            return env.Undefined();
        }
        return buffer_from_mpc(env, out_decommitment);
    }

    Napi::Value GenerateSetupProofs(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        auto key_id = info[0].As<Napi::String>().Utf8Value();
        auto decommitments_buf = info[1].As<Napi::Buffer<uint8_t>>();

        mpc_buffer_t out_proofs = {};
        mpc_status_t status = mpc_setup_generate_proofs(
            _handle, key_id.c_str(),
            decommitments_buf.Data(), decommitments_buf.Length(),
            &out_proofs);

        if (status != MPC_OK) {
            throw_mpc_error(env, status);
            return env.Undefined();
        }
        return buffer_from_mpc(env, out_proofs);
    }

    Napi::Value VerifySetupProofs(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        auto key_id = info[0].As<Napi::String>().Utf8Value();
        auto proofs_buf = info[1].As<Napi::Buffer<uint8_t>>();

        mpc_buffer_t out_paillier = {};
        mpc_status_t status = mpc_setup_verify_proofs(
            _handle, key_id.c_str(),
            proofs_buf.Data(), proofs_buf.Length(),
            &out_paillier);

        if (status != MPC_OK) {
            throw_mpc_error(env, status);
            return env.Undefined();
        }
        return buffer_from_mpc(env, out_paillier);
    }

    Napi::Value CreateSecret(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        auto key_id = info[0].As<Napi::String>().Utf8Value();
        auto proofs_buf = info[1].As<Napi::Buffer<uint8_t>>();

        char public_key[256] = {};
        int32_t algorithm = 0;
        mpc_status_t status = mpc_setup_create_secret(
            _handle, key_id.c_str(),
            proofs_buf.Data(), proofs_buf.Length(),
            public_key, sizeof(public_key), &algorithm);

        if (status != MPC_OK) {
            throw_mpc_error(env, status);
            return env.Undefined();
        }

        auto result = Napi::Object::New(env);
        result.Set("publicKey", Napi::String::New(env, public_key));
        result.Set("algorithm", Napi::Number::New(env, algorithm));
        return result;
    }

    Napi::Value Destroy(const Napi::CallbackInfo& info) {
        if (_handle) {
            mpc_setup_service_destroy(_handle);
            _handle = nullptr;
        }
        return info.Env().Undefined();
    }

    mpc_handle_t _handle = nullptr;
    NapiPlatformCtx* _platform_ctx = nullptr;
    NapiKeyPersistencyCtx* _persistency_ctx = nullptr;
};

// ============================================================================
// ECDSA online signing service wrapper
// ============================================================================

class NapiEcdsaOnlineService : public Napi::ObjectWrap<NapiEcdsaOnlineService> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "EcdsaOnlineSigningService", {
            InstanceMethod("startSigning", &NapiEcdsaOnlineService::StartSigning),
            InstanceMethod("cancelSigning", &NapiEcdsaOnlineService::CancelSigning),
            InstanceMethod("destroy", &NapiEcdsaOnlineService::Destroy),
        });
        exports.Set("EcdsaOnlineSigningService", func);
        return exports;
    }

    NapiEcdsaOnlineService(const Napi::CallbackInfo& info)
        : Napi::ObjectWrap<NapiEcdsaOnlineService>(info) {
        auto env = info.Env();
        if (info.Length() < 3) {
            Napi::TypeError::New(env, "Expected platform, keyPersistency, signingPersistency")
                .ThrowAsJavaScriptException();
            return;
        }

        _platform_ctx = new NapiPlatformCtx{Napi::Persistent(info[0].As<Napi::Object>())};
        _key_ctx = new NapiKeyPersistencyCtx{Napi::Persistent(info[1].As<Napi::Object>())};
        _signing_ctx = new NapiKeyPersistencyCtx{Napi::Persistent(info[2].As<Napi::Object>())};

        auto platform_cbs = make_platform_callbacks(_platform_ctx);
        auto key_cbs = make_key_persistency_callbacks(_key_ctx);
        mpc_ecdsa_signing_persistency_callbacks_t signing_cbs = {};
        signing_cbs.user_ctx = _signing_ctx;
        // TODO: wire signing persistency callbacks

        mpc_status_t status = mpc_ecdsa_online_create(
            &platform_cbs, &key_cbs, &signing_cbs, &_handle);
        if (status != MPC_OK) throw_mpc_error(env, status);
    }

    ~NapiEcdsaOnlineService() {
        if (_handle) mpc_ecdsa_online_destroy(_handle);
        delete _platform_ctx;
        delete _key_ctx;
        delete _signing_ctx;
    }

private:
    Napi::Value StartSigning(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        // TODO: implement full parameter marshalling
        return env.Undefined();
    }

    Napi::Value CancelSigning(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        auto txid = info[0].As<Napi::String>().Utf8Value();
        mpc_status_t status = mpc_ecdsa_online_cancel(_handle, txid.c_str());
        if (status != MPC_OK) throw_mpc_error(env, status);
        return env.Undefined();
    }

    Napi::Value Destroy(const Napi::CallbackInfo& info) {
        if (_handle) { mpc_ecdsa_online_destroy(_handle); _handle = nullptr; }
        return info.Env().Undefined();
    }

    mpc_handle_t _handle = nullptr;
    NapiPlatformCtx* _platform_ctx = nullptr;
    NapiKeyPersistencyCtx* _key_ctx = nullptr;
    NapiKeyPersistencyCtx* _signing_ctx = nullptr;
};

// ============================================================================
// EdDSA online signing service wrapper
// ============================================================================

class NapiEddsaOnlineService : public Napi::ObjectWrap<NapiEddsaOnlineService> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "EddsaOnlineSigningService", {
            InstanceMethod("cancelSigning", &NapiEddsaOnlineService::CancelSigning),
            InstanceMethod("destroy", &NapiEddsaOnlineService::Destroy),
        });
        exports.Set("EddsaOnlineSigningService", func);
        return exports;
    }

    NapiEddsaOnlineService(const Napi::CallbackInfo& info)
        : Napi::ObjectWrap<NapiEddsaOnlineService>(info) {
        auto env = info.Env();
        if (info.Length() < 3) {
            Napi::TypeError::New(env, "Expected platform, keyPersistency, signingPersistency")
                .ThrowAsJavaScriptException();
            return;
        }

        _platform_ctx = new NapiPlatformCtx{Napi::Persistent(info[0].As<Napi::Object>())};
        _key_ctx = new NapiKeyPersistencyCtx{Napi::Persistent(info[1].As<Napi::Object>())};
        _signing_ctx = new NapiKeyPersistencyCtx{Napi::Persistent(info[2].As<Napi::Object>())};

        auto platform_cbs = make_platform_callbacks(_platform_ctx);
        auto key_cbs = make_key_persistency_callbacks(_key_ctx);
        mpc_eddsa_signing_persistency_callbacks_t signing_cbs = {};
        signing_cbs.user_ctx = _signing_ctx;

        mpc_status_t status = mpc_eddsa_online_create(
            &platform_cbs, &key_cbs, &signing_cbs, &_handle);
        if (status != MPC_OK) throw_mpc_error(env, status);
    }

    ~NapiEddsaOnlineService() {
        if (_handle) mpc_eddsa_online_destroy(_handle);
        delete _platform_ctx;
        delete _key_ctx;
        delete _signing_ctx;
    }

private:
    Napi::Value CancelSigning(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        auto txid = info[0].As<Napi::String>().Utf8Value();
        mpc_status_t status = mpc_eddsa_online_cancel(_handle, txid.c_str());
        if (status != MPC_OK) throw_mpc_error(env, status);
        return env.Undefined();
    }

    Napi::Value Destroy(const Napi::CallbackInfo& info) {
        if (_handle) { mpc_eddsa_online_destroy(_handle); _handle = nullptr; }
        return info.Env().Undefined();
    }

    mpc_handle_t _handle = nullptr;
    NapiPlatformCtx* _platform_ctx = nullptr;
    NapiKeyPersistencyCtx* _key_ctx = nullptr;
    NapiKeyPersistencyCtx* _signing_ctx = nullptr;
};

// ============================================================================
// Module init
// ============================================================================

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    NapiSetupService::Init(env, exports);
    NapiEcdsaOnlineService::Init(env, exports);
    NapiEddsaOnlineService::Init(env, exports);
    return exports;
}

NODE_API_MODULE(mpc_cosigner, Init)
