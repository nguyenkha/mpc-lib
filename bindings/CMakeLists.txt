cmake_minimum_required(VERSION 3.13)

set(C_WRAPPER_SOURCES
    src/c-wrapper/mpc_cosigner_c_api.cpp
    src/c-wrapper/callback_shims.cpp
)

if(EMSCRIPTEN)
    # =========================================================================
    # WASM build
    # =========================================================================
    add_executable(mpc_cosigner_wasm
        ${C_WRAPPER_SOURCES}
        src/wasm/wasm_bindings.cpp
    )

    target_include_directories(mpc_cosigner_wasm PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/c-wrapper
    )

    target_link_libraries(mpc_cosigner_wasm PRIVATE cosigner)

    set(EXPORTED_FUNCTIONS
        "_mpc_free_buffer"
        "_mpc_setup_service_create"
        "_mpc_setup_service_destroy"
        "_mpc_setup_generate_commitments"
        "_mpc_setup_store_commitments"
        "_mpc_setup_generate_proofs"
        "_mpc_setup_verify_proofs"
        "_mpc_setup_create_secret"
        "_mpc_setup_add_user_request"
        "_mpc_setup_add_user"
        "_mpc_ecdsa_online_create"
        "_mpc_ecdsa_online_destroy"
        "_mpc_ecdsa_online_start_signing"
        "_mpc_ecdsa_online_mta_response"
        "_mpc_ecdsa_online_mta_verify"
        "_mpc_ecdsa_online_get_si"
        "_mpc_ecdsa_online_get_signature"
        "_mpc_ecdsa_online_cancel"
        "_mpc_ecdsa_offline_create"
        "_mpc_ecdsa_offline_destroy"
        "_mpc_ecdsa_offline_start_preprocessing"
        "_mpc_ecdsa_offline_mta_response"
        "_mpc_ecdsa_offline_mta_verify"
        "_mpc_ecdsa_offline_store_presigning"
        "_mpc_ecdsa_offline_sign"
        "_mpc_ecdsa_offline_signature"
        "_mpc_ecdsa_offline_cancel"
        "_mpc_eddsa_online_create"
        "_mpc_eddsa_online_destroy"
        "_mpc_eddsa_online_start_signing"
        "_mpc_eddsa_online_store_commitments"
        "_mpc_eddsa_online_broadcast_si"
        "_mpc_eddsa_online_get_signature"
        "_mpc_eddsa_online_cancel"
        "_mpc_refresh_create"
        "_mpc_refresh_destroy"
        "_mpc_refresh_key_request"
        "_mpc_refresh_key"
        "_mpc_refresh_key_fast_ack"
        "_mpc_refresh_cancel"
        "_malloc"
        "_free"
    )

    string(REPLACE ";" "," EXPORTED_FUNCTIONS_STR "${EXPORTED_FUNCTIONS}")

    set_target_properties(mpc_cosigner_wasm PROPERTIES
        SUFFIX ".js"
    )

    target_link_options(mpc_cosigner_wasm PRIVATE
        "SHELL:-s MODULARIZE=1"
        "SHELL:-s EXPORT_NAME='createMpcModule'"
        "SHELL:-s EXPORTED_FUNCTIONS='[${EXPORTED_FUNCTIONS_STR}]'"
        "SHELL:-s EXPORTED_RUNTIME_METHODS='[\"ccall\",\"cwrap\",\"addFunction\",\"removeFunction\"]'"
        "SHELL:-s ALLOW_TABLE_GROWTH=1"
        "SHELL:-s ALLOW_MEMORY_GROWTH=1"
        "SHELL:-s TOTAL_MEMORY=67108864"
        "SHELL:-s WASM=1"
    )

else()
    # =========================================================================
    # N-API native addon build
    # =========================================================================

    # cmake-js provides these variables
    if(NOT DEFINED CMAKE_JS_INC)
        message(FATAL_ERROR "Build with cmake-js: npx cmake-js compile")
    endif()

    # Find node-addon-api
    if(NOT DEFINED NODE_ADDON_API_DIR)
        execute_process(
            COMMAND node -p "require('node-addon-api').include"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE NODE_ADDON_API_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        string(REPLACE "\"" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
    endif()

    add_library(mpc_cosigner SHARED
        ${C_WRAPPER_SOURCES}
        src/napi/addon.cpp
    )

    set_target_properties(mpc_cosigner PROPERTIES
        PREFIX ""
        SUFFIX ".node"
    )

    target_compile_definitions(mpc_cosigner PRIVATE
        NAPI_VERSION=8
        NODE_ADDON_API_DISABLE_DEPRECATED
    )

    target_include_directories(mpc_cosigner PRIVATE
        ${CMAKE_JS_INC}
        ${NODE_ADDON_API_DIR}
        ${PROJECT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/c-wrapper
    )

    target_link_libraries(mpc_cosigner PRIVATE
        cosigner
        ${CMAKE_JS_LIB}
    )

    # When building without cmake-js (e.g. standalone cmake), N-API symbols
    # come from the Node.js executable at runtime.
    if(APPLE AND NOT CMAKE_JS_LIB)
        target_link_options(mpc_cosigner PRIVATE -undefined dynamic_lookup)
    endif()

endif()
