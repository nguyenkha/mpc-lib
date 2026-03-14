// WASM bindings entry point
// The C API functions are already exported via EXPORTED_FUNCTIONS in CMakeLists.txt.
// This file exists to ensure the C wrapper is linked into the WASM module.

#include "../c-wrapper/mpc_cosigner_c_api.h"

// Force linker to include the C API symbols
extern "C" {
    // Ensure mpc_free_buffer is available (it's the simplest symbol to reference)
    void* _mpc_wasm_init(void) {
        return (void*)&mpc_free_buffer;
    }
}
