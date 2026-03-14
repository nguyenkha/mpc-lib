export * from "./types.js";
export type { MpcBackend } from "./backend.js";

import type { MpcBackend } from "./backend.js";

let _backend: MpcBackend | null = null;

function detectEnvironment(): "node" | "browser" {
  if (
    typeof process !== "undefined" &&
    process.versions != null &&
    process.versions.node != null
  ) {
    return "node";
  }
  return "browser";
}

/**
 * Get the MPC backend, auto-detecting the runtime environment.
 * - Node.js: uses N-API native addon
 * - Browser: uses WASM (Emscripten)
 */
export async function getBackend(): Promise<MpcBackend> {
  if (_backend) return _backend;

  const env = detectEnvironment();
  if (env === "node") {
    const { NapiBackend } = await import("./napi-backend.js");
    _backend = new NapiBackend();
  } else {
    const { WasmBackend } = await import("./wasm-backend.js");
    const backend = new WasmBackend();
    await backend.initialize();
    _backend = backend;
  }
  return _backend;
}

/**
 * Explicitly set the backend (useful for testing or custom configurations).
 */
export function setBackend(backend: MpcBackend): void {
  _backend = backend;
}
