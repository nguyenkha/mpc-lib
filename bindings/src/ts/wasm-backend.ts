import type { MpcBackend } from "./backend.js";
import type {
  PlatformService,
  SetupKeyPersistency,
  CmpKeyPersistency,
  EcdsaSigningPersistency,
  EddsaSigningPersistency,
  PreprocessingPersistency,
  RefreshKeyPersistency,
  SetupService,
  EcdsaOnlineSigningService,
  EcdsaOfflineSigningService,
  EddsaOnlineSigningService,
  OfflineRefreshService,
} from "./types.js";

interface EmscriptenModule {
  ccall(
    ident: string,
    returnType: string | null,
    argTypes: string[],
    args: unknown[],
  ): unknown;
  cwrap(
    ident: string,
    returnType: string | null,
    argTypes: string[],
  ): (...args: unknown[]) => unknown;
  addFunction(func: (...args: unknown[]) => unknown, sig: string): number;
  removeFunction(ptr: number): void;
  _malloc(size: number): number;
  _free(ptr: number): void;
  HEAPU8: Uint8Array;
  HEAPU32: Uint32Array;
  HEAP32: Int32Array;
}

type ModuleFactory = () => Promise<EmscriptenModule>;

let moduleFactory: ModuleFactory | null = null;
let moduleInstance: EmscriptenModule | null = null;

async function loadWasmModule(): Promise<EmscriptenModule> {
  if (moduleInstance) return moduleInstance;

  if (!moduleFactory) {
    // Dynamic import of the Emscripten-generated JS loader
    // @ts-ignore -- WASM module is generated at build time
    const loader = await import("../../build/wasm/mpc_cosigner_wasm.js");
    moduleFactory = (loader.default || loader.createMpcModule) as ModuleFactory;
  }
  moduleInstance = await moduleFactory!();
  return moduleInstance;
}

export class WasmBackend implements MpcBackend {
  private module: EmscriptenModule | null = null;

  async initialize(): Promise<void> {
    this.module = await loadWasmModule();
  }

  private getModule(): EmscriptenModule {
    if (!this.module) {
      throw new Error("WASM module not initialized. Call initialize() first.");
    }
    return this.module;
  }

  createSetupService(
    _platform: PlatformService,
    _persistency: SetupKeyPersistency,
  ): SetupService {
    const _mod = this.getModule();

    // TODO: Implement WASM callback registration using Module.addFunction()
    // This requires:
    // 1. Creating C function pointers from JS functions via addFunction(fn, sig)
    // 2. Allocating callback structs on the WASM heap
    // 3. Calling _mpc_setup_service_create with the struct pointers
    // 4. Wrapping each service method to marshal data to/from WASM heap

    throw new Error(
      "WASM SetupService not yet implemented. " +
      "Use the N-API backend for Node.js."
    );
  }

  createEcdsaOnlineSigningService(
    _platform: PlatformService,
    _keyPersistency: CmpKeyPersistency,
    _signingPersistency: EcdsaSigningPersistency,
  ): EcdsaOnlineSigningService {
    throw new Error("WASM EcdsaOnlineSigningService not yet implemented");
  }

  createEcdsaOfflineSigningService(
    _platform: PlatformService,
    _keyPersistency: CmpKeyPersistency,
    _preprocessingPersistency: PreprocessingPersistency,
  ): EcdsaOfflineSigningService {
    throw new Error("WASM EcdsaOfflineSigningService not yet implemented");
  }

  createEddsaOnlineSigningService(
    _platform: PlatformService,
    _keyPersistency: CmpKeyPersistency,
    _signingPersistency: EddsaSigningPersistency,
  ): EddsaOnlineSigningService {
    throw new Error("WASM EddsaOnlineSigningService not yet implemented");
  }

  createOfflineRefreshService(
    _platform: PlatformService,
    _keyPersistency: CmpKeyPersistency,
    _refreshPersistency: RefreshKeyPersistency,
  ): OfflineRefreshService {
    throw new Error("WASM OfflineRefreshService not yet implemented");
  }
}
