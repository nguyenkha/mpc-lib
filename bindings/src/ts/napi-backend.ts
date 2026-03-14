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

// The native addon exports classes directly
interface NativeAddon {
  SetupService: new (
    platform: PlatformService,
    persistency: SetupKeyPersistency,
  ) => NativeSetupService;
  EcdsaOnlineSigningService: new (
    platform: PlatformService,
    keyPersistency: CmpKeyPersistency,
    signingPersistency: EcdsaSigningPersistency,
  ) => NativeEcdsaOnlineService;
  EddsaOnlineSigningService: new (
    platform: PlatformService,
    keyPersistency: CmpKeyPersistency,
    signingPersistency: EddsaSigningPersistency,
  ) => NativeEddsaOnlineService;
}

interface NativeSetupService {
  generateSetupCommitments(...args: unknown[]): Uint8Array;
  storeSetupCommitments(keyId: string, commitments: Uint8Array): Uint8Array;
  generateSetupProofs(keyId: string, decommitments: Uint8Array): Uint8Array;
  verifySetupProofs(keyId: string, proofs: Uint8Array): Uint8Array;
  createSecret(
    keyId: string,
    proofs: Uint8Array,
  ): { publicKey: string; algorithm: number };
  destroy(): void;
}

interface NativeEcdsaOnlineService {
  cancelSigning(txId: string): void;
  destroy(): void;
}

interface NativeEddsaOnlineService {
  cancelSigning(txId: string): void;
  destroy(): void;
}

let addon: NativeAddon | null = null;

function loadAddon(): NativeAddon {
  if (addon) return addon;
  try {
    // Try loading from build directory
    addon = require("../../build/Release/mpc_cosigner.node") as NativeAddon;
  } catch {
    try {
      // Try loading from prebuild
      addon = require("../../prebuilds/mpc_cosigner.node") as NativeAddon;
    } catch {
      throw new Error(
        "Native addon not found. Build with: npm run build:native",
      );
    }
  }
  return addon;
}

export class NapiBackend implements MpcBackend {
  createSetupService(
    platform: PlatformService,
    persistency: SetupKeyPersistency,
  ): SetupService {
    const native = loadAddon();
    const svc = new native.SetupService(platform, persistency);

    return {
      generateSetupCommitments(keyId, tenantId, algorithm, playerIds, t, ttl, deriveFrom) {
        return svc.generateSetupCommitments(
          keyId, tenantId, algorithm, playerIds, t, ttl, deriveFrom,
        );
      },
      storeSetupCommitments(keyId, commitments) {
        // Deserialize the returned buffer into SetupDecommitment
        const buf = svc.storeSetupCommitments(keyId, commitments as unknown as Uint8Array);
        // For MVP, return the raw decommitment object
        // TODO: parse the binary buffer into a structured SetupDecommitment
        return buf as unknown as ReturnType<SetupService["storeSetupCommitments"]>;
      },
      generateSetupProofs(keyId, decommitments) {
        const buf = svc.generateSetupProofs(keyId, decommitments as unknown as Uint8Array);
        return buf as unknown as ReturnType<SetupService["generateSetupProofs"]>;
      },
      verifySetupProofs(keyId, proofs) {
        const buf = svc.verifySetupProofs(keyId, proofs as unknown as Uint8Array);
        return buf as unknown as ReturnType<SetupService["verifySetupProofs"]>;
      },
      createSecret(keyId, paillierProofs) {
        const result = svc.createSecret(keyId, paillierProofs as unknown as Uint8Array);
        return { publicKey: result.publicKey, algorithm: result.algorithm };
      },
      addUserRequest() {
        throw new Error("Not implemented yet");
      },
      addUser() {
        throw new Error("Not implemented yet");
      },
      destroy() {
        svc.destroy();
      },
    };
  }

  createEcdsaOnlineSigningService(
    platform: PlatformService,
    keyPersistency: CmpKeyPersistency,
    signingPersistency: EcdsaSigningPersistency,
  ): EcdsaOnlineSigningService {
    const native = loadAddon();
    const svc = new native.EcdsaOnlineSigningService(
      platform, keyPersistency, signingPersistency,
    );

    return {
      startSigning() { throw new Error("Not implemented yet"); },
      mtaResponse() { throw new Error("Not implemented yet"); },
      mtaVerify() { throw new Error("Not implemented yet"); },
      getSi() { throw new Error("Not implemented yet"); },
      getCmpSignature() { throw new Error("Not implemented yet"); },
      cancelSigning(txId) { svc.cancelSigning(txId); },
      destroy() { svc.destroy(); },
    } as EcdsaOnlineSigningService;
  }

  createEcdsaOfflineSigningService(
    _platform: PlatformService,
    _keyPersistency: CmpKeyPersistency,
    _preprocessingPersistency: PreprocessingPersistency,
  ): EcdsaOfflineSigningService {
    throw new Error("EcdsaOfflineSigningService not yet implemented in N-API backend");
  }

  createEddsaOnlineSigningService(
    platform: PlatformService,
    keyPersistency: CmpKeyPersistency,
    signingPersistency: EddsaSigningPersistency,
  ): EddsaOnlineSigningService {
    const native = loadAddon();
    const svc = new native.EddsaOnlineSigningService(
      platform, keyPersistency, signingPersistency,
    );

    return {
      startSigning() { throw new Error("Not implemented yet"); },
      storeCommitments() { throw new Error("Not implemented yet"); },
      broadcastSi() { throw new Error("Not implemented yet"); },
      getEddsaSignature() { throw new Error("Not implemented yet"); },
      cancelSigning(requestId) { svc.cancelSigning(requestId); },
      destroy() { svc.destroy(); },
    } as EddsaOnlineSigningService;
  }

  createOfflineRefreshService(
    _platform: PlatformService,
    _keyPersistency: CmpKeyPersistency,
    _refreshPersistency: RefreshKeyPersistency,
  ): OfflineRefreshService {
    throw new Error("OfflineRefreshService not yet implemented in N-API backend");
  }
}
