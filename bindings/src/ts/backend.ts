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

export interface MpcBackend {
  initialize?(): Promise<void>;

  createSetupService(
    platform: PlatformService,
    persistency: SetupKeyPersistency,
  ): SetupService;

  createEcdsaOnlineSigningService(
    platform: PlatformService,
    keyPersistency: CmpKeyPersistency,
    signingPersistency: EcdsaSigningPersistency,
  ): EcdsaOnlineSigningService;

  createEcdsaOfflineSigningService(
    platform: PlatformService,
    keyPersistency: CmpKeyPersistency,
    preprocessingPersistency: PreprocessingPersistency,
  ): EcdsaOfflineSigningService;

  createEddsaOnlineSigningService(
    platform: PlatformService,
    keyPersistency: CmpKeyPersistency,
    signingPersistency: EddsaSigningPersistency,
  ): EddsaOnlineSigningService;

  createOfflineRefreshService(
    platform: PlatformService,
    keyPersistency: CmpKeyPersistency,
    refreshPersistency: RefreshKeyPersistency,
  ): OfflineRefreshService;
}
