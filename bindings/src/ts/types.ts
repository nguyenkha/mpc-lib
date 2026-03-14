// ============================================================================
// Byte size constants matching C types
// ============================================================================

/** elliptic_curve256_point_t - compressed EC point (33 bytes) */
export const EC_POINT_SIZE = 33;
/** elliptic_curve256_scalar_t - EC scalar (32 bytes) */
export const EC_SCALAR_SIZE = 32;
/** ed25519_point_t - compressed Ed25519 point (32 bytes) */
export const ED25519_POINT_SIZE = 32;
/** ed25519_scalar_t - Ed25519 scalar (32 bytes) */
export const ED25519_SCALAR_SIZE = 32;
/** commitments_sha256_t - SHA256 hash (32 bytes) */
export const SHA256_SIZE = 32;
/** commitments_commitment_t - salt(32) + hash(32) = 64 bytes */
export const COMMITMENT_SIZE = 64;
/** HDChaincode - BIP32 chaincode (32 bytes) */
export const CHAINCODE_SIZE = 32;

// ============================================================================
// Enums
// ============================================================================

export enum SignAlgorithm {
  ECDSA_SECP256K1 = 0,
  EDDSA_ED25519 = 1,
  ECDSA_SECP256R1 = 2,
  ECDSA_STARK = 3,
}

export enum SigningFlags {
  NONE = 0x00,
  POSITIVE_R = 0x01,
  EDDSA_KECCAK = 0x02,
}

export enum CosignerErrorCode {
  GENERIC_ERROR = 0,
  INTERNAL_ERROR = 1,
  INVALID_PARAMETERS = 2,
  BAD_KEY = 3,
  INVALID_TRANSACTION = 4,
  NOT_ALIGNED_DATA = 5,
  NOT_IMPLEMENTED = 6,
  UNKNOWN_ALGORITHM = 7,
  NO_MEM = 8,
  UNAUTHORIZED = 9,
  REJECTED = 10,
  BUSY = 11,
  BACKUP_FAILED = 12,
  AUTHORIZATION_FAILED = 13,
  DISABLED_DEVICE = 14,
  INVALID_PRESIGNING_INDEX = 15,
  BAD_IMPORTED_PUBLIC_KEY = 16,
  BAD_IMPORTED_PRIVATE_KEY = 17,
  BAD_IMPORTED_KEY_ALREADY_EXISTS = 18,
  NO_SIGNING_INFO_GIVEN = 19,
  PARTIAL_SIGNING_INFO_GIVEN = 20,
}

export enum SigningType {
  MULTI_ROUND_SIGNATURE = 0,
  SINGLE_ROUND_SIGNATURE = 1,
}

// ============================================================================
// Core data types
// ============================================================================

/** Player map: keys are stringified uint64 player IDs */
export type PlayerMap<T> = Record<string, T>;

export interface RecoverableSignature {
  /** 32 bytes - elliptic_curve256_scalar_t */
  r: Uint8Array;
  /** 32 bytes - elliptic_curve256_scalar_t */
  s: Uint8Array;
  /** Recovery ID */
  v: number;
}

export interface EddsaSignature {
  /** 32 bytes - ed25519_point_t */
  R: Uint8Array;
  /** 32 bytes - ed25519_scalar_t */
  s: Uint8Array;
}

export interface SigningBlockData {
  /** Message data to sign */
  data: Uint8Array;
  /** BIP44 HD derivation path */
  path: number[];
}

export interface SigningData {
  /** 32 bytes - HDChaincode */
  chaincode: Uint8Array;
  blocks: SigningBlockData[];
}

export interface ShareDerivationArgs {
  masterKeyId: string;
  chaincode: Uint8Array;
}

// ============================================================================
// Setup service types
// ============================================================================

export interface PublicShare {
  /** 33 bytes - elliptic_curve256_point_t */
  X: Uint8Array;
  /** 33 bytes - elliptic_curve256_point_t */
  schnorrR: Uint8Array;
}

export interface SetupDecommitment {
  /** 32 bytes */
  ack: Uint8Array;
  /** 32 bytes */
  seed: Uint8Array;
  share: PublicShare;
  paillierPublicKey: Uint8Array;
  ringPedersenPublicKey: Uint8Array;
}

export interface SetupZkProofs {
  /** 32 bytes - elliptic_curve256_scalar_t */
  schnorrS: Uint8Array;
  paillierBlumZkp: Uint8Array;
  ringPedersenParamZkp: Uint8Array;
}

export interface AddUserData {
  /** Map of player ID -> encrypted share bytes */
  encryptedShares: PlayerMap<Uint8Array>;
  /** 33 bytes - elliptic_curve256_point_t */
  publicKey: Uint8Array;
}

// ============================================================================
// ECDSA MTA types (passed opaquely between parties)
// ============================================================================

export interface CmpMtaMessage {
  message: Uint8Array;
  commitment: Uint8Array;
  proof: Uint8Array;
}

export interface CmpMtaRequest {
  mta: CmpMtaMessage;
  mtaProofs: PlayerMap<Uint8Array>;
  /** 33 bytes */
  A: Uint8Array;
  /** 33 bytes */
  B: Uint8Array;
  /** 33 bytes */
  Z: Uint8Array;
}

export interface CmpMtaResponse {
  kGammaMta: PlayerMap<CmpMtaMessage>;
  kXMta: PlayerMap<CmpMtaMessage>;
  /** 33 bytes */
  GAMMA: Uint8Array;
  gammaProofs: PlayerMap<Uint8Array>;
}

export interface CmpMtaResponses {
  /** 32 bytes */
  ack: Uint8Array;
  response: CmpMtaResponse[];
}

export interface CmpMtaDeltas {
  /** 32 bytes - elliptic_curve256_scalar_t */
  delta: Uint8Array;
  /** 33 bytes - elliptic_curve256_point_t */
  DELTA: Uint8Array;
  proof: Uint8Array;
}

// ============================================================================
// Key metadata types (serialized as opaque blobs across the C boundary)
// ============================================================================

export interface CmpPlayerInfo {
  /** 33 bytes */
  publicShare: Uint8Array;
  paillierPublicKey: Uint8Array;
  ringPedersenPublicKey: Uint8Array;
}

export interface CmpKeyMetadata {
  /** 33 bytes - public key of all players */
  publicKey: Uint8Array;
  algorithm: SignAlgorithm;
  /** Threshold - players needed for signature */
  t: number;
  /** Total number of players */
  n: number;
  flags: number;
  ttl: bigint;
  /** 32 bytes */
  seed: Uint8Array;
  playersInfo: PlayerMap<CmpPlayerInfo>;
}

export interface PreprocessingMetadata {
  keyId: string;
  algorithm: SignAlgorithm;
  playersIds: bigint[];
  startIndex: number;
  count: number;
  /** 32 bytes */
  ack: Uint8Array;
}

export interface CmpSignaturePreprocessedData {
  /** 32 bytes */
  k: Uint8Array;
  /** 32 bytes */
  chi: Uint8Array;
  /** 33 bytes */
  R: Uint8Array;
}

// ============================================================================
// Cosigner exception
// ============================================================================

export class CosignerError extends Error {
  constructor(
    public readonly code: CosignerErrorCode,
    message?: string,
  ) {
    super(message ?? `Cosigner error: ${CosignerErrorCode[code]}`);
    this.name = "CosignerError";
  }
}

export class UnknownTxIdError extends Error {
  constructor(public readonly txId: string) {
    super(`Unknown transaction ID: ${txId}`);
    this.name = "UnknownTxIdError";
  }
}

// ============================================================================
// Callback interfaces (consumers must implement these)
// ============================================================================

export interface PlatformService {
  genRandom(length: number): Uint8Array;
  getCurrentTenantId(): string;
  getIdFromKeyId(keyId: string): bigint;
  deriveInitialShare(
    deriveFrom: ShareDerivationArgs,
    algorithm: SignAlgorithm,
  ): Uint8Array;
  encryptForPlayer(playerId: bigint, data: Uint8Array): Uint8Array;
  decryptMessage(encryptedData: Uint8Array): Uint8Array;
  backupKey(
    keyId: string,
    algorithm: SignAlgorithm,
    privateKey: Uint8Array,
    metadata: Uint8Array,
    auxiliaryKeys: Uint8Array,
  ): boolean;
  onStartSigning(
    keyId: string,
    txId: string,
    data: SigningData,
    metadataJson: string,
    players: string[],
    signatureType: SigningType,
  ): void;
  fillSigningInfoFromMetadata(
    metadata: string,
    count: number,
  ): Uint32Array;
  isClientId(playerId: bigint): boolean;
  nowMsec?(): bigint;
}

export interface CmpKeyPersistency {
  keyExist(keyId: string): boolean;
  loadKey(keyId: string): { algorithm: SignAlgorithm; privateKey: Uint8Array };
  getTenantIdFromKeyId(keyId: string): string;
  loadKeyMetadata(keyId: string, fullLoad: boolean): Uint8Array;
  loadAuxiliaryKeys(keyId: string): Uint8Array;
}

export interface SetupKeyPersistency extends CmpKeyPersistency {
  storeKey(
    keyId: string,
    algorithm: SignAlgorithm,
    privateKey: Uint8Array,
    ttl?: bigint,
  ): void;
  storeKeyMetadata(
    keyId: string,
    metadata: Uint8Array,
    allowOverride: boolean,
  ): void;
  storeAuxiliaryKeys(keyId: string, aux: Uint8Array): void;
  storeKeyIdTenantId(keyId: string, tenantId: string): void;
  storeSetupData(keyId: string, data: Uint8Array): void;
  loadSetupData(keyId: string): Uint8Array;
  storeSetupCommitments(
    keyId: string,
    commitments: PlayerMap<Uint8Array>,
  ): void;
  loadSetupCommitments(keyId: string): PlayerMap<Uint8Array>;
  deleteTemporaryKeyData(keyId: string, deleteKey?: boolean): void;
}

export interface EcdsaSigningPersistency {
  storeCmpSigningData(txId: string, data: Uint8Array): void;
  loadCmpSigningData(txId: string): Uint8Array;
  updateCmpSigningData(txId: string, data: Uint8Array): void;
  deleteTemporarySigningData(txId: string): void;
}

export interface EddsaSigningPersistency {
  storeSigningData(txId: string, data: Uint8Array): void;
  loadSigningData(txId: string): Uint8Array;
  updateSigningData(txId: string, data: Uint8Array): void;
  storeSigningCommitments(
    txId: string,
    commitments: PlayerMap<Uint8Array[]>,
  ): void;
  loadSigningCommitments(txId: string): PlayerMap<Uint8Array[]>;
  deleteTemporarySigningData(txId: string): void;
}

export interface PreprocessingPersistency {
  storePreprocessingMetadata(
    requestId: string,
    data: Uint8Array,
    override?: boolean,
  ): void;
  loadPreprocessingMetadata(requestId: string): Uint8Array;
  storePreprocessingData(
    requestId: string,
    index: bigint,
    data: Uint8Array,
  ): void;
  loadPreprocessingData(requestId: string, index: bigint): Uint8Array;
  deletePreprocessingData(requestId: string): void;
  createPreprocessedData(keyId: string, size: bigint): void;
  storePreprocessedData(
    keyId: string,
    index: bigint,
    data: Uint8Array,
  ): void;
  loadPreprocessedData(keyId: string, index: bigint): Uint8Array;
  deletePreprocessedData(keyId: string): void;
}

export interface RefreshKeyPersistency {
  loadRefreshKeySeeds(requestId: string): PlayerMap<Uint8Array>;
  storeRefreshKeySeeds(
    requestId: string,
    seeds: PlayerMap<Uint8Array>,
  ): void;
  transformPreprocessedDataAndStoreTemporary(
    keyId: string,
    requestId: string,
    handler: (index: bigint, data: CmpSignaturePreprocessedData) => void,
  ): void;
  commit(keyId: string, requestId: string): void;
  deleteRefreshKeySeeds(requestId: string): void;
  deleteTemporaryKey(keyId: string): void;
  storeTemporaryKey(
    keyId: string,
    algorithm: SignAlgorithm,
    privateKey: Uint8Array,
  ): void;
}

// ============================================================================
// Service interfaces
// ============================================================================

export interface SetupService {
  generateSetupCommitments(
    keyId: string,
    tenantId: string,
    algorithm: SignAlgorithm,
    playerIds: bigint[],
    t: number,
    ttl: bigint,
    deriveFrom: ShareDerivationArgs,
  ): Uint8Array;

  storeSetupCommitments(
    keyId: string,
    commitments: PlayerMap<Uint8Array>,
  ): SetupDecommitment;

  generateSetupProofs(
    keyId: string,
    decommitments: PlayerMap<SetupDecommitment>,
  ): SetupZkProofs;

  verifySetupProofs(
    keyId: string,
    proofs: PlayerMap<SetupZkProofs>,
  ): PlayerMap<Uint8Array>;

  createSecret(
    keyId: string,
    paillierProofs: PlayerMap<PlayerMap<Uint8Array>>,
  ): { publicKey: string; algorithm: SignAlgorithm };

  addUserRequest(
    keyId: string,
    algorithm: SignAlgorithm,
    newKeyId: string,
    playerIds: bigint[],
    t: number,
  ): AddUserData;

  addUser(
    tenantId: string,
    keyId: string,
    algorithm: SignAlgorithm,
    t: number,
    data: PlayerMap<AddUserData>,
    ttl: bigint,
  ): Uint8Array;

  destroy(): void;
}

export interface EcdsaOnlineSigningService {
  startSigning(
    keyId: string,
    txId: string,
    algorithm: SignAlgorithm,
    data: SigningData,
    metadataJson: string,
    players: string[],
    playerIds: bigint[],
  ): CmpMtaRequest[];

  mtaResponse(
    txId: string,
    requests: PlayerMap<CmpMtaRequest[]>,
    version: number,
  ): { playerId: bigint; response: CmpMtaResponses };

  mtaVerify(
    txId: string,
    mtaResponses: PlayerMap<CmpMtaResponses>,
  ): { playerId: bigint; deltas: CmpMtaDeltas[] };

  getSi(
    txId: string,
    deltas: PlayerMap<CmpMtaDeltas[]>,
  ): { playerId: bigint; sis: Uint8Array[] };

  getCmpSignature(
    txId: string,
    s: PlayerMap<Uint8Array[]>,
  ): { playerId: bigint; signatures: RecoverableSignature[] };

  cancelSigning(txId: string): void;

  destroy(): void;
}

export interface EcdsaOfflineSigningService {
  startEcdsaSignaturePreprocessing(
    tenantId: string,
    keyId: string,
    requestId: string,
    startIndex: number,
    count: number,
    totalCount: number,
    playerIds: bigint[],
  ): CmpMtaRequest[];

  offlineMtaResponse(
    requestId: string,
    requests: PlayerMap<CmpMtaRequest[]>,
  ): { playerId: bigint; response: CmpMtaResponses };

  offlineMtaVerify(
    requestId: string,
    mtaResponses: PlayerMap<CmpMtaResponses>,
  ): { playerId: bigint; deltas: CmpMtaDeltas[] };

  storePresigningData(
    requestId: string,
    deltas: PlayerMap<CmpMtaDeltas[]>,
  ): { playerId: bigint; keyId: string };

  ecdsaSign(
    keyId: string,
    txId: string,
    data: SigningData,
    metadataJson: string,
    players: string[],
    playerIds: bigint[],
    preprocessedDataIndex: bigint,
    protocolVersion: number,
  ): RecoverableSignature[];

  ecdsaOfflineSignature(
    keyId: string,
    txId: string,
    algorithm: SignAlgorithm,
    partialSigs: PlayerMap<RecoverableSignature[]>,
  ): { playerId: bigint; signatures: RecoverableSignature[] };

  cancelPreprocessing(requestId: string): void;

  destroy(): void;
}

export interface EddsaOnlineSigningService {
  startSigning(
    keyId: string,
    txId: string,
    data: SigningData,
    metadataJson: string,
    players: string[],
    playerIds: bigint[],
  ): Uint8Array[];

  storeCommitments(
    txId: string,
    commitments: PlayerMap<Uint8Array[]>,
    version: number,
  ): { playerId: bigint; Rs: Uint8Array[] };

  broadcastSi(
    txId: string,
    Rs: PlayerMap<Uint8Array[]>,
  ): { playerId: bigint; si: Uint8Array[] };

  getEddsaSignature(
    txId: string,
    s: PlayerMap<Uint8Array[]>,
  ): { playerId: bigint; signatures: EddsaSignature[] };

  cancelSigning(requestId: string): void;

  destroy(): void;
}

export interface OfflineRefreshService {
  refreshKeyRequest(
    tenantId: string,
    keyId: string,
    requestId: string,
    playerIds: bigint[],
  ): PlayerMap<Uint8Array>;

  refreshKey(
    keyId: string,
    requestId: string,
    encryptedSeeds: PlayerMap<PlayerMap<Uint8Array>>,
  ): string;

  refreshKeyFastAck(
    tenantId: string,
    keyId: string,
    requestId: string,
  ): void;

  cancelRefreshKey(requestId: string): void;

  destroy(): void;
}
