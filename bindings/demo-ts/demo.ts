/**
 * MPC Library TypeScript Demo
 *
 * Demonstrates how to use the TypeScript bindings for the Fireblocks MPC
 * signing library. Shows:
 *   1. Implementing the PlatformService and SetupKeyPersistency callbacks
 *   2. Running a 2-of-2 CMP key generation (setup) protocol
 *   3. Running a 3-of-3 key generation
 *   4. Service lifecycle management
 *
 * This mirrors the C++ test in test/cosigner/setup_test.cpp.
 *
 * Usage:
 *   npx ts-node demo-ts/demo.ts
 *   # or after building:
 *   node dist/esm/demo.js
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  SignAlgorithm,
  SigningType,
  CosignerError,
  CosignerErrorCode,
  type PlatformService,
  type SetupKeyPersistency,
  type SetupService,
  type SigningData,
  type ShareDerivationArgs,
  type PlayerMap,
  type SetupDecommitment,
  type SetupZkProofs,
  type AddUserData,
  EC_POINT_SIZE,
  EC_SCALAR_SIZE,
  COMMITMENT_SIZE,
  SHA256_SIZE,
} from "../src/ts/types.js";

// ============================================================================
// Helper: hex encoding
// ============================================================================

function toHex(buf: Uint8Array): string {
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ============================================================================
// In-memory PlatformService implementation
// ============================================================================

class DemoPlatformService implements PlatformService {
  constructor(private readonly playerId: bigint) {}

  genRandom(length: number): Uint8Array {
    return randomBytes(length);
  }

  getCurrentTenantId(): string {
    return "demo-tenant";
  }

  getIdFromKeyId(_keyId: string): bigint {
    return this.playerId;
  }

  deriveInitialShare(
    _deriveFrom: ShareDerivationArgs,
    _algorithm: SignAlgorithm,
  ): Uint8Array {
    throw new Error("deriveInitialShare not used in fresh key generation");
  }

  encryptForPlayer(_playerId: bigint, data: Uint8Array): Uint8Array {
    // In a real implementation, encrypt with the player's public key.
    // For demo purposes, pass through unencrypted.
    return data;
  }

  decryptMessage(encryptedData: Uint8Array): Uint8Array {
    return encryptedData;
  }

  backupKey(
    keyId: string,
    algorithm: SignAlgorithm,
    _privateKey: Uint8Array,
    _metadata: Uint8Array,
    _auxiliaryKeys: Uint8Array,
  ): boolean {
    console.log(
      `  [backup] Key ${keyId} (algo=${SignAlgorithm[algorithm]}) backed up`,
    );
    return true;
  }

  onStartSigning(
    _keyId: string,
    _txId: string,
    _data: SigningData,
    _metadataJson: string,
    _players: string[],
    _signatureType: SigningType,
  ): void {
    // Authorization callback - allow everything in demo
  }

  fillSigningInfoFromMetadata(
    _metadata: string,
    count: number,
  ): Uint32Array {
    return new Uint32Array(count);
  }

  isClientId(_playerId: bigint): boolean {
    return false;
  }

  nowMsec(): bigint {
    return BigInt(Date.now());
  }
}

// ============================================================================
// In-memory SetupKeyPersistency implementation
// ============================================================================

interface StoredKeyInfo {
  algorithm: SignAlgorithm;
  privateKey: Uint8Array;
  metadata?: Uint8Array;
  auxiliaryKeys?: Uint8Array;
  tenantId?: string;
}

interface StoredSetupData {
  data: Uint8Array;
}

class DemoSetupPersistency implements SetupKeyPersistency {
  private keys = new Map<string, StoredKeyInfo>();
  private setupData = new Map<string, StoredSetupData>();
  private setupCommitments = new Map<string, PlayerMap<Uint8Array>>();

  // --- CmpKeyPersistency ---

  keyExist(keyId: string): boolean {
    return this.keys.has(keyId);
  }

  loadKey(keyId: string): { algorithm: SignAlgorithm; privateKey: Uint8Array } {
    const info = this.keys.get(keyId);
    if (!info) {
      throw new CosignerError(CosignerErrorCode.BAD_KEY);
    }
    return { algorithm: info.algorithm, privateKey: new Uint8Array(info.privateKey) };
  }

  getTenantIdFromKeyId(_keyId: string): string {
    return "demo-tenant";
  }

  loadKeyMetadata(keyId: string, _fullLoad: boolean): Uint8Array {
    const info = this.keys.get(keyId);
    if (!info || !info.metadata) {
      throw new CosignerError(CosignerErrorCode.BAD_KEY);
    }
    return new Uint8Array(info.metadata);
  }

  loadAuxiliaryKeys(keyId: string): Uint8Array {
    const info = this.keys.get(keyId);
    if (!info || !info.auxiliaryKeys) {
      throw new CosignerError(CosignerErrorCode.BAD_KEY);
    }
    return new Uint8Array(info.auxiliaryKeys);
  }

  // --- SetupKeyPersistency extensions ---

  storeKey(
    keyId: string,
    algorithm: SignAlgorithm,
    privateKey: Uint8Array,
    _ttl?: bigint,
  ): void {
    const existing = this.keys.get(keyId) ?? ({} as StoredKeyInfo);
    existing.algorithm = algorithm;
    existing.privateKey = new Uint8Array(privateKey);
    this.keys.set(keyId, existing);
  }

  storeKeyMetadata(
    keyId: string,
    metadata: Uint8Array,
    allowOverride: boolean,
  ): void {
    const existing = this.keys.get(keyId);
    if (!existing) {
      throw new CosignerError(CosignerErrorCode.BAD_KEY);
    }
    if (!allowOverride && existing.metadata) {
      throw new CosignerError(CosignerErrorCode.INTERNAL_ERROR);
    }
    existing.metadata = new Uint8Array(metadata);
  }

  storeAuxiliaryKeys(keyId: string, aux: Uint8Array): void {
    const existing = this.keys.get(keyId);
    if (!existing) {
      throw new CosignerError(CosignerErrorCode.BAD_KEY);
    }
    existing.auxiliaryKeys = new Uint8Array(aux);
  }

  storeKeyIdTenantId(keyId: string, tenantId: string): void {
    const existing = this.keys.get(keyId);
    if (existing) {
      existing.tenantId = tenantId;
    }
  }

  storeSetupData(keyId: string, data: Uint8Array): void {
    this.setupData.set(keyId, { data: new Uint8Array(data) });
  }

  loadSetupData(keyId: string): Uint8Array {
    const entry = this.setupData.get(keyId);
    if (!entry) {
      throw new CosignerError(CosignerErrorCode.BAD_KEY);
    }
    return new Uint8Array(entry.data);
  }

  storeSetupCommitments(
    keyId: string,
    commitments: PlayerMap<Uint8Array>,
  ): void {
    // Deep copy
    const copy: PlayerMap<Uint8Array> = {};
    for (const [id, buf] of Object.entries(commitments)) {
      copy[id] = new Uint8Array(buf);
    }
    this.setupCommitments.set(keyId, copy);
  }

  loadSetupCommitments(keyId: string): PlayerMap<Uint8Array> {
    const entry = this.setupCommitments.get(keyId);
    if (!entry) {
      return {};
    }
    // Return copies
    const copy: PlayerMap<Uint8Array> = {};
    for (const [id, buf] of Object.entries(entry)) {
      copy[id] = new Uint8Array(buf);
    }
    return copy;
  }

  deleteTemporaryKeyData(keyId: string, deleteKey?: boolean): void {
    this.setupData.delete(keyId);
    this.setupCommitments.delete(keyId);
    if (deleteKey) {
      this.keys.delete(keyId);
    }
  }

  /** Debug: dump a key's private share as hex */
  dumpKey(keyId: string): string {
    const info = this.keys.get(keyId);
    if (!info) return "(not found)";
    return toHex(info.privateKey);
  }
}

// ============================================================================
// Demo: CMP Key Generation Protocol
// ============================================================================

interface PlayerContext {
  id: bigint;
  platform: DemoPlatformService;
  persistency: DemoSetupPersistency;
  service: SetupService;
}

/**
 * Simulates the CMP key generation protocol between multiple players.
 *
 * Protocol rounds:
 *   1. Each player generates commitments
 *   2. Players exchange commitments and generate decommitments
 *   3. Players exchange decommitments and generate ZK proofs
 *   4. Players verify ZK proofs and produce Paillier large-factor proofs
 *   5. Players exchange Paillier proofs and create the shared secret
 *
 * At the end, all players share the same public key but hold different
 * private key shares.
 */
async function runKeyGeneration(
  playerIds: bigint[],
  algorithm: SignAlgorithm,
  createService: (
    platform: PlatformService,
    persistency: SetupKeyPersistency,
  ) => SetupService,
): Promise<void> {
  const keyId = randomUUID();
  const algoName = SignAlgorithm[algorithm];

  console.log(`\n${"=".repeat(60)}`);
  console.log(`Key Generation: ${algoName} with ${playerIds.length} players`);
  console.log(`Key ID: ${keyId}`);
  console.log(`${"=".repeat(60)}`);

  // Create per-player contexts
  const players: PlayerContext[] = playerIds.map((id) => {
    const platform = new DemoPlatformService(id);
    const persistency = new DemoSetupPersistency();
    const service = createService(platform, persistency);
    return { id, platform, persistency, service };
  });

  try {
    // -----------------------------------------------------------------------
    // Round 1: Generate commitments
    // -----------------------------------------------------------------------
    console.log("\n--- Round 1: Generate Commitments ---");
    const commitments: PlayerMap<Uint8Array> = {};

    for (const player of players) {
      console.log(`  Player ${player.id}: generating commitment...`);
      const commitment = player.service.generateSetupCommitments(
        keyId,
        "demo-tenant",
        algorithm,
        playerIds,
        playerIds.length, // t = n (all players needed)
        0n,               // no TTL
        { masterKeyId: "", chaincode: new Uint8Array(0) },
      );
      commitments[player.id.toString()] = commitment;
      console.log(
        `  Player ${player.id}: commitment = ${toHex(commitment).slice(0, 32)}...`,
      );
    }

    // -----------------------------------------------------------------------
    // Round 2: Store commitments, get decommitments
    // -----------------------------------------------------------------------
    console.log("\n--- Round 2: Store Commitments & Decommit ---");
    const decommitments: PlayerMap<SetupDecommitment> = {};

    for (const player of players) {
      console.log(`  Player ${player.id}: storing commitments & decommitting...`);
      const decommitment = player.service.storeSetupCommitments(
        keyId,
        commitments,
      );
      decommitments[player.id.toString()] = decommitment;
      console.log(`  Player ${player.id}: decommitment generated`);
    }

    // -----------------------------------------------------------------------
    // Round 3: Generate ZK proofs
    // -----------------------------------------------------------------------
    console.log("\n--- Round 3: Generate ZK Proofs ---");
    const proofs: PlayerMap<SetupZkProofs> = {};

    for (const player of players) {
      console.log(`  Player ${player.id}: generating ZK proofs...`);
      const proof = player.service.generateSetupProofs(keyId, decommitments);
      proofs[player.id.toString()] = proof;
      console.log(`  Player ${player.id}: ZK proofs generated`);
    }

    // -----------------------------------------------------------------------
    // Round 4: Verify proofs
    // -----------------------------------------------------------------------
    console.log("\n--- Round 4: Verify ZK Proofs ---");
    const paillierProofs: PlayerMap<PlayerMap<Uint8Array>> = {};

    for (const player of players) {
      console.log(`  Player ${player.id}: verifying ZK proofs...`);
      const pProof = player.service.verifySetupProofs(keyId, proofs);
      paillierProofs[player.id.toString()] = pProof;
      console.log(`  Player ${player.id}: proofs verified`);
    }

    // -----------------------------------------------------------------------
    // Round 5: Create secret (finalize)
    // -----------------------------------------------------------------------
    console.log("\n--- Round 5: Create Shared Secret ---");
    let sharedPublicKey: string | null = null;

    for (const player of players) {
      console.log(`  Player ${player.id}: creating secret...`);
      const { publicKey, algorithm: resultAlgo } = player.service.createSecret(
        keyId,
        paillierProofs,
      );
      console.log(
        `  Player ${player.id}: public key = ${toHex(new TextEncoder().encode(publicKey)).slice(0, 40)}...`,
      );
      console.log(
        `  Player ${player.id}: algorithm  = ${SignAlgorithm[resultAlgo]}`,
      );

      if (sharedPublicKey === null) {
        sharedPublicKey = publicKey;
      } else if (sharedPublicKey !== publicKey) {
        throw new Error(
          `Public key mismatch! Player ${player.id} produced a different key.`,
        );
      }
    }

    // -----------------------------------------------------------------------
    // Result
    // -----------------------------------------------------------------------
    console.log(`\n--- Result ---`);
    console.log(`Shared public key: ${sharedPublicKey}`);
    console.log(`All ${players.length} players agree on the same public key.`);

    for (const player of players) {
      const share = player.persistency.dumpKey(keyId);
      console.log(`  Player ${player.id} private share: ${share.slice(0, 16)}...`);
    }
  } finally {
    // Clean up native resources
    for (const player of players) {
      player.service.destroy();
    }
  }
}

// ============================================================================
// Demo: Type Showcase
// ============================================================================

function showTypes(): void {
  console.log("\n" + "=".repeat(60));
  console.log("Type Constants (matching C headers)");
  console.log("=".repeat(60));
  console.log(`  EC_POINT_SIZE    = ${EC_POINT_SIZE} bytes   (elliptic_curve256_point_t)`);
  console.log(`  EC_SCALAR_SIZE   = ${EC_SCALAR_SIZE} bytes   (elliptic_curve256_scalar_t)`);
  console.log(`  COMMITMENT_SIZE  = ${COMMITMENT_SIZE} bytes   (commitments_commitment_t)`);
  console.log(`  SHA256_SIZE      = ${SHA256_SIZE} bytes   (commitments_sha256_t)`);

  console.log("\nSign Algorithms:");
  for (const [name, value] of Object.entries(SignAlgorithm)) {
    if (typeof value === "number") {
      console.log(`  ${name} = ${value}`);
    }
  }

  console.log("\nError Codes:");
  for (const [name, value] of Object.entries(CosignerErrorCode)) {
    if (typeof value === "number") {
      console.log(`  ${name} = ${value}`);
    }
  }
}

// ============================================================================
// Demo: Mock Service (for running without native addon)
// ============================================================================

/**
 * A mock SetupService that simulates the protocol without the native library.
 * Useful for testing TypeScript integration and type correctness.
 */
function createMockSetupService(
  platform: PlatformService,
  _persistency: SetupKeyPersistency,
): SetupService {
  return {
    generateSetupCommitments(
      _keyId, _tenantId, _algorithm, _playerIds, _t, _ttl, _deriveFrom,
    ): Uint8Array {
      // Generate a random commitment (salt + hash = 64 bytes)
      return platform.genRandom(COMMITMENT_SIZE);
    },

    storeSetupCommitments(
      _keyId, _commitments,
    ): SetupDecommitment {
      return {
        ack: platform.genRandom(SHA256_SIZE),
        seed: platform.genRandom(SHA256_SIZE),
        share: {
          X: platform.genRandom(EC_POINT_SIZE),
          schnorrR: platform.genRandom(EC_POINT_SIZE),
        },
        paillierPublicKey: platform.genRandom(256),
        ringPedersenPublicKey: platform.genRandom(128),
      };
    },

    generateSetupProofs(
      _keyId, _decommitments,
    ): SetupZkProofs {
      return {
        schnorrS: platform.genRandom(EC_SCALAR_SIZE),
        paillierBlumZkp: platform.genRandom(512),
        ringPedersenParamZkp: platform.genRandom(256),
      };
    },

    verifySetupProofs(
      _keyId, _proofs,
    ): PlayerMap<Uint8Array> {
      return {};
    },

    createSecret(
      keyId, _paillierProofs,
    ): { publicKey: string; algorithm: SignAlgorithm } {
      // Return a deterministic mock public key derived from keyId
      // so all players produce the same result
      const encoder = new TextEncoder();
      const hash = createHash("sha256").update(encoder.encode(keyId)).digest();
      const pubkey = toHex(hash);
      return { publicKey: pubkey, algorithm: SignAlgorithm.ECDSA_SECP256K1 };
    },

    addUserRequest(
      _keyId, _algorithm, _newKeyId, _playerIds, _t,
    ): AddUserData {
      return {
        encryptedShares: {},
        publicKey: platform.genRandom(EC_POINT_SIZE),
      };
    },

    addUser(
      _tenantId, _keyId, _algorithm, _t, _data, _ttl,
    ): Uint8Array {
      return platform.genRandom(COMMITMENT_SIZE);
    },

    destroy(): void {
      // Nothing to clean up for mock
    },
  };
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║         MPC Library - TypeScript Bindings Demo          ║");
  console.log("╚══════════════════════════════════════════════════════════╝");

  // Show type constants
  showTypes();

  // Determine which service factory to use
  let createService: (
    platform: PlatformService,
    persistency: SetupKeyPersistency,
  ) => SetupService;

  let usingNative = false;

  try {
    // Try loading the native addon - test it eagerly
    const { NapiBackend } = await import("../src/ts/napi-backend.js");
    const backend = new NapiBackend();
    // Eagerly test that the addon loads by creating a dummy service
    const testPlatform = new DemoPlatformService(0n);
    const testPersistency = new DemoSetupPersistency();
    const testSvc = backend.createSetupService(testPlatform, testPersistency);
    testSvc.destroy();
    // If we got here, native addon works
    createService = (p, k) => backend.createSetupService(p, k);
    usingNative = true;
    console.log("\n[Using native N-API backend]");
  } catch {
    // Fall back to mock
    createService = createMockSetupService;
    console.log("\n[Native addon not available, using mock backend]");
    console.log("[Build with `npm run build:native` for real MPC operations]");
  }

  // Run key generation demos
  console.log("\n" + "=".repeat(60));
  console.log("Demo 1: 2-of-2 ECDSA secp256k1 key generation");
  console.log("=".repeat(60));
  await runKeyGeneration(
    [1n, 2n],
    SignAlgorithm.ECDSA_SECP256K1,
    createService,
  );

  console.log("\n" + "=".repeat(60));
  console.log("Demo 2: 3-of-3 EdDSA Ed25519 key generation");
  console.log("=".repeat(60));
  await runKeyGeneration(
    [1n, 2n, 3n],
    SignAlgorithm.EDDSA_ED25519,
    createService,
  );

  if (!usingNative) {
    console.log("\n" + "=".repeat(60));
    console.log("Demo 3: 2-of-2 ECDSA secp256r1 key generation");
    console.log("=".repeat(60));
    await runKeyGeneration(
      [10n, 20n],
      SignAlgorithm.ECDSA_SECP256R1,
      createService,
    );
  }

  // Demonstrate error handling
  console.log("\n" + "=".repeat(60));
  console.log("Demo: Error Handling");
  console.log("=".repeat(60));

  try {
    throw new CosignerError(CosignerErrorCode.BAD_KEY, "Key 'abc' not found");
  } catch (e) {
    if (e instanceof CosignerError) {
      console.log(`  Caught CosignerError: code=${CosignerErrorCode[e.code]}, message="${e.message}"`);
    }
  }

  // Demonstrate persistency usage
  console.log("\n" + "=".repeat(60));
  console.log("Demo: In-Memory Persistency");
  console.log("=".repeat(60));

  const persistency = new DemoSetupPersistency();
  const testKey = new Uint8Array(32);
  testKey.fill(0x42);

  persistency.storeKey("test-key-1", SignAlgorithm.ECDSA_SECP256K1, testKey);
  console.log(`  Stored key: ${persistency.dumpKey("test-key-1")}`);

  const loaded = persistency.loadKey("test-key-1");
  console.log(`  Loaded key: algo=${SignAlgorithm[loaded.algorithm]}, ` +
    `key=${toHex(loaded.privateKey).slice(0, 16)}...`);

  console.log(`  Key exists: ${persistency.keyExist("test-key-1")}`);
  console.log(`  Missing key exists: ${persistency.keyExist("nonexistent")}`);

  try {
    persistency.loadKey("nonexistent");
  } catch (e) {
    if (e instanceof CosignerError) {
      console.log(`  loadKey("nonexistent") threw: ${CosignerErrorCode[e.code]}`);
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("Demo complete!");
  console.log("=".repeat(60));
}

main().catch(console.error);
