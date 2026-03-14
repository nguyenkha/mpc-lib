# fb-mpc

TypeScript bindings for the [Fireblocks MPC](https://github.com/fireblocks/mpc-lib) signing library. Provides access to MPC CMP key generation, ECDSA/EdDSA signing, and key refresh from Node.js (via N-API native addon) and browsers (via WASM).

## Installation

```sh
npm install fb-mpc
```

## Prerequisites

Building the native addon requires:

- C++ compiler (GCC, Clang, or MSVC)
- CMake 3.14+
- OpenSSL 1.1.1+
- Node.js 18+

On Ubuntu/Debian:

```sh
apt install build-essential libssl-dev cmake
```

On macOS:

```sh
brew install openssl cmake
```

## Building

```sh
# Build the native addon + TypeScript
npm run build

# Or build components separately:
npm run build:native   # N-API addon (.node)
npm run build:wasm     # WASM module (requires Emscripten)
npm run build:ts       # TypeScript compilation
```

## Quick Start

```typescript
import { getBackend } from "fb-mpc";

// Auto-detects Node.js (N-API) or browser (WASM)
const backend = await getBackend();

// Create a setup service for key generation
const setupService = backend.createSetupService(platform, persistency);
```

### Implementing Callbacks

The library requires you to implement two callback interfaces:

**PlatformService** — provides platform capabilities (random number generation, signing authorization, etc.):

```typescript
import type { PlatformService } from "fb-mpc";

const platform: PlatformService = {
  genRandom(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
  },
  getTenantId(): string {
    return "my-tenant";
  },
  getPlayerId(): bigint {
    return 1n;
  },
  // ... see types.ts for all methods
};
```

**Key Persistency** — provides storage for key material:

```typescript
import type { SetupKeyPersistency } from "fb-mpc";

const persistency: SetupKeyPersistency = {
  storeKey(keyId, algorithm, privateKey, ttl) { /* save to DB */ },
  loadKey(keyId) { /* load from DB */ },
  // ... see types.ts for all methods
};
```

### CMP Key Generation Protocol

The setup protocol runs in 5 rounds between N players:

```typescript
import { SignAlgorithm } from "fb-mpc";

const keyId = "unique-key-id";
const playerIds = [1n, 2n];
const algorithm = SignAlgorithm.ECDSA_SECP256K1;

// Round 1: Generate commitments
const commitment = setupService.generateSetupCommitments(
  keyId, "tenant", algorithm, playerIds, 2, 0n, { masterKeyId: "", chaincode: new Uint8Array(0) },
);

// Round 2: Exchange commitments, get decommitments
const decommitment = setupService.storeSetupCommitments(keyId, allCommitments);

// Round 3: Exchange decommitments, generate ZK proofs
const proofs = setupService.generateSetupProofs(keyId, allDecommitments);

// Round 4: Verify proofs
const paillierProofs = setupService.verifySetupProofs(keyId, allProofs);

// Round 5: Create shared secret
const { publicKey, algorithm: algo } = setupService.createSecret(keyId, allPaillierProofs);

// Clean up
setupService.destroy();
```

## Services

| Service | Description |
|---------|-------------|
| `SetupService` | CMP key generation (distributed key creation) |
| `EcdsaOnlineSigningService` | ECDSA online signing (secp256k1, secp256r1, Stark) |
| `EcdsaOfflineSigningService` | ECDSA offline pre-signing |
| `EddsaOnlineSigningService` | EdDSA signing (Ed25519) |
| `OfflineRefreshService` | Key share refresh without changing the public key |

## Supported Algorithms

| Algorithm | Enum Value |
|-----------|------------|
| ECDSA secp256k1 | `SignAlgorithm.ECDSA_SECP256K1` |
| EdDSA Ed25519 | `SignAlgorithm.EDDSA_ED25519` |
| ECDSA secp256r1 | `SignAlgorithm.ECDSA_SECP256R1` |
| ECDSA Stark | `SignAlgorithm.ECDSA_STARK` |

## Architecture

```
fb-mpc
├── src/ts/          # TypeScript API layer
│   ├── types.ts     # All interfaces, enums, type constants
│   ├── backend.ts   # MpcBackend interface
│   ├── index.ts     # Entry point + runtime detection
│   ├── napi-backend.ts   # Node.js N-API backend
│   └── wasm-backend.ts   # Browser WASM backend
├── src/c-wrapper/   # C API over C++ services
├── src/napi/        # N-API native addon
├── src/wasm/        # WASM/Emscripten bindings
└── demo-ts/         # Demo application
```

The package uses a dual-backend architecture:
- **Node.js**: Loads a native N-API addon (`.node`) for direct C++ interop
- **Browser**: Loads a WASM module compiled via Emscripten

Runtime detection is automatic — `getBackend()` selects the appropriate backend.

## Demo

Run the demo to see the key generation protocol in action:

```sh
npx tsc -p demo-ts/tsconfig.json
node dist/demo/demo-ts/demo.js
```

The demo runs with a mock backend if the native addon is not built.

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.

This package wraps the [Fireblocks MPC library](https://github.com/fireblocks/mpc-lib), which is licensed under GPL-3.0.
