// The floating-primary guard. Every operation that advances the single shared MLS
// ratchet runs through `withMlsState`: download the current blob, decrypt it, run
// the caller's op against that exact state, then compare-and-swap the new state
// back. If another device committed in between, the CAS is rejected and we retry
// from the fresh state — so a ratchet fork is impossible, and any deposit or ack
// (the `deferred` step) runs only after our state actually committed.

import { openMlsState, sealMlsState, type SealedBlob } from "./account";

// Injected so this module stays transport-agnostic and unit-testable against an
// in-memory server. In production these wrap api.ts get/putMlsState.
export interface MlsStateTransport {
  get(): Promise<{ version: number; sealed: SealedBlob } | undefined>;
  put(expectedVersion: number, sealed: SealedBlob): Promise<{ version: number } | "conflict">;
}

export interface MlsOpResult<T> {
  // Whether the op advanced the MLS state and therefore needs to be committed.
  changed: boolean;
  // The new serialized MLS client state (required when `changed`).
  state?: string;
  // Side effects (deposit envelopes, ack tokens, receipts) that MUST run only
  // after the state commits — never on a losing attempt.
  deferred?: () => Promise<void>;
  result: T;
}

export type MlsOp<T> = (state: string | undefined, version: number) => Promise<MlsOpResult<T>>;

const MAX_ATTEMPTS = 8;

export class RollbackError extends Error {
  constructor(readonly serverVersion: number, readonly knownVersion: number) {
    super("The shared state version went backwards; refusing to apply a rolled-back ratchet.");
  }
}

export interface MlsRunConfig {
  transport: MlsStateTransport;
  rootSecret: string;
  mailboxId: string;
  // The highest version this device has ever committed/observed. A fetched
  // version below this means the server served stale/rolled-back state.
  knownVersion: number;
}

export interface MlsRunOutcome<T> {
  version: number;
  result: T;
}

export async function withMlsState<T>(config: MlsRunConfig, op: MlsOp<T>): Promise<MlsRunOutcome<T>> {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    const current = await config.transport.get();
    if (current && current.version < config.knownVersion) {
      throw new RollbackError(current.version, config.knownVersion);
    }
    const version = current?.version ?? 0;
    const state = current ? await openMlsState(config.rootSecret, config.mailboxId, current.sealed) : undefined;
    const out = await op(state, version);
    if (!out.changed) {
      return { version, result: out.result };
    }
    if (out.state === undefined) throw new Error("A changed MLS op must return the new state.");
    const sealed = await sealMlsState(config.rootSecret, config.mailboxId, out.state);
    const committed = await config.transport.put(version, sealed);
    if (committed === "conflict") continue;
    if (out.deferred) await out.deferred();
    return { version: committed.version, result: out.result };
  }
  throw new Error("Could not commit shared device state; another device kept winning. Try again.");
}

// Builds a transport from the api.ts calls, decoding the server's base64url blob
// into the SealedBlob shape the crypto layer expects.
export function serverTransport(
  origin: string,
  adminCapability: string,
  getMlsState: (origin: string, admin: string) => Promise<{ version: number; size_class: number; ciphertext: string } | undefined>,
  putMlsState: (origin: string, admin: string, expected: number, sealed: SealedBlob) => Promise<{ version: number } | "conflict">,
): MlsStateTransport {
  return {
    async get() {
      const response = await getMlsState(origin, adminCapability);
      if (!response) return undefined;
      return { version: response.version, sealed: { size_class: response.size_class, ciphertext: response.ciphertext } };
    },
    put(expectedVersion, sealed) {
      return putMlsState(origin, adminCapability, expectedVersion, sealed);
    },
  };
}
