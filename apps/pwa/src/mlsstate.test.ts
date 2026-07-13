import { describe, expect, it } from "vitest";
import { openMlsState, randomRootSecret, sealMlsState, type SealedBlob } from "./account";
import { RollbackError, withMlsState, type MlsStateTransport } from "./mlsstate";

// An in-memory CAS store standing in for the mailbox server, plus a hook to
// simulate another device committing between our read and our write.
function memoryStore(root: string, mailboxId: string) {
  let store: { version: number; sealed: SealedBlob } | undefined;
  const transport: MlsStateTransport = {
    async get() {
      return store ? { version: store.version, sealed: store.sealed } : undefined;
    },
    async put(expected, sealed) {
      if ((store?.version ?? 0) !== expected) return "conflict";
      store = { version: expected + 1, sealed };
      return { version: expected + 1 };
    },
  };
  return {
    transport,
    async externalCommit(state: string) {
      const version = (store?.version ?? 0) + 1;
      store = { version, sealed: await sealMlsState(root, mailboxId, state) };
    },
    async currentState() {
      return store ? openMlsState(root, mailboxId, store.sealed) : undefined;
    },
    version: () => store?.version ?? 0,
  };
}

const root = randomRootSecret();
const mailboxId = "11111111-1111-1111-1111-111111111111";

describe("withMlsState", () => {
  it("commits the first write from empty state", async () => {
    const { transport, currentState } = memoryStore(root, mailboxId);
    const outcome = await withMlsState({ transport, rootSecret: root, mailboxId, knownVersion: 0 }, async (state) => {
      expect(state).toBeUndefined();
      return { changed: true, state: "state-v1", result: "ok" };
    });
    expect(outcome.version).toBe(1);
    expect(outcome.result).toBe("ok");
    expect(await currentState()).toBe("state-v1");
  });

  it("skips the write and keeps the version when nothing changed", async () => {
    const { transport } = memoryStore(root, mailboxId);
    await withMlsState({ transport, rootSecret: root, mailboxId, knownVersion: 0 }, async () => ({ changed: true, state: "seed", result: 0 }));
    let putCount = 0;
    const wrapped: MlsStateTransport = { get: transport.get, put: (...args) => { putCount += 1; return transport.put(...args); } };
    const outcome = await withMlsState({ transport: wrapped, rootSecret: root, mailboxId, knownVersion: 1 }, async (state) => {
      expect(state).toBe("seed");
      return { changed: false, result: "unchanged" };
    });
    expect(outcome.version).toBe(1);
    expect(outcome.result).toBe("unchanged");
    expect(putCount).toBe(0);
  });

  it("retries on a lost race and runs the deferred effect exactly once, after commit", async () => {
    const helper = memoryStore(root, mailboxId);
    let opRuns = 0;
    let deferredRuns = 0;
    const outcome = await withMlsState({ transport: helper.transport, rootSecret: root, mailboxId, knownVersion: 0 }, async (state) => {
      opRuns += 1;
      // On the first attempt only, another device commits before our PUT, so our
      // compare-and-swap must fail and we must retry against the fresh state.
      if (opRuns === 1) {
        expect(state).toBeUndefined();
        await helper.externalCommit("from-other-device");
      } else {
        expect(state).toBe("from-other-device");
      }
      return { changed: true, state: `mine-after-${opRuns}`, result: opRuns, deferred: async () => { deferredRuns += 1; } };
    });
    expect(opRuns).toBe(2);
    expect(deferredRuns).toBe(1); // never ran on the losing attempt
    expect(outcome.version).toBe(2);
    expect(await helper.currentState()).toBe("mine-after-2");
  });

  it("refuses to apply a rolled-back server version", async () => {
    const { transport } = memoryStore(root, mailboxId);
    await withMlsState({ transport, rootSecret: root, mailboxId, knownVersion: 0 }, async () => ({ changed: true, state: "v1", result: 0 }));
    // This device already knows version 5; the server offering version 1 is a rollback.
    await expect(
      withMlsState({ transport, rootSecret: root, mailboxId, knownVersion: 5 }, async () => ({ changed: true, state: "x", result: 0 })),
    ).rejects.toBeInstanceOf(RollbackError);
  });

  it("gives up after bounded attempts if it never wins the race", async () => {
    const helper = memoryStore(root, mailboxId);
    await expect(
      withMlsState({ transport: helper.transport, rootSecret: root, mailboxId, knownVersion: 0 }, async () => {
        await helper.externalCommit("always-ahead"); // every attempt is preempted
        return { changed: true, state: "never-lands", result: 0 };
      }),
    ).rejects.toThrow(/Could not commit/);
  });
});
