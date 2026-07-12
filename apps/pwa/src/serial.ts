// Serializes async tasks so read-modify-write cycles on the vault — and the
// single MLS ratchet or link sequence counters inside it — never interleave.
// A task that persists a clone taken before another task's persist would
// silently revert that work (forking the MLS ratchet or reusing an AEAD
// nonce), so every state-mutating path must run through the same runner.
export type SerialRunner = <T>(task: () => Promise<T>) => Promise<T>;

export function createSerialRunner(): SerialRunner {
  let tail: Promise<unknown> = Promise.resolve();
  return <T>(task: () => Promise<T>): Promise<T> => {
    const result = tail.then(task, task);
    tail = result.then(() => undefined, () => undefined);
    return result;
  };
}
