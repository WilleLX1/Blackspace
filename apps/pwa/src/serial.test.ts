import { describe, expect, it } from "vitest";
import { createSerialRunner } from "./serial";

describe("createSerialRunner", () => {
  it("runs tasks strictly one after another", async () => {
    const run = createSerialRunner();
    const order: string[] = [];
    let releaseFirst = () => {};
    const gate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const first = run(async () => { order.push("first:start"); await gate; order.push("first:end"); });
    const second = run(async () => { order.push("second"); });
    await Promise.resolve();
    expect(order).toEqual(["first:start"]);
    releaseFirst();
    await Promise.all([first, second]);
    expect(order).toEqual(["first:start", "first:end", "second"]);
  });

  it("returns each task's own result", async () => {
    const run = createSerialRunner();
    expect(await run(async () => 7)).toBe(7);
    expect(await run(async () => "eight")).toBe("eight");
  });

  it("keeps running tasks after one rejects", async () => {
    const run = createSerialRunner();
    await expect(run(async () => { throw new Error("boom"); })).rejects.toThrow("boom");
    expect(await run(async () => "still alive")).toBe("still alive");
  });
});
