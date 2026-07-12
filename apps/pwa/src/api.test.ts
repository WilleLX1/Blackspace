import { afterEach, describe, expect, it, vi } from "vitest";
import { revokeDepositCapability, serverInfo } from "./api";

describe("mailbox HTTP response handling", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("accepts a successful empty response for no-content operations", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(revokeDepositCapability("https://mailbox.example", "admin", crypto.randomUUID())).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("reports an empty JSON response without exposing browser parser errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 200 })));

    await expect(serverInfo("https://mailbox.example")).rejects.toThrow("Mailbox returned an empty response.");
  });
});
