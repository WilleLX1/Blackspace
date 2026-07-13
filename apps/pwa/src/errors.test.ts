import { describe, expect, it } from "vitest";
import { errorMessage, explainErrorMessage } from "./errors";

describe("safe client errors", () => {
  it("preserves approved Tauri transport details", () => {
    expect(errorMessage("Tor request timed out.", "Mailbox sync failed.")).toBe("Tor request timed out.");
    expect(errorMessage("Mailbox operation failed with status 503.", "Mailbox sync failed.")).toBe("Mailbox operation failed with status 503.");
    expect(errorMessage("Mailbox rejected an invalid request (status 400).", "Onboarding failed.")).toBe("Mailbox rejected an invalid request (status 400).");
  });

  it("does not expose arbitrary native error strings", () => {
    expect(errorMessage("request failed for http://secret.onion with token abc", "Mailbox sync failed.")).toBe("Mailbox sync failed.");
  });

  it("preserves structured web errors", () => {
    expect(errorMessage(new Error("The invitation is invalid."), "Onboarding failed.")).toBe("The invitation is invalid.");
  });
});

describe("error explanations", () => {
  it("explains a web 401 from the parenthesized status", () => {
    const help = explainErrorMessage("Mailbox operation failed (401).");
    expect(help).toMatch(/capability/i);
  });

  it("explains a Tauri status form too", () => {
    expect(explainErrorMessage("Mailbox delivery is temporarily unavailable (status 503).")).toMatch(/temporarily unavailable/i);
  });

  it("explains the Tor-not-ready case", () => {
    expect(explainErrorMessage("Tor is not ready. Blackspace will not use a direct connection.")).toMatch(/Tor/);
  });

  it("returns undefined when there is nothing useful to add", () => {
    expect(explainErrorMessage("Use a matching vault passphrase of at least 10 characters.")).toBeUndefined();
  });
});
