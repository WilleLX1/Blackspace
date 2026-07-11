import { describe, expect, it } from "vitest";
import { onboardingError } from "./onboarding";

describe("onboarding errors", () => {
  it("turns Firefox aborts into retry-safe guidance", () => {
    const aborted = new DOMException("The operation was aborted.", "AbortError");
    expect(onboardingError(aborted, "mailbox registration")).toContain("safely resume the same signup attempt");
  });

  it("does not claim an invitation was consumed during the server check", () => {
    const aborted = new DOMException("The operation was aborted.", "AbortError");
    expect(onboardingError(aborted, "server check")).toContain("has not been consumed");
  });
});

