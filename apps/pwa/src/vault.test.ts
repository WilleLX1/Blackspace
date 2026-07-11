import { describe, expect, it } from "vitest";
import { recoveryKitEncoding } from "./vault";

describe("recovery kit encoding", () => {
  it("recognizes legacy JSON containers with leading whitespace", () => {
    expect(recoveryKitEncoding(new TextEncoder().encode("\n  {\"format\":\"blackspace-recovery\"}"))).toBe("legacy-json");
  });

  it("treats binary recovery kits as encrypted CBOR", () => {
    expect(recoveryKitEncoding(new Uint8Array([0x01, 0xa3, 0x7b, 0xff]))).toBe("encrypted-cbor");
  });
});
