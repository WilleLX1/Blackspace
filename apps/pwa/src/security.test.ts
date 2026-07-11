import { afterEach, describe, expect, it, vi } from "vitest";
import { assertV3OnionUrl, deriveTransportMode } from "./security";

describe("transport mode", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("recognises loopback development and HTTPS", () => {
    expect(deriveTransportMode({ protocol: "http:", hostname: "localhost" } as Location)).toBe("compatibility-web-dev");
    expect(deriveTransportMode({ protocol: "https:", hostname: "example.org" } as Location)).toBe("https-web");
  });

  it("rejects ordinary clearnet HTTP", () => {
    expect(deriveTransportMode({ protocol: "http:", hostname: "example.org" } as Location)).toBeNull();
  });

  it("accepts only strict v3 onion origins", () => {
    const host = `${"a".repeat(56)}.onion`;
    expect(deriveTransportMode({ protocol: "http:", hostname: host } as Location)).toBe("tor-web");
    expect(assertV3OnionUrl(`http://${host}`)).toBe(`http://${host}`);
    expect(() => assertV3OnionUrl(`http://${host}:8080`)).toThrow();
    expect(() => assertV3OnionUrl("https://example.org")).toThrow();
  });
});
