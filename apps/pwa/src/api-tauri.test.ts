import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

import {
  claimEnrollmentParcel,
  getMlsState,
  listDevices,
  parkEnrollmentParcel,
  putMlsState,
  registerDevice,
  revokeDevice,
} from "./api";

describe("Tor Native multi-device API bridge", () => {
  beforeEach(() => {
    Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: true, value: {} });
    invokeMock.mockReset();
  });
  afterEach(() => { delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__; });

  it("routes shared-state reads and CAS conflicts through typed Tauri commands", async () => {
    invokeMock.mockResolvedValueOnce({ version: 4, size_class: 4096, ciphertext: "sealed" });
    await expect(getMlsState("http://example.onion", "admin")).resolves.toEqual({ version: 4, size_class: 4096, ciphertext: "sealed" });
    expect(invokeMock).toHaveBeenLastCalledWith("get_mls_state", { serverUrl: "http://example.onion", adminCapability: "admin" });

    invokeMock.mockResolvedValueOnce({ conflict: true });
    await expect(putMlsState("http://example.onion", "admin", 4, { size_class: 4096, ciphertext: "next" })).resolves.toBe("conflict");
  });

  it("routes enrollment and device management without exposing generic HTTP", async () => {
    invokeMock
      .mockResolvedValueOnce({ parcel_id: crypto.randomUUID() })
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce({ devices: [{ id: crypto.randomUUID(), label: "Desktop", enrolled_at: 1, revoked: false }] })
      .mockResolvedValueOnce(undefined);

    await parkEnrollmentParcel("http://example.onion", "admin", { ciphertext: "opaque" });
    await expect(claimEnrollmentParcel("http://example.onion", "claim")).resolves.toBeUndefined();
    await registerDevice("http://example.onion", "admin", crypto.randomUUID(), "Desktop");
    await expect(listDevices("http://example.onion", "admin")).resolves.toHaveLength(1);
    await revokeDevice("http://example.onion", "admin", crypto.randomUUID());

    expect(invokeMock.mock.calls.map(([command]) => command)).toEqual([
      "park_enrollment_parcel", "claim_enrollment_parcel", "register_device", "list_devices", "revoke_device",
    ]);
  });
});
