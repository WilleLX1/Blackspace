import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

import {
  claimEnrollmentParcel,
  diagnosticServerInfo,
  finalizeEnrollmentParcel,
  getMlsState,
  listDevices,
  parkEnrollmentParcel,
  putMlsState,
  registerDevice,
  secureDeviceReset,
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

  it("keeps Tor and HTTPS diagnostics on explicit, separate native commands", async () => {
    invokeMock
      .mockResolvedValueOnce({ instance_name: "Tor mailbox" })
      .mockResolvedValueOnce({ instance_name: "HTTPS mailbox" });

    await diagnosticServerInfo("http://example.onion", "tor");
    await diagnosticServerInfo("https://mailbox.example", "https");

    expect(invokeMock.mock.calls).toEqual([
      ["get_server_info", { serverUrl: "http://example.onion" }],
      ["get_https_server_info", { serverUrl: "https://mailbox.example" }],
    ]);
  });

  it("routes enrollment and device management without exposing generic HTTP", async () => {
    invokeMock
      .mockResolvedValueOnce({ parcel_id: crypto.randomUUID() })
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce({ status: "pending_confirmation", eph_pub: "ephemeral" })
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce({ devices: [{ id: crypto.randomUUID(), label: "Desktop", enrolled_at: 1, revoked: false }] })
      .mockResolvedValueOnce({ conflict: false, version: 5, revoked_devices: 2 });

    await parkEnrollmentParcel("http://example.onion", "admin", { parcel_verifier: "verifier", eph_pub: "ephemeral", expires_at: 123 });
    await finalizeEnrollmentParcel("http://example.onion", "admin", "parcel", { nonce: "nonce", size_class: 4096, ciphertext: "opaque" });
    await expect(claimEnrollmentParcel("http://example.onion", "claim")).resolves.toEqual({ status: "pending_confirmation", eph_pub: "ephemeral" });
    await registerDevice("http://example.onion", "admin", crypto.randomUUID(), "Desktop");
    await expect(listDevices("http://example.onion", "admin")).resolves.toHaveLength(1);
    await expect(secureDeviceReset("http://example.onion", "admin", {
      current_device_id: crypto.randomUUID(),
      read_capability_verifier: "read",
      admin_capability_verifier: "admin-next",
      revoke_deposit_capability_ids: [],
      expected_mls_state_version: 4,
      mls_state_size_class: 4096,
      mls_state_ciphertext: "sealed",
    })).resolves.toEqual({ version: 5, revoked_devices: 2 });

    expect(invokeMock.mock.calls.map(([command]) => command)).toEqual([
      "park_enrollment_parcel", "finalize_enrollment_parcel", "claim_enrollment_parcel", "register_device", "list_devices", "secure_device_reset",
    ]);
  });
});
