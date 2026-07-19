import { invoke } from "@tauri-apps/api/core";
import { detectTransportMode, validateServerUrl } from "./security";
import type { DepositTarget, KeyPackageWire, ServerInfo } from "./model";

const isTauri = () => "__TAURI_INTERNALS__" in window;

class MailboxOperationError extends Error {
  constructor(readonly status: number) {
    super(`Mailbox operation failed (${status}).`);
  }
}

async function jsonRequest<T>(origin: string, path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${origin}${path}`, { redirect: "error", credentials: "omit", cache: "no-store", ...init });
  if (!response.ok) throw new MailboxOperationError(response.status);
  const body = await response.text();
  if (!body.trim()) throw new Error("Mailbox returned an empty response.");
  try { return JSON.parse(body) as T; }
  catch { throw new Error("Mailbox returned an invalid JSON response."); }
}

async function noContentRequest(origin: string, path: string, init?: RequestInit): Promise<void> {
  const response = await fetch(`${origin}${path}`, { redirect: "error", credentials: "omit", cache: "no-store", ...init });
  if (!response.ok) throw new MailboxOperationError(response.status);
}

export function ownOrigin(onionOrigin: string, httpsOrigin?: string): string {
  const mode = detectTransportMode();
  if (mode === "compatibility-web-dev") return window.location.origin;
  if (mode === "tor-web") return validateServerUrl(onionOrigin, mode);
  if (mode === "https-web" && httpsOrigin) return validateServerUrl(httpsOrigin, mode);
  return onionOrigin;
}

export function targetOrigin(target: DepositTarget): string {
  const mode = detectTransportMode();
  if (mode === "tor-native" || mode === "tor-web") return validateServerUrl(target.onion_url, mode);
  if (mode === "https-web") {
    if (!target.https_url) throw new Error("This contact is Tor-only. Open Blackspace through Tor to message them.");
    return validateServerUrl(target.https_url, mode);
  }
  return target.https_url ?? window.location.origin;
}

export async function serverInfo(origin: string): Promise<ServerInfo> {
  if (isTauri()) return invoke("get_server_info", { serverUrl: origin });
  return jsonRequest(origin, "/v1/info");
}

// Diagnostics deliberately keep these probes separate. In the native client,
// the Tor probe stays behind the managed SOCKS boundary while the HTTPS probe
// uses a dedicated HTTPS-only command; neither path is used as a delivery fallback.
export async function diagnosticServerInfo(origin: string, transport: "tor" | "https"): Promise<ServerInfo> {
  if (isTauri()) return invoke(transport === "tor" ? "get_server_info" : "get_https_server_info", { serverUrl: origin });
  return jsonRequest(origin, "/v1/info");
}

export async function provisionMailbox(origin: string, registrationToken: string, request: object): Promise<{ mailbox_id: string; initial_deposit_capability_id: string }> {
  if (isTauri()) return invoke("provision_mailbox", { serverUrl: origin, registrationToken, request });
  return jsonRequest(origin, "/v1/mailboxes", {
    method: "POST", headers: { "content-type": "application/json", authorization: `BlackspaceRegistration ${registrationToken}` }, body: JSON.stringify(request),
  });
}

export async function createDepositCapability(origin: string, adminCapability: string, verifier: string): Promise<{ capability_id: string }> {
  if (isTauri()) return invoke("create_deposit_capability", { serverUrl: origin, adminCapability, request: { verifier, expires_at: null } });
  return jsonRequest(origin, "/v1/mailbox/deposit-capabilities", {
    method: "POST", headers: { "content-type": "application/json", authorization: `BlackspaceAdmin ${adminCapability}` }, body: JSON.stringify({ verifier, expires_at: null }),
  });
}

export async function revokeDepositCapability(origin: string, adminCapability: string, capabilityId: string): Promise<void> {
  if (isTauri()) { await invoke("revoke_deposit_capability", { serverUrl: origin, adminCapability, capabilityId }); return; }
  await noContentRequest(origin, `/v1/mailbox/deposit-capabilities/${encodeURIComponent(capabilityId)}`, {
    method: "DELETE", headers: { authorization: `BlackspaceAdmin ${adminCapability}` },
  });
}

export async function publishKeyPackages(origin: string, adminCapability: string, keyPackages: KeyPackageWire[]): Promise<void> {
  const request = { key_packages: keyPackages };
  if (isTauri()) { await invoke("publish_key_packages", { serverUrl: origin, adminCapability, request }); return; }
  await jsonRequest(origin, "/v1/mailbox/key-packages", {
    method: "POST", headers: { "content-type": "application/json", authorization: `BlackspaceAdmin ${adminCapability}` }, body: JSON.stringify(request),
  });
}

export async function recoverMailbox(origin: string, oldAdminCapability: string, request: object): Promise<{ deposit_capability_ids: string[] }> {
  if (isTauri()) return invoke("recover_mailbox", { serverUrl: origin, oldAdminCapability, request });
  return jsonRequest(origin, "/v1/mailbox/recover", {
    method: "POST", headers: { "content-type": "application/json", authorization: `BlackspaceAdmin ${oldAdminCapability}` }, body: JSON.stringify(request),
  });
}

export async function rotateReadCapability(origin: string, adminCapability: string, verifier: string): Promise<void> {
  if (isTauri()) { await invoke("rotate_read_capability", { serverUrl: origin, adminCapability, request: { read_capability_verifier: verifier } }); return; }
  await jsonRequest(origin, "/v1/mailbox/read-capability/rotate", {
    method: "POST", headers: { "content-type": "application/json", authorization: `BlackspaceAdmin ${adminCapability}` }, body: JSON.stringify({ read_capability_verifier: verifier }),
  });
}

export async function claimKeyPackage(target: DepositTarget): Promise<KeyPackageWire> {
  if (isTauri()) {
    const response = await invoke<{ key_package: KeyPackageWire }>("claim_key_package", { target });
    return response.key_package;
  }
  const response = await jsonRequest<{ key_package: KeyPackageWire }>(targetOrigin(target), "/v1/deposit/key-packages/claim", {
    method: "POST", headers: { authorization: `BlackspaceDeposit ${target.deposit_capability}` },
  });
  return response.key_package;
}

export async function depositEnvelope(target: DepositTarget, envelope: object): Promise<void> {
  if (isTauri()) { await invoke("deposit_envelope", { target, envelope }); return; }
  try {
    await jsonRequest(targetOrigin(target), "/v1/deposit/envelopes", {
      method: "POST", headers: { "content-type": "application/blackspace-envelope+json", authorization: `BlackspaceDeposit ${target.deposit_capability}` }, body: JSON.stringify(envelope),
    });
  } catch (cause) {
    // A retry of the same persisted envelope ID is an idempotent success.
    if (!(cause instanceof MailboxOperationError) || cause.status !== 409) throw cause;
  }
}

export async function pullEnvelopes(origin: string, readCapability: string): Promise<Array<{ ciphertext: string; acknowledgement_token: string; deposit_capability_id: string }>> {
  if (isTauri()) {
    const response = await invoke<{ envelopes: Array<{ ciphertext: string; acknowledgement_token: string; deposit_capability_id: string }> }>("pull_envelopes", { serverUrl: origin, readCapability, limit: 100 });
    return response.envelopes;
  }
  const response = await jsonRequest<{ envelopes: Array<{ ciphertext: string; acknowledgement_token: string; deposit_capability_id: string }> }>(origin, "/v1/mailbox/pull", {
    method: "POST", headers: { "content-type": "application/json", authorization: `BlackspaceRead ${readCapability}` }, body: JSON.stringify({ limit: 100 }),
  });
  return response.envelopes;
}

export async function acknowledgeEnvelopes(origin: string, readCapability: string, tokens: string[]): Promise<void> {
  if (!tokens.length) return;
  if (isTauri()) { await invoke("acknowledge_envelopes", { serverUrl: origin, readCapability, acknowledgementTokens: tokens }); return; }
  await jsonRequest(origin, "/v1/mailbox/ack", {
    method: "POST", headers: { "content-type": "application/json", authorization: `BlackspaceRead ${readCapability}` }, body: JSON.stringify({ acknowledgement_tokens: tokens }),
  });
}

// ---- Multi-device (floating primary) ----

export interface SealedStateResponse { version: number; size_class: number; ciphertext: string }

// Reads the shared MLS-state blob. 204 (no blob uploaded yet) returns undefined.
export async function getMlsState(origin: string, adminCapability: string): Promise<SealedStateResponse | undefined> {
  if (isTauri()) return (await invoke<SealedStateResponse | null>("get_mls_state", { serverUrl: origin, adminCapability })) ?? undefined;
  const response = await fetch(`${origin}/v1/mailbox/mls-state`, {
    method: "GET", redirect: "error", credentials: "omit", cache: "no-store",
    headers: { authorization: `BlackspaceAdmin ${adminCapability}` },
  });
  if (response.status === 204) return undefined;
  if (!response.ok) throw new MailboxOperationError(response.status);
  return JSON.parse(await response.text()) as SealedStateResponse;
}

// Compare-and-swap write. Returns "conflict" on 409 so the caller re-reads and retries.
export async function putMlsState(origin: string, adminCapability: string, expectedVersion: number, sealed: { size_class: number; ciphertext: string }): Promise<{ version: number } | "conflict"> {
  if (isTauri()) {
    const result = await invoke<{ conflict: boolean; version?: number }>("put_mls_state", { serverUrl: origin, adminCapability, request: { expected_version: expectedVersion, size_class: sealed.size_class, ciphertext: sealed.ciphertext } });
    if (result.conflict || result.version === undefined) return "conflict";
    return { version: result.version };
  }
  const response = await fetch(`${origin}/v1/mailbox/mls-state`, {
    method: "PUT", redirect: "error", credentials: "omit", cache: "no-store",
    headers: { "content-type": "application/json", authorization: `BlackspaceAdmin ${adminCapability}` },
    body: JSON.stringify({ expected_version: expectedVersion, size_class: sealed.size_class, ciphertext: sealed.ciphertext }),
  });
  if (response.status === 409) return "conflict";
  if (!response.ok) throw new MailboxOperationError(response.status);
  return JSON.parse(await response.text()) as { version: number };
}

export async function parkEnrollmentParcel(origin: string, adminCapability: string, parcel: object): Promise<{ parcel_id: string }> {
  if (isTauri()) return invoke("park_enrollment_parcel", { serverUrl: origin, adminCapability, request: parcel });
  return jsonRequest(origin, "/v1/enroll/parcels", {
    method: "POST", headers: { "content-type": "application/json", authorization: `BlackspaceAdmin ${adminCapability}` }, body: JSON.stringify(parcel),
  });
}

export async function finalizeEnrollmentParcel(origin: string, adminCapability: string, parcelId: string, parcel: object): Promise<void> {
  if (isTauri()) { await invoke("finalize_enrollment_parcel", { serverUrl: origin, adminCapability, parcelId, request: parcel }); return; }
  await noContentRequest(origin, `/v1/enroll/parcels/${encodeURIComponent(parcelId)}`, {
    method: "PUT", headers: { "content-type": "application/json", authorization: `BlackspaceAdmin ${adminCapability}` }, body: JSON.stringify(parcel),
  });
}

export interface EnrollmentParcelClaim {
  status: "pending_confirmation" | "ready";
  eph_pub: string;
  nonce?: string;
  size_class?: number;
  ciphertext?: string;
}

export async function claimEnrollmentParcel(origin: string, claimSecret: string): Promise<EnrollmentParcelClaim | undefined> {
  if (isTauri()) return (await invoke<EnrollmentParcelClaim | null>("claim_enrollment_parcel", { serverUrl: origin, claimSecret })) ?? undefined;
  const response = await fetch(`${origin}/v1/enroll/parcels/claim`, {
    method: "POST", redirect: "error", credentials: "omit", cache: "no-store",
    headers: { authorization: `BlackspaceEnroll ${claimSecret}` },
  });
  if (response.status === 404) return undefined;
  if (!response.ok) throw new MailboxOperationError(response.status);
  return JSON.parse(await response.text()) as EnrollmentParcelClaim;
}

export async function registerDevice(origin: string, adminCapability: string, deviceId: string, label: string): Promise<void> {
  if (isTauri()) { await invoke("register_device", { serverUrl: origin, adminCapability, request: { device_id: deviceId, label } }); return; }
  await noContentRequest(origin, "/v1/mailbox/devices", {
    method: "POST", headers: { "content-type": "application/json", authorization: `BlackspaceAdmin ${adminCapability}` }, body: JSON.stringify({ device_id: deviceId, label }),
  });
}

export interface DeviceRecord { id: string; label: string; enrolled_at: number; revoked: boolean }

export async function listDevices(origin: string, adminCapability: string): Promise<DeviceRecord[]> {
  if (isTauri()) return (await invoke<{ devices: DeviceRecord[] }>("list_devices", { serverUrl: origin, adminCapability })).devices;
  const response = await jsonRequest<{ devices: DeviceRecord[] }>(origin, "/v1/mailbox/devices", {
    method: "GET", headers: { authorization: `BlackspaceAdmin ${adminCapability}` },
  });
  return response.devices;
}

export interface SecureDeviceResetRequest {
  current_device_id: string;
  read_capability_verifier: string;
  admin_capability_verifier: string;
  revoke_deposit_capability_ids: string[];
  expected_mls_state_version: number;
  mls_state_size_class: number;
  mls_state_ciphertext: string;
}

export async function secureDeviceReset(origin: string, adminCapability: string, request: SecureDeviceResetRequest): Promise<{ version: number; revoked_devices: number } | "conflict"> {
  if (isTauri()) {
    const result = await invoke<{ conflict: boolean; version?: number; revoked_devices?: number }>("secure_device_reset", { serverUrl: origin, adminCapability, request });
    if (result.conflict || result.version === undefined) return "conflict";
    return { version: result.version, revoked_devices: result.revoked_devices ?? 0 };
  }
  const response = await fetch(`${origin}/v1/mailbox/devices/secure-reset`, {
    method: "POST", redirect: "error", credentials: "omit", cache: "no-store",
    headers: { "content-type": "application/json", authorization: `BlackspaceAdmin ${adminCapability}` },
    body: JSON.stringify(request),
  });
  if (response.status === 409) return "conflict";
  if (!response.ok) throw new MailboxOperationError(response.status);
  return JSON.parse(await response.text()) as { version: number; revoked_devices: number };
}
