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
  return response.json() as Promise<T>;
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
  await jsonRequest(origin, `/v1/mailbox/deposit-capabilities/${encodeURIComponent(capabilityId)}`, {
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
