import init, {
  wasm_create_mls_message, wasm_decode_client_payload, wasm_encode_client_payload,
  wasm_generate_mls_identity, wasm_join_mls_conversation,
  wasm_mls_recovery_identity_snapshot, wasm_process_mls_message,
  wasm_open_recovery_state,
  wasm_replenish_mls_key_packages, wasm_start_mls_conversation,
  wasm_seal_recovery_state,
  wasm_verification_fingerprint,
} from "./wasm/blackspace_core";
import { base64Url, fromBase64Url } from "./crypto";
import type { SecureContent } from "./crypto";

let ready: Promise<unknown> | undefined;
const ensureReady = () => ready ??= init();

export interface MlsIdentityResult { identity_public_key: string; key_packages: string[]; client_state: string }
export interface MlsStartResult { client_state: string; group_id: string; welcome: string; first_message: string }
interface MlsJoinWireResult { client_state: string; group_id: string; first_payload: string; peer_identity: string }
export interface MlsJoinResult { client_state: string; group_id: string; first_payload: Uint8Array; peer_identity: string }
export interface MlsMessageResult { client_state: string; message: string }
export interface MlsProcessResult { client_state: string; payload: string }

export async function mlsGenerate(count = 20): Promise<MlsIdentityResult> {
  await ensureReady(); return JSON.parse(wasm_generate_mls_identity(count)) as MlsIdentityResult;
}

export async function mlsReplenish(state: string, count: number): Promise<{ client_state: string; key_packages: string[] }> {
  await ensureReady(); return JSON.parse(wasm_replenish_mls_key_packages(state, count));
}

export async function mlsRecoveryIdentitySnapshot(state: string): Promise<string> {
  await ensureReady(); return wasm_mls_recovery_identity_snapshot(state);
}

export async function encodeSecureContent(content: SecureContent): Promise<Uint8Array> {
  await ensureReady(); return fromBase64Url(wasm_encode_client_payload(JSON.stringify(content)));
}

export async function decodeSecureContent(payload: Uint8Array): Promise<SecureContent> {
  await ensureReady(); return JSON.parse(wasm_decode_client_payload(base64Url(payload))) as SecureContent;
}

export async function contactFingerprint(first: string, second: string): Promise<{ hex: string; words: string[] }> {
  await ensureReady(); return JSON.parse(wasm_verification_fingerprint(first, second));
}

export async function sealRecoveryState(state: unknown, passphrase: string): Promise<Uint8Array> {
  await ensureReady(); return fromBase64Url(wasm_seal_recovery_state(JSON.stringify(state), passphrase));
}

export async function openRecoveryState(blob: Uint8Array, passphrase: string): Promise<unknown> {
  await ensureReady(); return JSON.parse(wasm_open_recovery_state(base64Url(blob), passphrase));
}

export async function mlsStart(state: string, recipientIdentity: string, keyPackage: string, payload: Uint8Array): Promise<MlsStartResult> {
  await ensureReady(); return JSON.parse(wasm_start_mls_conversation(state, recipientIdentity, keyPackage, base64Url(payload))) as MlsStartResult;
}

export async function mlsJoin(state: string, welcome: string, firstMessage: string): Promise<MlsJoinResult> {
  await ensureReady();
  const result = JSON.parse(wasm_join_mls_conversation(state, welcome, firstMessage)) as MlsJoinWireResult;
  return { ...result, first_payload: fromBase64Url(result.first_payload) };
}

export async function mlsCreateMessage(state: string, groupId: string, payload: Uint8Array): Promise<MlsMessageResult> {
  await ensureReady(); return JSON.parse(wasm_create_mls_message(state, groupId, base64Url(payload))) as MlsMessageResult;
}

export async function mlsProcessMessage(state: string, groupId: string, message: string): Promise<{ client_state: string; payload: Uint8Array }> {
  await ensureReady(); const result = JSON.parse(wasm_process_mls_message(state, groupId, message)) as MlsProcessResult;
  return { client_state: result.client_state, payload: fromBase64Url(result.payload) };
}

export async function mlsGroupHint(groupId: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", fromBase64Url(groupId) as BufferSource);
  return base64Url(new Uint8Array(digest)).slice(0, 16);
}
