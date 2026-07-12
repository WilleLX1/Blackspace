import type { AccountState, StoredAccount } from "./model";
import { argon2id } from "hash-wasm";
import { invoke } from "@tauri-apps/api/core";
import { openRecoveryState, sealRecoveryState } from "./mls";

const DATABASE = "blackspace-private-alpha";
const STORE = "vault";
const KEY = "primary";
const WRAP_AAD = new TextEncoder().encode("blackspace:v2:web-vault-key");
const RECORD_AAD = new TextEncoder().encode("blackspace:v2:web-vault-record:account");

interface LegacyVault {
  version: 1;
  salt: string;
  nonce: string;
  ciphertext: string;
}

interface EncryptedVault {
  version: 2;
  salt: string;
  wrapNonce: string;
  wrappedKey: string;
  recordNonce: string;
  ciphertext: string;
}

type StoredVault = LegacyVault | EncryptedVault;

interface LegacyRecoveryContainer {
  format: "blackspace-recovery";
  version: 2;
  vault: StoredVault;
}

let unlockedVaultKey: CryptoKey | undefined;
const isTauri = () => "__TAURI_INTERNALS__" in window;

const encode = (bytes: Uint8Array) => {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(binary);
};
const decode = (value: string) => Uint8Array.from(atob(value), (character) => character.charCodeAt(0));

async function database(): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function readRecord(): Promise<StoredVault | undefined> {
  const db = await database();
  return new Promise<StoredVault | undefined>((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get(KEY);
    request.onsuccess = () => resolve(request.result as StoredVault | undefined);
    request.onerror = () => reject(request.error);
  }).finally(() => db.close());
}

async function writeRecord(record: StoredVault): Promise<void> {
  const db = await database();
  return new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(STORE, "readwrite");
    transaction.objectStore(STORE).put(record, KEY);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  }).finally(() => db.close());
}

async function deriveWrappingKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  if (passphrase.length < 10) throw new Error("Use at least 10 characters for the vault passphrase.");
  const raw = await argon2id({
    password: passphrase,
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 64 * 1024,
    hashLength: 32,
    outputType: "binary",
  });
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function createVault(state: StoredAccount, passphrase: string): Promise<EncryptedVault> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapNonce = crypto.getRandomValues(new Uint8Array(12));
  const rawVaultKey = crypto.getRandomValues(new Uint8Array(32));
  const wrappingKey = await deriveWrappingKey(passphrase, salt);
  const wrappedKey = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: wrapNonce as BufferSource, additionalData: WRAP_AAD }, wrappingKey, rawVaultKey,
  ));
  unlockedVaultKey = await crypto.subtle.importKey("raw", rawVaultKey, "AES-GCM", false, ["encrypt", "decrypt"]);
  return encryptRecord(state, { version: 2, salt: encode(salt), wrapNonce: encode(wrapNonce), wrappedKey: encode(wrappedKey), recordNonce: "", ciphertext: "" }, unlockedVaultKey);
}

async function unwrapVaultKey(record: EncryptedVault, passphrase: string): Promise<CryptoKey> {
  const wrappingKey = await deriveWrappingKey(passphrase, decode(record.salt));
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(record.wrapNonce) as BufferSource, additionalData: WRAP_AAD }, wrappingKey, decode(record.wrappedKey),
  );
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptRecord(state: StoredAccount, wrapper: EncryptedVault, vaultKey: CryptoKey): Promise<EncryptedVault> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(state));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce as BufferSource, additionalData: RECORD_AAD }, vaultKey, plaintext,
  ));
  return { ...wrapper, recordNonce: encode(nonce), ciphertext: encode(ciphertext) };
}

async function decryptRecord(record: EncryptedVault, vaultKey: CryptoKey): Promise<StoredAccount> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(record.recordNonce) as BufferSource, additionalData: RECORD_AAD }, vaultKey, decode(record.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext)) as StoredAccount;
}

async function decryptLegacy(record: LegacyVault, passphrase: string): Promise<AccountState> {
  const key = await deriveWrappingKey(passphrase, decode(record.salt));
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(record.nonce) as BufferSource, additionalData: new TextEncoder().encode("blackspace:v1:web-vault") },
    key,
    decode(record.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext)) as AccountState;
}

export async function vaultExists(): Promise<boolean> {
  if (isTauri()) return invoke<boolean>("native_vault_exists");
  return Boolean(await readRecord());
}

export async function saveVault(state: StoredAccount, passphrase: string): Promise<void> {
  if (isTauri()) { await invoke("native_save_vault", { state, passphrase }); return; }
  const existing = await readRecord();
  if (!existing || existing.version === 1) {
    await writeRecord(await createVault(state, passphrase));
    return;
  }
  const key = unlockedVaultKey ?? await unwrapVaultKey(existing, passphrase);
  unlockedVaultKey = key;
  await writeRecord(await encryptRecord(state, existing, key));
}

export async function unlockVault(passphrase: string): Promise<StoredAccount> {
  if (isTauri()) return invoke<StoredAccount>("native_unlock_vault", { passphrase });
  const record = await readRecord();
  if (!record) throw new Error("No Blackspace vault was found.");
  try {
    if (record.version === 1) {
      const state = await decryptLegacy(record, passphrase);
      await writeRecord(await createVault(state, passphrase));
      return state;
    }
    unlockedVaultKey = await unwrapVaultKey(record, passphrase);
    return await decryptRecord(record, unlockedVaultKey);
  } catch {
    unlockedVaultKey = undefined;
    throw new Error("The passphrase is incorrect or the vault is damaged.");
  }
}

export function lockVault(): void {
  unlockedVaultKey = undefined;
  if (isTauri()) void invoke("native_lock_vault");
}

export async function createRecoveryKit(state: AccountState, passphrase: string): Promise<Uint8Array> {
  return sealRecoveryState({ format: "blackspace-recovery", version: 1, state }, passphrase);
}

export function recoveryKitEncoding(contents: Uint8Array): "legacy-json" | "encrypted-cbor" {
  let offset = 0;
  while (offset < contents.length && [0x09, 0x0a, 0x0d, 0x20].includes(contents[offset])) offset += 1;
  return contents[offset] === 0x7b ? "legacy-json" : "encrypted-cbor";
}

function parseLegacyRecoveryKit(contents: Uint8Array): LegacyRecoveryContainer {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(contents));
  } catch {
    throw new Error("This recovery kit is not a recognized Blackspace recovery file.");
  }
  if (!parsed || typeof parsed !== "object") throw new Error("This recovery kit is not a recognized Blackspace recovery file.");
  const container = parsed as Partial<LegacyRecoveryContainer>;
  if (container.format !== "blackspace-recovery" || container.version !== 2 || !container.vault || typeof container.vault !== "object") {
    throw new Error("This recovery kit version is not supported.");
  }
  const vault = container.vault as Partial<StoredVault>;
  if (vault.version !== 1 && vault.version !== 2) throw new Error("This recovery kit version is not supported.");
  return container as LegacyRecoveryContainer;
}

export async function openRecoveryKit(contents: Uint8Array, passphrase: string): Promise<AccountState> {
  if (recoveryKitEncoding(contents) === "legacy-json") {
    const parsed = parseLegacyRecoveryKit(contents);
    try {
      if (parsed.vault.version === 1) return await decryptLegacy(parsed.vault, passphrase);
      return await decryptRecord(parsed.vault, await unwrapVaultKey(parsed.vault, passphrase)) as AccountState;
    } catch {
      throw new Error("The recovery passphrase is incorrect or the recovery kit is damaged.");
    }
  }

  let parsed: { format: string; version: number; state: AccountState };
  try {
    parsed = await openRecoveryState(contents, passphrase) as { format: string; version: number; state: AccountState };
  } catch {
    throw new Error("The recovery passphrase is incorrect or the recovery kit is damaged.");
  }
  if (parsed.format !== "blackspace-recovery" || parsed.version !== 1 || !parsed.state) {
    throw new Error("This recovery kit version is not supported.");
  }
  return parsed.state;
}

export async function deleteVault(): Promise<void> {
  unlockedVaultKey = undefined;
  if (isTauri()) { await invoke("native_delete_vault"); return; }
  const db = await database();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(STORE, "readwrite");
    transaction.objectStore(STORE).delete(KEY);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
  db.close();
}
