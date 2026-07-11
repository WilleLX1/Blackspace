/* tslint:disable */
/* eslint-disable */

export function wasm_create_mls_message(client_state: string, group_id: string, payload: string): string;

export function wasm_decode_client_payload(payload: string): string;

export function wasm_encode_client_payload(json: string): string;

/**
 * Opaque browser bridge. Private material is serialized only as an opaque
 * state blob for immediate encryption by the vault layer.
 */
export function wasm_generate_mls_identity(package_count: number): string;

export function wasm_join_mls_conversation(client_state: string, welcome: string, first_message: string): string;

export function wasm_mls_recovery_identity_snapshot(client_state: string): string;

export function wasm_open_recovery_state(blob: string, passphrase: string): string;

export function wasm_process_mls_message(client_state: string, group_id: string, message: string): string;

export function wasm_replenish_mls_key_packages(client_state: string, package_count: number): string;

export function wasm_seal_recovery_state(json: string, passphrase: string): string;

export function wasm_start_mls_conversation(client_state: string, recipient_identity: string, recipient_key_package: string, first_payload: string): string;

export function wasm_verification_fingerprint(first: string, second: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly wasm_create_mls_message: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasm_decode_client_payload: (a: number, b: number) => [number, number, number, number];
    readonly wasm_encode_client_payload: (a: number, b: number) => [number, number, number, number];
    readonly wasm_generate_mls_identity: (a: number) => [number, number, number, number];
    readonly wasm_join_mls_conversation: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasm_mls_recovery_identity_snapshot: (a: number, b: number) => [number, number, number, number];
    readonly wasm_open_recovery_state: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_process_mls_message: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasm_replenish_mls_key_packages: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasm_seal_recovery_state: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_start_mls_conversation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly wasm_verification_fingerprint: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
