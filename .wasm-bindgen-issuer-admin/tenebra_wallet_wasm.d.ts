/* tslint:disable */
/* eslint-disable */

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly wallet_address: (a: number, b: number) => number;
    readonly wallet_alloc: (a: number) => number;
    readonly wallet_free: (a: number, b: number) => void;
    readonly wallet_generate_seed: (a: number) => number;
    readonly wallet_mnemonic_to_seed: (a: number, b: number, c: number) => number;
    readonly wallet_native_file_address: (a: number, b: number, c: number, d: number) => number;
    readonly wallet_native_file_balance: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly wallet_seed_balance: (a: number, b: number, c: number, d: number) => number;
    readonly wallet_native_file_history: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly wallet_native_file_rewards: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly wallet_seed_rewards: (a: number, b: number, c: number, d: number) => number;
    readonly wallet_native_file_seed: (a: number, b: number, c: number, d: number) => number;
    readonly wallet_native_file_sign_dex_create_pool: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: bigint, h: bigint, i: number) => number;
    readonly wallet_native_file_sign_dex_remove_liquidity: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number) => number;
    readonly wallet_native_file_sign_dex_swap: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: bigint, h: bigint, i: number) => number;
    readonly wallet_native_file_sign_message: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly wallet_native_file_sign_mining_challenge: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly wallet_native_file_sign_transfer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint, i: bigint, j: number) => number;
    readonly wallet_seed_sign_transfer: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: bigint, h: number) => number;
    readonly wallet_seed_history_v2: (a: number, b: number, c: number, d: number) => number;
    readonly wallet_seed_sign_asset_admin: (a: number, b: number, c: number, d: bigint, e: bigint, f: number, g: number, h: number, i: number, j: number, k: number) => number;
    readonly wallet_seed_sign_asset_create: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: bigint, k: number) => number;
    readonly wallet_seed_sign_asset_create_with_options: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: bigint, k: number, l: number, m: number, n: number, o: number, p: number) => number;
    readonly wallet_seed_sign_asset_transfer: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number) => number;
    readonly wallet_seed_sign_mining_challenge: (a: number, b: number, c: number, d: number) => number;
    readonly wallet_seed_to_mnemonic: (a: number, b: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
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
