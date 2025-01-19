/* tslint:disable */
/* eslint-disable */
/**
 * @param {string} input
 * @returns {string}
 */
export function js_decrypt_inbox_message(input: string): string;
/**
 * @param {string} input
 * @returns {string}
 */
export function js_encrypt_inbox_message(input: string): string;
/**
 * @param {string} input
 * @returns {string}
 */
export function js_sender_x3dh(input: string): string;
/**
 * @param {string} input
 * @returns {string}
 */
export function js_receiver_x3dh(input: string): string;
/**
 * @returns {string}
 */
export function js_generate_x448(): string;
/**
 * @returns {string}
 */
export function js_generate_ed448(): string;
/**
 * @param {string} key
 * @returns {string}
 */
export function js_get_pubkey_ed448(key: string): string;
/**
 * @param {string} key
 * @returns {string}
 */
export function js_get_pubkey_x448(key: string): string;
/**
 * @param {string} key
 * @param {string} message
 * @returns {string}
 */
export function js_sign_ed448(key: string, message: string): string;
/**
 * @param {string} public_key
 * @param {string} message
 * @param {string} signature
 * @returns {string}
 */
export function js_verify_ed448(
  public_key: string,
  message: string,
  signature: string
): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_new_double_ratchet(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_double_ratchet_encrypt(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_double_ratchet_decrypt(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_new_triple_ratchet(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_triple_ratchet_init_round_1(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_triple_ratchet_init_round_2(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_triple_ratchet_init_round_3(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_triple_ratchet_init_round_4(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_triple_ratchet_encrypt(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_triple_ratchet_decrypt(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_triple_ratchet_resize(params: string): string;
/**
 * @param {string} params
 * @returns {string}
 */
export function js_verify_point(params: string): string;

export type InitInput =
  | RequestInfo
  | URL
  | Response
  | BufferSource
  | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly js_decrypt_inbox_message: (a: number, b: number, c: number) => void;
  readonly js_encrypt_inbox_message: (a: number, b: number, c: number) => void;
  readonly js_sender_x3dh: (a: number, b: number, c: number) => void;
  readonly js_receiver_x3dh: (a: number, b: number, c: number) => void;
  readonly js_generate_x448: (a: number) => void;
  readonly js_generate_ed448: (a: number) => void;
  readonly js_get_pubkey_ed448: (a: number, b: number, c: number) => void;
  readonly js_get_pubkey_x448: (a: number, b: number, c: number) => void;
  readonly js_sign_ed448: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number
  ) => void;
  readonly js_verify_ed448: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number,
    f: number,
    g: number
  ) => void;
  readonly js_new_double_ratchet: (a: number, b: number, c: number) => void;
  readonly js_double_ratchet_encrypt: (a: number, b: number, c: number) => void;
  readonly js_double_ratchet_decrypt: (a: number, b: number, c: number) => void;
  readonly js_new_triple_ratchet: (a: number, b: number, c: number) => void;
  readonly js_triple_ratchet_init_round_1: (
    a: number,
    b: number,
    c: number
  ) => void;
  readonly js_triple_ratchet_init_round_2: (
    a: number,
    b: number,
    c: number
  ) => void;
  readonly js_triple_ratchet_init_round_3: (
    a: number,
    b: number,
    c: number
  ) => void;
  readonly js_triple_ratchet_init_round_4: (
    a: number,
    b: number,
    c: number
  ) => void;
  readonly js_triple_ratchet_encrypt: (a: number, b: number, c: number) => void;
  readonly js_triple_ratchet_decrypt: (a: number, b: number, c: number) => void;
  readonly js_triple_ratchet_resize: (a: number, b: number, c: number) => void;
  readonly js_verify_point: (a: number, b: number, c: number) => void;
  readonly uniffi_channel_checksum_func_double_ratchet_decrypt: () => number;
  readonly uniffi_channel_checksum_func_double_ratchet_encrypt: () => number;
  readonly uniffi_channel_checksum_func_new_double_ratchet: () => number;
  readonly uniffi_channel_checksum_func_new_triple_ratchet: () => number;
  readonly uniffi_channel_checksum_func_triple_ratchet_decrypt: () => number;
  readonly uniffi_channel_checksum_func_triple_ratchet_encrypt: () => number;
  readonly uniffi_channel_checksum_func_triple_ratchet_init_round_1: () => number;
  readonly uniffi_channel_checksum_func_triple_ratchet_init_round_2: () => number;
  readonly uniffi_channel_checksum_func_triple_ratchet_init_round_3: () => number;
  readonly uniffi_channel_checksum_func_triple_ratchet_init_round_4: () => number;
  readonly ffi_channel_uniffi_contract_version: () => number;
  readonly ffi_channel_rustbuffer_alloc: (
    a: number,
    b: number,
    c: number
  ) => void;
  readonly ffi_channel_rustbuffer_from_bytes: (
    a: number,
    b: number,
    c: number,
    d: number
  ) => void;
  readonly ffi_channel_rustbuffer_free: (
    a: number,
    b: number,
    c: number,
    d: number
  ) => void;
  readonly ffi_channel_rustbuffer_reserve: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number,
    f: number
  ) => void;
  readonly ffi_channel_foreign_executor_callback_set: (a: number) => void;
  readonly ffi_channel_rust_future_continuation_callback_set: (
    a: number
  ) => void;
  readonly ffi_channel_rust_future_complete_u8: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_complete_i8: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_complete_u16: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_complete_i16: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_complete_i32: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_complete_i64: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_poll_f32: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_cancel_f32: (a: number) => void;
  readonly ffi_channel_rust_future_complete_f32: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_free_f32: (a: number) => void;
  readonly ffi_channel_rust_future_complete_f64: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_complete_rust_buffer: (
    a: number,
    b: number,
    c: number
  ) => void;
  readonly ffi_channel_rust_future_complete_void: (
    a: number,
    b: number
  ) => void;
  readonly uniffi_channel_fn_func_double_ratchet_decrypt: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number
  ) => void;
  readonly uniffi_channel_fn_func_double_ratchet_encrypt: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number
  ) => void;
  readonly uniffi_channel_fn_func_new_double_ratchet: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number,
    f: number,
    g: number,
    h: number,
    i: number,
    j: number,
    k: number,
    l: number,
    m: number,
    n: number,
    o: number,
    p: number,
    q: number,
    r: number
  ) => void;
  readonly uniffi_channel_fn_func_new_triple_ratchet: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number,
    f: number,
    g: number,
    h: number,
    i: number,
    j: number,
    k: number,
    l: number,
    m: number,
    n: number,
    o: number,
    p: number
  ) => void;
  readonly uniffi_channel_fn_func_triple_ratchet_decrypt: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number
  ) => void;
  readonly uniffi_channel_fn_func_triple_ratchet_encrypt: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number
  ) => void;
  readonly uniffi_channel_fn_func_triple_ratchet_init_round_1: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number
  ) => void;
  readonly uniffi_channel_fn_func_triple_ratchet_init_round_2: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number
  ) => void;
  readonly uniffi_channel_fn_func_triple_ratchet_init_round_3: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number
  ) => void;
  readonly uniffi_channel_fn_func_triple_ratchet_init_round_4: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number
  ) => void;
  readonly ffi_channel_rust_future_free_u8: (a: number) => void;
  readonly ffi_channel_rust_future_free_u16: (a: number) => void;
  readonly ffi_channel_rust_future_free_i8: (a: number) => void;
  readonly ffi_channel_rust_future_free_u32: (a: number) => void;
  readonly ffi_channel_rust_future_free_i32: (a: number) => void;
  readonly ffi_channel_rust_future_free_u64: (a: number) => void;
  readonly ffi_channel_rust_future_free_i64: (a: number) => void;
  readonly ffi_channel_rust_future_free_i16: (a: number) => void;
  readonly ffi_channel_rust_future_free_f64: (a: number) => void;
  readonly ffi_channel_rust_future_free_pointer: (a: number) => void;
  readonly ffi_channel_rust_future_free_rust_buffer: (a: number) => void;
  readonly ffi_channel_rust_future_free_void: (a: number) => void;
  readonly ffi_channel_rust_future_poll_u8: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_u16: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_i8: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_u32: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_i32: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_u64: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_i64: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_i16: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_f64: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_pointer: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_poll_rust_buffer: (
    a: number,
    b: number
  ) => void;
  readonly ffi_channel_rust_future_poll_void: (a: number, b: number) => void;
  readonly ffi_channel_rust_future_complete_u32: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_complete_u64: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_complete_pointer: (
    a: number,
    b: number
  ) => number;
  readonly ffi_channel_rust_future_cancel_u8: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_u16: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_i8: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_u32: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_i32: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_u64: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_i64: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_i16: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_f64: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_pointer: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_rust_buffer: (a: number) => void;
  readonly ffi_channel_rust_future_cancel_void: (a: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (
    a: number,
    b: number,
    c: number,
    d: number
  ) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {SyncInitInput} module
 *
 * @returns {InitOutput}
 */
export function initSync(module: SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {InitInput | Promise<InitInput>} module_or_path
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init(
  module_or_path?: InitInput | Promise<InitInput>
): Promise<InitOutput>;
