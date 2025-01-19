/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export function js_decrypt_inbox_message(a: number, b: number, c: number): void;
export function js_encrypt_inbox_message(a: number, b: number, c: number): void;
export function js_sender_x3dh(a: number, b: number, c: number): void;
export function js_receiver_x3dh(a: number, b: number, c: number): void;
export function js_generate_x448(a: number): void;
export function js_generate_ed448(a: number): void;
export function js_get_pubkey_ed448(a: number, b: number, c: number): void;
export function js_get_pubkey_x448(a: number, b: number, c: number): void;
export function js_sign_ed448(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): void;
export function js_verify_ed448(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number,
  f: number,
  g: number
): void;
export function js_new_double_ratchet(a: number, b: number, c: number): void;
export function js_double_ratchet_encrypt(
  a: number,
  b: number,
  c: number
): void;
export function js_double_ratchet_decrypt(
  a: number,
  b: number,
  c: number
): void;
export function js_new_triple_ratchet(a: number, b: number, c: number): void;
export function js_triple_ratchet_init_round_1(
  a: number,
  b: number,
  c: number
): void;
export function js_triple_ratchet_init_round_2(
  a: number,
  b: number,
  c: number
): void;
export function js_triple_ratchet_init_round_3(
  a: number,
  b: number,
  c: number
): void;
export function js_triple_ratchet_init_round_4(
  a: number,
  b: number,
  c: number
): void;
export function js_triple_ratchet_encrypt(
  a: number,
  b: number,
  c: number
): void;
export function js_triple_ratchet_decrypt(
  a: number,
  b: number,
  c: number
): void;
export function js_triple_ratchet_resize(a: number, b: number, c: number): void;
export function js_verify_point(a: number, b: number, c: number): void;
export function uniffi_channel_checksum_func_double_ratchet_decrypt(): number;
export function uniffi_channel_checksum_func_double_ratchet_encrypt(): number;
export function uniffi_channel_checksum_func_new_double_ratchet(): number;
export function uniffi_channel_checksum_func_new_triple_ratchet(): number;
export function uniffi_channel_checksum_func_triple_ratchet_decrypt(): number;
export function uniffi_channel_checksum_func_triple_ratchet_encrypt(): number;
export function uniffi_channel_checksum_func_triple_ratchet_init_round_1(): number;
export function uniffi_channel_checksum_func_triple_ratchet_init_round_2(): number;
export function uniffi_channel_checksum_func_triple_ratchet_init_round_3(): number;
export function uniffi_channel_checksum_func_triple_ratchet_init_round_4(): number;
export function ffi_channel_uniffi_contract_version(): number;
export function ffi_channel_rustbuffer_alloc(
  a: number,
  b: number,
  c: number
): void;
export function ffi_channel_rustbuffer_from_bytes(
  a: number,
  b: number,
  c: number,
  d: number
): void;
export function ffi_channel_rustbuffer_free(
  a: number,
  b: number,
  c: number,
  d: number
): void;
export function ffi_channel_rustbuffer_reserve(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number,
  f: number
): void;
export function ffi_channel_foreign_executor_callback_set(a: number): void;
export function ffi_channel_rust_future_continuation_callback_set(
  a: number
): void;
export function ffi_channel_rust_future_complete_u8(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_complete_i8(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_complete_u16(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_complete_i16(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_complete_i32(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_complete_i64(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_poll_f32(a: number, b: number): void;
export function ffi_channel_rust_future_cancel_f32(a: number): void;
export function ffi_channel_rust_future_complete_f32(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_free_f32(a: number): void;
export function ffi_channel_rust_future_complete_f64(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_complete_rust_buffer(
  a: number,
  b: number,
  c: number
): void;
export function ffi_channel_rust_future_complete_void(
  a: number,
  b: number
): void;
export function uniffi_channel_fn_func_double_ratchet_decrypt(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): void;
export function uniffi_channel_fn_func_double_ratchet_encrypt(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): void;
export function uniffi_channel_fn_func_new_double_ratchet(
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
): void;
export function uniffi_channel_fn_func_new_triple_ratchet(
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
): void;
export function uniffi_channel_fn_func_triple_ratchet_decrypt(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): void;
export function uniffi_channel_fn_func_triple_ratchet_encrypt(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): void;
export function uniffi_channel_fn_func_triple_ratchet_init_round_1(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): void;
export function uniffi_channel_fn_func_triple_ratchet_init_round_2(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): void;
export function uniffi_channel_fn_func_triple_ratchet_init_round_3(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): void;
export function uniffi_channel_fn_func_triple_ratchet_init_round_4(
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): void;
export function ffi_channel_rust_future_free_u8(a: number): void;
export function ffi_channel_rust_future_free_u16(a: number): void;
export function ffi_channel_rust_future_free_i8(a: number): void;
export function ffi_channel_rust_future_free_u32(a: number): void;
export function ffi_channel_rust_future_free_i32(a: number): void;
export function ffi_channel_rust_future_free_u64(a: number): void;
export function ffi_channel_rust_future_free_i64(a: number): void;
export function ffi_channel_rust_future_free_i16(a: number): void;
export function ffi_channel_rust_future_free_f64(a: number): void;
export function ffi_channel_rust_future_free_pointer(a: number): void;
export function ffi_channel_rust_future_free_rust_buffer(a: number): void;
export function ffi_channel_rust_future_free_void(a: number): void;
export function ffi_channel_rust_future_poll_u8(a: number, b: number): void;
export function ffi_channel_rust_future_poll_u16(a: number, b: number): void;
export function ffi_channel_rust_future_poll_i8(a: number, b: number): void;
export function ffi_channel_rust_future_poll_u32(a: number, b: number): void;
export function ffi_channel_rust_future_poll_i32(a: number, b: number): void;
export function ffi_channel_rust_future_poll_u64(a: number, b: number): void;
export function ffi_channel_rust_future_poll_i64(a: number, b: number): void;
export function ffi_channel_rust_future_poll_i16(a: number, b: number): void;
export function ffi_channel_rust_future_poll_f64(a: number, b: number): void;
export function ffi_channel_rust_future_poll_pointer(
  a: number,
  b: number
): void;
export function ffi_channel_rust_future_poll_rust_buffer(
  a: number,
  b: number
): void;
export function ffi_channel_rust_future_poll_void(a: number, b: number): void;
export function ffi_channel_rust_future_complete_u32(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_complete_u64(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_complete_pointer(
  a: number,
  b: number
): number;
export function ffi_channel_rust_future_cancel_u8(a: number): void;
export function ffi_channel_rust_future_cancel_u16(a: number): void;
export function ffi_channel_rust_future_cancel_i8(a: number): void;
export function ffi_channel_rust_future_cancel_u32(a: number): void;
export function ffi_channel_rust_future_cancel_i32(a: number): void;
export function ffi_channel_rust_future_cancel_u64(a: number): void;
export function ffi_channel_rust_future_cancel_i64(a: number): void;
export function ffi_channel_rust_future_cancel_i16(a: number): void;
export function ffi_channel_rust_future_cancel_f64(a: number): void;
export function ffi_channel_rust_future_cancel_pointer(a: number): void;
export function ffi_channel_rust_future_cancel_rust_buffer(a: number): void;
export function ffi_channel_rust_future_cancel_void(a: number): void;
export function __wbindgen_add_to_stack_pointer(a: number): number;
export function __wbindgen_malloc(a: number, b: number): number;
export function __wbindgen_realloc(
  a: number,
  b: number,
  c: number,
  d: number
): number;
export function __wbindgen_free(a: number, b: number, c: number): void;
export function __wbindgen_exn_store(a: number): void;
