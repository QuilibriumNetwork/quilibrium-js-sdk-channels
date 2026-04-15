#!/usr/bin/env node

/**
 * SDK health check — verifies the built SDK works end-to-end.
 * Run after `yarn build`:
 *
 *   node test/sdk-check.js
 *   yarn check          (alias)
 *
 * Exits 0 if all checks pass, 1 if any fail.
 * No browser needed — runs entirely in Node.
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import crypto from 'crypto';

// The SDK is browser-only and touches window/navigator/localStorage at import.
// Provide minimal shims so the module loads in Node for testing purposes.
if (typeof globalThis.window === 'undefined') {
  const storage = {};
  globalThis.window = globalThis;
  Object.defineProperty(globalThis, 'navigator', {
    value: { credentials: {}, userAgent: 'node' },
    writable: true, configurable: true,
  });
  globalThis.localStorage = {
    getItem: (k) => storage[k] ?? null,
    setItem: (k, v) => { storage[k] = String(v); },
    removeItem: (k) => { delete storage[k]; },
  };
  Object.defineProperty(globalThis, 'crypto', {
    value: crypto.webcrypto ?? crypto,
    writable: true, configurable: true,
  });
  globalThis.document = { createElement: () => ({}) };
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

let passed = 0;
let failed = 0;

function pass(label, detail) {
  passed++;
  console.log(`  \x1b[32m✓\x1b[0m ${label}${detail ? `  \x1b[2m${detail}\x1b[0m` : ''}`);
}

function fail(label, detail) {
  failed++;
  console.log(`  \x1b[31m✗\x1b[0m ${label}${detail ? `  \x1b[2m${detail}\x1b[0m` : ''}`);
}

console.log('');
console.log('  \x1b[1mSDK Health Check\x1b[0m');
console.log('');

// --- 1. dist/ files exist ---
const files = ['dist/index.js', 'dist/index.esm.js', 'dist/index.d.ts', 'dist/index.css', 'dist/channelwasm_bg.wasm'];
const missing = files.filter(f => !existsSync(resolve(root, f)));
if (missing.length === 0) {
  pass('Build artifacts', `${files.length} files in dist/`);
} else {
  fail('Build artifacts', `missing: ${missing.join(', ')}. Run yarn build.`);
}

// --- 2. SDK module loads ---
let sdk;
try {
  sdk = await import(pathToFileURL(resolve(root, 'dist/index.esm.js')).href);
  pass('SDK module loads', 'dist/index.esm.js imported successfully');
} catch (e) {
  fail('SDK module loads', e.message);
  console.log('');
  process.exit(1);
}

// --- 3. WASM initializes ---
try {
  const wasmPath = resolve(root, 'dist/channelwasm_bg.wasm');
  const wasmBytes = readFileSync(wasmPath);
  sdk.channel_raw.initSync(wasmBytes);
  pass('WASM crypto backend', 'channelwasm_bg.wasm compiled and initialized');
} catch (e) {
  fail('WASM crypto backend', e.message);
}

// --- 4. Ed448 key generation ---
try {
  const pair = sdk.channel_raw.js_generate_ed448();
  const parsed = JSON.parse(pair);
  if (parsed.public_key?.length === 57 && parsed.private_key?.length === 57) {
    pass('Ed448 key generation', `${parsed.public_key.length}-byte pubkey, ${parsed.private_key.length}-byte privkey`);
  } else {
    fail('Ed448 key generation', `unexpected key sizes: pub=${parsed.public_key?.length}, priv=${parsed.private_key?.length}`);
  }
} catch (e) {
  fail('Ed448 key generation', e.message);
}

// --- 5. Public key derivation ---
try {
  const pair = JSON.parse(sdk.channel_raw.js_generate_ed448());
  const privKeyBase64 = Buffer.from(pair.private_key).toString('base64');
  const pubkey = sdk.channel_raw.js_get_pubkey_ed448(privKeyBase64);
  if (pubkey && pubkey.length > 0) {
    pass('Public key derivation', 'js_get_pubkey_ed448 works');
  } else {
    fail('Public key derivation', 'empty result');
  }
} catch (e) {
  fail('Public key derivation', e.message);
}

// --- 6. Exports check ---
const requiredExports = ['PasskeysProvider', 'usePasskeyFlow', 'usePasskeysContext', 'PasskeyModal', 'channel', 'channel_raw'];
const missingExports = requiredExports.filter(name => !sdk[name]);
if (missingExports.length === 0) {
  pass('SDK exports', `${requiredExports.length} required exports found`);
} else {
  fail('SDK exports', `missing: ${missingExports.join(', ')}`);
}

// --- 7. TypeScript declarations ---
try {
  const dts = readFileSync(resolve(root, 'dist/index.d.ts'), 'utf-8');
  const hasHookType = dts.includes('usePasskeyFlow');
  const hasModalType = dts.includes('PasskeyModal');
  if (hasHookType && hasModalType) {
    pass('Type declarations', 'index.d.ts includes usePasskeyFlow and PasskeyModal');
  } else {
    fail('Type declarations', `missing: ${!hasHookType ? 'usePasskeyFlow' : ''} ${!hasModalType ? 'PasskeyModal' : ''}`.trim());
  }
} catch (e) {
  fail('Type declarations', e.message);
}

// --- Summary ---
console.log('');
if (failed === 0) {
  console.log(`  \x1b[32m\x1b[1m${passed}/${passed} checks passed\x1b[0m`);
} else {
  console.log(`  \x1b[31m\x1b[1m${failed} failed\x1b[0m, ${passed} passed`);
}
console.log('');

process.exit(failed > 0 ? 1 : 0);
