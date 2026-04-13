# Passkey Test Pages

Two visual test pages for the SDK, both served by `yarn test`.

## Quick Start

```bash
yarn build       # build the SDK first (required -- test pages load from dist/)
yarn test        # serve project root on http://localhost:3001
```

Then open:

- `http://localhost:3001/test/` -- PasskeyModal full component test
- `http://localhost:3001/test/hook-test.html` -- usePasskeyFlow hook inspector

For build-verified testing (same as CI):

```bash
yarn test-build  # full build + serve
```

---

## Test Pages

### `index.html` -- PasskeyModal Visual Test

Tests the real `PasskeyModal` component loaded from `dist/index.esm.js`.

**Control panel:**
- **Show Create** -- opens the modal in new-account flow
- **Show Import** -- opens the modal in import flow (with .key file dropzone)
- **Force Success** -- injects success context values; no authenticator needed (UI-only test)
- **Force Error** -- injects error context values with a sample error message; no authenticator needed

Note: the modal renders a full-page overlay, so sidebar controls are only accessible before opening the modal. Use Force Success/Error before opening, or use the modal's own controls to dismiss it.

**Status panel** shows live context values: visible, importMode, complete, error.

The modal's own buttons (Continue, Cancel, Proceed Without Passkeys) drive state normally -- no mocking. Clicking "Continue" will trigger a real WebAuthn prompt.

> **Note:** `yarn test-build` generates `test-build.html` via `test/create-build-test.js`. That page renders modal states using raw DOM + hardcoded CSS class names (no React, no real component). It is a CSS smoke test for the build pipeline, not a functional component test. Use `index.html` for component testing.

**Test flows:**
1. Create flow: Show Create Modal > Continue > (passkey prompt) > Continue > success
2. Import flow: Show Import Modal > drop .key file > Continue > (passkey prompt) > success
3. Error flow: Show Create Modal > cancel the passkey prompt > error state > Proceed Without Passkeys
4. Cancel: Show Create Modal > Cancel > modal closes cleanly; reopen shows fresh state

---

### `hook-test.html` -- usePasskeyFlow Hook Inspector

Tests the `usePasskeyFlow` hook directly, without `PasskeyModal`. Useful for verifying the state machine in isolation.

**State machine** visualizes the main flow steps (`idle` → `ready` → `registering` → `awaiting_completion` → `completing` → `success`) with branch steps (`importing`, `ready_with_keypair`, `fallback_registering`, `error`) shown inline when active. A WASM status indicator in the header and state machine bar shows whether the crypto backend loaded successfully.

**State panel** shows all hook return values live: `step`, `error`, `address`, `isImportMode`, `isPasskeySupported`, `canRetry`.

**Action buttons** are wired to every hook method:
- `startRegistration()` -- triggers first WebAuthn prompt
- `completeRegistration()` -- triggers second WebAuthn prompt (enabled only when `step: awaiting_completion`)
- `proceedWithoutPasskey()` -- fallback flow
- `importKeyFile()` -- file picker for .key files
- `retry()` -- enabled only when `canRetry: true`
- `cancel()` / `dismiss()`

**Event log** records all `onStepChange`, `onComplete`, `onError`, `onCancel` callback fires with timestamps.

---

## Architecture

- **Source CSS**: `src/components/modals/PasskeyModal.css`
- **Built CSS**: `dist/index.css` (compiled with PostCSS) -- used by both test pages
- **Built SDK**: `dist/index.esm.js` -- loaded as ES module, exposed as `window.__SDK__`

Both pages use CDN React + Babel standalone for JSX -- no extra build dependencies. WASM is initialized on load; if it fails, the SDK still loads but crypto actions will not work (indicated by a red status dot).

---

## Limitations

These test pages load the SDK directly in the browser without a proper bundler (webpack, Vite, etc.). This creates several constraints:

- **Node.js `crypto` module**: Shimmed via a CDN polyfill (`crypto-browserify` from esm.sh). The polyfill does not fully work in this context, so operations that call `crypto.createHash` (address derivation) fail with a "Class constructor cannot be invoked without new" error. This does not affect the real SDK when consumed through a bundler.

- **WebAuthn / Passkeys**: `navigator.credentials.create()` requires HTTPS or a properly configured platform authenticator (Windows Hello, Touch ID). On `http://localhost` with Windows 10, the browser prompt may not appear at all. The SDK itself works correctly on HTTPS in production.

- **Bare import specifiers**: The ESM bundle uses bare imports (`buffer`, `crypto`, `react`). An importmap + local shims redirect these to CDN/UMD equivalents. This is fragile but adequate for testing UI states.

**What you CAN test here:**
- Modal UI states (Force Success/Error on index.html)
- CSS, animations, layout of PasskeyModal
- WASM loading and key generation
- State machine transitions and error handling (hook-test.html)
- Hook return values and callback timing

**What requires the real app:**
- Full end-to-end passkey registration flow
- WebAuthn browser prompts
- Address derivation and upload

---

*Updated: 2026-04-13*
