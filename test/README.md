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
- **Show Create Modal** -- opens the modal in new-account flow
- **Show Import Modal** -- opens the modal in import flow (with .key file dropzone)
- **Hide Modal** -- closes the modal
- **Force Success State** -- injects success context values; no authenticator needed (UI-only test)
- **Force Error State** -- injects error context values with a sample error message; no authenticator needed

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

Both pages use CDN React + Babel standalone for JSX -- no extra build dependencies.

---

*Updated: 2026-04-13*
