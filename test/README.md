# SDK Testing

## Quick Start

```bash
yarn build       # build the SDK (required before testing)
yarn test        # run automated health check (no browser needed)
```

`yarn test` verifies the SDK works end-to-end in under a second:

- Build artifacts exist (JS, ESM, .d.ts, CSS, WASM)
- SDK module loads
- WASM crypto backend compiles and initializes
- Ed448 key generation produces valid keypairs
- Public key derivation works
- All required exports present (PasskeysProvider, usePasskeyFlow, PasskeyModal, etc.)
- TypeScript declarations include expected types

If any check fails, it exits with code 1 and tells you what broke.

---

## Visual Test Pages

For testing modal UI states in the browser:

```bash
yarn serve       # start HTTP server on http://localhost:3001
```

Then open:

- `http://localhost:3001/test/` -- PasskeyModal visual test
- `http://localhost:3001/test/hook-test.html` -- SDK diagnostics + hook inspector

### `index.html` -- PasskeyModal Visual Test

Tests the real `PasskeyModal` component from `dist/`. Use the sidebar to open the modal and test visual states.

**Recommended workflow:**
1. Click **Show Create** or **Show Import** to open the modal
2. Use **Force Success / Force Error** to test all visual states without a real authenticator
3. The modal's own buttons (Continue, Cancel) drive real state, but WebAuthn requires HTTPS

### `hook-test.html` -- SDK Diagnostics + Hook Inspector

Two sections:

1. **SDK Diagnostics** -- runs the same checks as `yarn test` but in the browser. Shows pass/fail for SDK loading, WASM, key generation, WebAuthn API, and exports. If you see all green, the SDK build is healthy.

2. **Hook Inspector** -- shows the `usePasskeyFlow` state machine live. Action buttons let you trigger hook methods and watch state transitions in the event log. Actions will fail with crypto polyfill errors (this is expected in the browser, see limitations below).

---

## Limitations of the Visual Test Pages

The test pages load the SDK directly in the browser without a bundler. This creates constraints that do not affect the real SDK when consumed through webpack/Vite:

- **crypto polyfill**: Node.js `crypto` is shimmed via esm.sh. The shim doesn't fully work, so address derivation fails with a "Class constructor" error.
- **WebAuthn**: Requires HTTPS and a platform authenticator (Windows Hello, Touch ID). Does not work on `http://localhost` on most Windows setups.
- **Bare imports**: Handled via importmap + local shims for React. Fragile but sufficient for UI testing.

**What the visual pages are good for:** modal CSS/animations/layout, Force Success/Error UI states, verifying WASM loads, watching state machine transitions.

**What requires the real app:** end-to-end passkey registration, WebAuthn prompts, address derivation.

The automated `yarn test` check covers everything that can be verified without a browser.

---

*Updated: 2026-04-13*
