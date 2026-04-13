# @quilibrium/quilibrium-js-sdk-channels

TypeScript/React SDK for the Quilibrium decentralized network. Provides cryptographic channel primitives for end-to-end encrypted messaging using Double Ratchet (1:1) and Triple Ratchet (group) protocols, along with WebAuthn/Passkey-based key management for browser applications.

## Installation

```bash
yarn add @quilibrium/quilibrium-js-sdk-channels
```

**WASM requirement**: Consuming apps must serve the bundled `.wasm` file at `/wasm/channelwasm_bg.wasm`. Copy it from `node_modules/@quilibrium/quilibrium-js-sdk-channels/dist/` to your public directory.

## Quick start

```tsx
import { channel, passkey, PasskeysProvider, PasskeyModal } from '@quilibrium/quilibrium-js-sdk-channels';

// Wrap your app with the provider
function App() {
  return (
    <PasskeysProvider fqAppPrefix="myapp">
      <PasskeyModal
        fqAppPrefix="myapp"
        getUserRegistration={async (address) => { /* fetch from backend */ }}
        uploadRegistration={async ({ address, registration }) => { /* send to backend */ }}
      />
      {/* your app */}
    </PasskeysProvider>
  );
}
```

## Exports

| Export | Description |
|--------|-------------|
| `channel` | Core SDK: key generation, Double/Triple Ratchet sessions, sealed envelopes |
| `channel_raw` | Direct wasm-bindgen bindings (low-level) |
| `passkey` | WebAuthn credential management (register, authenticate, storage) |
| `PasskeysProvider` | React context provider for passkey lifecycle state |
| `usePasskeysContext` | Hook to access passkey state and actions |
| `PasskeyModal` | Onboarding modal UI for passkey creation and key import |

## Cryptographic primitives

- **Ed448** (57-byte keys) for digital signatures
- **X448** (56-byte keys) for Diffie-Hellman key exchange
- **X3DH** key agreement to bootstrap Double Ratchet sessions
- **Double Ratchet** for 1:1 encrypted messaging
- **Triple Ratchet** for multi-party encrypted group channels ("Spaces")
- **Sealed envelopes**: Inbox (ECDH + AES-GCM), Hub (+ Ed448 signature), Sync (owner-signed)

All cryptographic operations run in a Rust-compiled WebAssembly module.

## Passkey compatibility

| Environment | Strategy | Storage |
|-------------|----------|---------|
| Chrome 131+ | PRF extension | AES-GCM encrypted blob in localStorage |
| Safari 17+ | LargeBlob extension | Raw blob in authenticator |
| Electron / fallback | IndexedDB | AES-GCM key + encrypted blob in IndexedDB |

## Development

```bash
yarn install       # Install dependencies
yarn build         # Build to dist/ (CJS + ESM + types + CSS)
yarn dev           # Watch mode
yarn clean         # Remove dist/
```

### Type checking

```bash
npx tsc --noEmit
```

## Testing

There is no automated test suite. Testing is done visually via browser test pages in the [`test/`](test/) folder (see [test/README.md](test/README.md) for full details).

### Development testing

```bash
yarn test
```

Serves `test/index.html` at `http://localhost:3001`. This page renders the PasskeyModal with a control panel to switch between all modal states (create, import, success, error). Uses source CSS directly for fast iteration: edit `src/components/modals/PasskeyModal.css`, refresh the browser, and see changes immediately.

### Production build testing

```bash
yarn test-build
```

Runs a full `yarn build`, generates `test/test-build.html` wired to the compiled CSS from `dist/`, and serves it. Use this to verify that the build pipeline produces correct output before publishing.

## Build output

| File | Format |
|------|--------|
| `dist/index.js` | CommonJS |
| `dist/index.esm.js` | ES Module |
| `dist/index.d.ts` | TypeScript declarations |
| `dist/index.css` | Extracted CSS |
| `dist/channelwasm_bg.wasm` | WebAssembly binary |

React and react-dom are externalized (peer dependencies, not bundled).

## License

MIT
