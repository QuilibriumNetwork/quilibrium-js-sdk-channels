import { useState, useEffect, useCallback, useRef } from 'react';
import { Buffer } from 'buffer';
import {
  completeRegistration as sdkCompleteRegistration,
  register,
  encryptDataSaveKey,
  updateStoredPasskey,
  createKeyFromBuffer,
  encrypt,
} from '../passkeys/types';
import { usePasskeysContext } from '../components/context/PasskeysContext';
import { sha256 } from 'multiformats/hashes/sha2';
import { base58btc } from 'multiformats/bases/base58';
import * as secureChannel from '../channel/channel';
import * as ch from '../channel/channelwasm';
import type {
  PasskeyFlowStep,
  PasskeyErrorCode,
  PasskeyFlowError,
  UsePasskeyFlowOptions,
  UsePasskeyFlowReturn,
} from '../types/passkey-flow';

/**
 * Classify a caught error into a stable PasskeyErrorCode.
 *
 * Classification strategy:
 * - DOMException.name for WebAuthn errors (most reliable)
 * - Context parameter for storage vs network vs file errors
 * - Fallback to 'unknown'
 */
function classifyError(
  error: unknown,
  context: 'registration' | 'completion' | 'upload' | 'file_import',
): PasskeyFlowError {
  const rawMessage = error instanceof Error ? error.message : String(error);

  // File import errors are always 'invalid_key_file'
  if (context === 'file_import') {
    return { code: 'invalid_key_file', rawMessage };
  }

  // Upload errors are always 'network_error'
  if (context === 'upload') {
    return { code: 'network_error', rawMessage };
  }

  // DOMException-based classification for WebAuthn errors
  if (error instanceof DOMException) {
    switch (error.name) {
      case 'NotAllowedError':
        return { code: 'user_cancelled', rawMessage };
      case 'NotSupportedError':
        return { code: 'not_supported', rawMessage };
      case 'TimeoutError':
      case 'AbortError':
        return { code: 'timeout', rawMessage };
    }
  }

  // Non-DOMException during completion = storage failure
  // (e.g., Error('could not add key to credential') from LargeBlob write)
  if (context === 'completion' && !(error instanceof DOMException)) {
    return { code: 'storage_failed', rawMessage };
  }

  return { code: 'unknown', rawMessage };
}

export function usePasskeyFlow(options: UsePasskeyFlowOptions): UsePasskeyFlowReturn {
  const {
    fqAppPrefix,
    getUserRegistration,
    uploadRegistration,
    onStepChange,
    onComplete,
    onError,
    onCancel,
  } = options;

  // --- Context ---
  const {
    showPasskeyPrompt,
    setShowPasskeyPrompt,
    passkeyRegistrationComplete,
    setPasskeyRegistrationComplete,
    passkeyRegistrationError,
    setPasskeyRegistrationError,
  } = usePasskeysContext();

  // --- Internal state ---
  const [keypair, setKeypair] = useState<string | undefined>();
  const [credentialId, setCredentialId] = useState<string | undefined>();
  const [address, setAddress] = useState<string | null>(null);
  const [internalStep, setInternalStep] = useState<PasskeyFlowStep>('idle');
  const [error, setError] = useState<PasskeyFlowError | null>(null);
  const [canRetry, setCanRetry] = useState(false);
  const [passkeySupported, setPasskeySupported] = useState(true);

  // Track previous step for onStepChange callback
  const prevStepRef = useRef<PasskeyFlowStep>('idle');

  // --- Electron / incompatibility detection (runs once on mount) ---
  useEffect(() => {
    // @ts-ignore
    if (window.electron) {
      if (!window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`)) {
        window.localStorage.setItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`, 'true');
      }
      setPasskeySupported(false);
    } else if (window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`)) {
      setPasskeySupported(false);
    }
  }, [fqAppPrefix]);

  // --- Compute the canonical step from state ---
  // Priority order matters: error > success > awaiting > ready_with_keypair > ready > idle
  // This matches the JSX conditional ordering in the original PasskeyModal.
  const computedStep: PasskeyFlowStep = (() => {
    // Transient steps (registering, completing, importing, fallback_registering)
    // are set directly via setInternalStep during async operations.
    if (
      internalStep === 'registering' ||
      internalStep === 'completing' ||
      internalStep === 'importing' ||
      internalStep === 'fallback_registering'
    ) {
      return internalStep;
    }

    if (!showPasskeyPrompt.value) {
      return 'idle';
    }

    // Error state: passkeyRegistrationComplete === false AND error is set
    if (passkeyRegistrationComplete === false && passkeyRegistrationError) {
      return 'error';
    }

    // Success
    if (passkeyRegistrationComplete === true) {
      return 'success';
    }

    // Awaiting second prompt
    if (credentialId && passkeyRegistrationComplete === undefined) {
      return 'awaiting_completion';
    }

    // Import mode with parsed keypair
    if (showPasskeyPrompt.importMode && keypair && !credentialId) {
      return 'ready_with_keypair';
    }

    // Active and waiting for user action
    return 'ready';
  })();

  // Use computed step, but allow transient overrides
  const step = computedStep;

  // --- Fire onStepChange callback ---
  useEffect(() => {
    if (step !== prevStepRef.current) {
      prevStepRef.current = step;
      onStepChange?.(step);

      if (step === 'success') {
        onComplete?.();
      }
      if (step === 'error' && error) {
        onError?.(error);
      }
    }
  }, [step, error, onStepChange, onComplete, onError]);

  // --- Shared helpers ---

  /**
   * Generate or reuse a keypair. Returns the parsed keypair object and
   * the raw JSON string (for state storage).
   */
  const getOrGenerateKeypair = useCallback((): { pair: string; parsed: { public_key: number[]; private_key: number[] } } => {
    let pair = keypair ?? '';
    if (!pair) {
      pair = ch.js_generate_ed448();
      setKeypair(pair);
    }
    return { pair, parsed: JSON.parse(pair) };
  }, [keypair]);

  /**
   * Derive address from a public key via sha256 + base58btc.
   */
  const deriveAddress = useCallback(async (publicKey: number[]): Promise<string> => {
    const h = await sha256.digest(Buffer.from(publicKey) as unknown as Uint8Array<ArrayBufferLike>);
    return base58btc.baseEncode(h.bytes);
  }, []);

  /**
   * Build and upload user registration. This is the shared logic from all
   * completion paths (passkey complete, fallback complete).
   */
  const buildAndUploadRegistration = useCallback(async (
    addr: string,
    p: { public_key: number[]; private_key: number[] },
  ): Promise<void> => {
    const senderIdent = secureChannel.NewUserKeyset({
      type: 'ed448',
      private_key: [...p.private_key],
      public_key: [...p.public_key],
    });
    const senderDevice = await secureChannel.NewDeviceKeyset();

    let existing: secureChannel.UserRegistration | undefined;
    try {
      existing = await getUserRegistration(addr);
    } catch {}

    const senderRegistration = await secureChannel.ConstructUserRegistration(
      senderIdent,
      existing?.device_registrations ?? [],
      [senderDevice],
    );

    const key = await createKeyFromBuffer(
      new Uint8Array(p.private_key) as unknown as ArrayBuffer,
    );
    const inner = await encrypt(
      Buffer.from(JSON.stringify({ identity: senderIdent, device: senderDevice }), 'utf-8'),
      key,
    );
    const envelope = Buffer.from(
      JSON.stringify({
        iv: [...inner.iv],
        ciphertext: [...new Uint8Array(inner.ciphertext)],
      }),
      'utf-8',
    );
    await encryptDataSaveKey(2, envelope);

    // Note: original code does NOT await this. Preserving that behavior.
    uploadRegistration({ address: addr, registration: senderRegistration });
  }, [getUserRegistration, uploadRegistration]);

  // --- Actions ---

  const importKeyFile = useCallback(async (file: File): Promise<void> => {
    setInternalStep('importing');
    try {
      const data = await file.arrayBuffer();
      let keyHex: string;

      if (data.byteLength === 57) {
        keyHex = Buffer.from(data).toString('hex');
      } else {
        keyHex = Buffer.from(data).toString('utf-8');
      }

      if (keyHex.length !== 114) {
        if (keyHex.startsWith('{')) {
          keyHex = Buffer.from(
            new Uint8Array(JSON.parse(keyHex).private_key),
          ).toString('hex');
        }
      }

      if (keyHex.length !== 114) {
        throw new Error('Corrupted key file, try a different file or cancel and create a new account');
      }

      const pubkey = Buffer.from(
        ch.js_get_pubkey_ed448(Buffer.from(keyHex, 'hex').toString('base64')),
        'base64',
      );

      const pair = JSON.stringify({
        public_key: [...new Uint8Array(pubkey)],
        private_key: [...new Uint8Array(Buffer.from(keyHex, 'hex'))],
      });

      setKeypair(pair);
      setInternalStep('ready_with_keypair');
    } catch (e: unknown) {
      const classified = classifyError(e, 'file_import');
      setError(classified);
      setCanRetry(true);
      setPasskeyRegistrationComplete(false);
      setPasskeyRegistrationError(classified.rawMessage ?? 'Invalid key file');
      setInternalStep('error');
    }
  }, [setPasskeyRegistrationComplete, setPasskeyRegistrationError]);

  const startRegistration = useCallback(async (): Promise<void> => {
    setInternalStep('registering');
    try {
      const { pair, parsed: p } = getOrGenerateKeypair();
      const addr = await deriveAddress(p.public_key);
      setAddress(addr);

      const r = await register(fqAppPrefix, addr);
      setCredentialId(r.id);

      // Check if register() detected incompatibility mid-flow
      if (window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`)) {
        setPasskeySupported(false);
      }

      setInternalStep('awaiting_completion');
    } catch (e: unknown) {
      const classified = classifyError(e, 'registration');
      setError(classified);
      setCanRetry(true); // No credential created yet, safe to retry
      setPasskeyRegistrationComplete(false);
      setPasskeyRegistrationError(classified.rawMessage ?? 'Registration failed');
      setInternalStep('error');
    }
  }, [fqAppPrefix, getOrGenerateKeypair, deriveAddress, setPasskeyRegistrationComplete, setPasskeyRegistrationError]);

  const completeRegistrationAction = useCallback(async (): Promise<void> => {
    setInternalStep('completing');
    try {
      const { pair, parsed: p } = getOrGenerateKeypair();
      const addr = address ?? await deriveAddress(p.public_key);
      if (!address) setAddress(addr);

      if (!credentialId) {
        throw new Error('No credential ID - cannot complete registration');
      }

      await sdkCompleteRegistration(fqAppPrefix, {
        credentialId,
        largeBlob: Buffer.from(p.private_key).toString('hex'),
        publicKey: Buffer.from(p.public_key).toString('hex'),
        address: addr,
      });

      // Check if completeRegistration fell back to IndexedDB silently
      if (window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`)) {
        setPasskeySupported(false);
      }

      await buildAndUploadRegistration(addr, p);
      setPasskeyRegistrationComplete(true);
      setKeypair(undefined);
      setCredentialId(undefined);
      setInternalStep('success');
    } catch (e: unknown) {
      const classified = classifyError(e, 'completion');
      setError(classified);
      setCanRetry(false); // Credential may exist, retry would create orphan
      setPasskeyRegistrationComplete(false);
      setPasskeyRegistrationError(classified.rawMessage ?? 'Completion failed');
      setInternalStep('error');
    }
  }, [fqAppPrefix, credentialId, address, getOrGenerateKeypair, deriveAddress, buildAndUploadRegistration, setPasskeyRegistrationComplete, setPasskeyRegistrationError]);

  const proceedWithoutPasskey = useCallback(async (): Promise<void> => {
    setInternalStep('fallback_registering');
    try {
      window.localStorage.setItem(
        `${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`,
        'true',
      );
      setPasskeySupported(false);

      const { pair, parsed: p } = getOrGenerateKeypair();
      const addr = address ?? await deriveAddress(p.public_key);
      if (!address) setAddress(addr);

      setCredentialId('not-passkey');

      await encryptDataSaveKey(1, Buffer.from(new Uint8Array(p.private_key)));

      // BUG FIX: use p.public_key (snake_case), not p.publicKey (camelCase)
      // Original code at lines 409 and 495 used p.publicKey which is undefined.
      updateStoredPasskey('not-passkey', {
        credentialId: 'not-passkey',
        address: addr,
        publicKey: Buffer.from(p.public_key).toString('hex'),
        completedOnboarding: false,
      });

      await buildAndUploadRegistration(addr, p);
      setPasskeyRegistrationComplete(true);
      setKeypair(undefined);
      setCredentialId(undefined);
      setPasskeyRegistrationError(undefined);
      setInternalStep('success');
    } catch (e: unknown) {
      // Note: uploadRegistration is fire-and-forget (not awaited), so upload
      // errors won't reach this catch. Only encryptDataSaveKey/storage errors can.
      const classified = classifyError(e, 'completion');
      setError(classified);
      setCanRetry(false);
      setPasskeyRegistrationComplete(false);
      setPasskeyRegistrationError(classified.rawMessage ?? 'Fallback registration failed');
      setInternalStep('error');
    }
  }, [fqAppPrefix, address, getOrGenerateKeypair, deriveAddress, buildAndUploadRegistration, setPasskeyRegistrationComplete, setPasskeyRegistrationError]);

  const retry = useCallback((): void => {
    if (!canRetry) return;
    setError(null);
    setPasskeyRegistrationComplete(undefined);
    setPasskeyRegistrationError(undefined);
    // Don't clear keypair - if import mode, preserve the parsed file
    // Don't clear credentialId - canRetry is only true when no credential exists
    setInternalStep(keypair ? 'ready_with_keypair' : 'ready');
  }, [canRetry, keypair, setPasskeyRegistrationComplete, setPasskeyRegistrationError]);

  const cancel = useCallback((): void => {
    setError(null);
    setCanRetry(false);
    setKeypair(undefined);
    // BUG FIX: original cancel didn't reset credentialId.
    // INTENTIONAL BEHAVIOR CHANGE: The original allowed "resuming" an interrupted
    // flow after cancel (reopening showed Step 1b). This is broken behavior because
    // the stale credential from Step 1a is unusable in a new session and causes
    // confusing UX. We now reset fully, which means a cancelled-then-reopened flow
    // starts fresh at Step 1a (creating a new credential). The orphan from the
    // first attempt remains in the authenticator (WebAuthn limitation).
    setCredentialId(undefined);
    setAddress(null);
    setPasskeyRegistrationError(undefined);
    setPasskeyRegistrationComplete(undefined);
    setShowPasskeyPrompt({ ...showPasskeyPrompt, value: false });
    setInternalStep('idle');
    onCancel?.();
  }, [showPasskeyPrompt, setShowPasskeyPrompt, setPasskeyRegistrationError, setPasskeyRegistrationComplete, onCancel]);

  const dismiss = useCallback((): void => {
    setShowPasskeyPrompt({ ...showPasskeyPrompt, value: false });
    setInternalStep('idle');
  }, [showPasskeyPrompt, setShowPasskeyPrompt]);

  // --- Return ---
  return {
    step,
    error,
    address,
    isImportMode: !!showPasskeyPrompt.importMode,
    isPasskeySupported: passkeySupported,
    hasKeypair: !!keypair,
    canRetry,
    startRegistration,
    completeRegistration: completeRegistrationAction,
    proceedWithoutPasskey,
    importKeyFile,
    retry,
    cancel,
    dismiss,
  };
}
