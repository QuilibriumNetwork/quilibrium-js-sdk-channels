import type * as secureChannel from '../channel/channel';

// --- Step State Machine ---

export type PasskeyFlowStep =
  | 'idle'
  | 'ready'
  | 'importing'
  | 'ready_with_keypair'
  | 'registering'
  | 'awaiting_completion'
  | 'completing'
  | 'success'
  | 'error'
  | 'fallback_registering';

// --- Error Types ---

export type PasskeyErrorCode =
  | 'user_cancelled'
  | 'not_supported'
  | 'timeout'
  | 'storage_failed'
  | 'invalid_key_file'
  | 'network_error'
  | 'unknown';

export interface PasskeyFlowError {
  code: PasskeyErrorCode;
  rawMessage?: string;
}

// --- Hook Options ---

/**
 * Options for usePasskeyFlow.
 *
 * IMPORTANT: `getUserRegistration`, `uploadRegistration`, and callback functions
 * should be stable references (wrapped in useCallback or defined outside the
 * component) to avoid unnecessary re-renders and effect re-runs.
 */
export interface UsePasskeyFlowOptions {
  fqAppPrefix: string;
  getUserRegistration: (address: string) => Promise<secureChannel.UserRegistration>;
  uploadRegistration: (params: {
    address: string;
    registration: secureChannel.UserRegistration;
  }) => Promise<void>;
  onStepChange?: (step: PasskeyFlowStep) => void;
  onComplete?: () => void;
  onError?: (error: PasskeyFlowError) => void;
  onCancel?: () => void;
}

// --- Hook Return ---

export interface UsePasskeyFlowReturn {
  // State
  step: PasskeyFlowStep;
  error: PasskeyFlowError | null;
  address: string | null;
  isImportMode: boolean;
  isPasskeySupported: boolean;
  canRetry: boolean;

  // Actions
  startRegistration: () => Promise<void>;
  completeRegistration: () => Promise<void>;
  proceedWithoutPasskey: () => Promise<void>;
  importKeyFile: (file: File) => Promise<void>;
  retry: () => void;
  cancel: () => void;
  dismiss: () => void;
}
