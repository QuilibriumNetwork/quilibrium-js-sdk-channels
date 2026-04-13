import { Buffer } from 'buffer';
window.Buffer = Buffer;

export * as channel from './channel/channel';
export { PasskeysProvider, usePasskeysContext } from './components/context/PasskeysContext';
export { PasskeyModal } from './components/modals/PasskeyModal';
export * as passkey from './passkeys/types';
export * as channel_raw from './channel/channelwasm';

// New: headless hook for custom passkey UI
export { usePasskeyFlow } from './hooks/usePasskeyFlow';
export type {
  UsePasskeyFlowOptions,
  UsePasskeyFlowReturn,
  PasskeyFlowStep,
  PasskeyFlowError,
  PasskeyErrorCode,
} from './types/passkey-flow';
