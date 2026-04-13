import React, {
  FC,
  ReactNode,
  createContext,
  useContext,
  useEffect,
  useState,
} from 'react';
import {
  authenticate,
  getStoredPasskeys,
  StoredPasskey,
  updateStoredPasskey as updatePasskey,
} from '../../passkeys/types';
import * as ch from '../../channel/channelwasm';

type PasskeysContextValue = {
  currentPasskeyInfo:
    | {
        credentialId: string;
        address: string;
        publicKey: string;
        displayName?: string;
        pfpUrl?: string;
        completedOnboarding: boolean;
      }
    | undefined;
  showPasskeyPrompt: { value: boolean; importMode?: boolean };
  setShowPasskeyPrompt: (state: {
    value: boolean;
    importMode?: boolean;
  }) => void;
  passkeyRegistrationComplete?: boolean;
  setPasskeyRegistrationComplete: (value: boolean | undefined) => void;
  passkeyRegistrationError?: string;
  setPasskeyRegistrationError: (value: string | undefined) => void;
  signWithPasskey: (credentialId: string, payload: string) => Promise<string>;
  exportKey: (credentialId: string) => Promise<string>;
  updateStoredPasskey: (
    credentialId: string,
    storedPasskey: StoredPasskey
  ) => void;
};

type PasskeysContextProps = {
  fqAppPrefix: string;
  children: ReactNode;
};

const PasskeysProvider: FC<PasskeysContextProps> = ({ fqAppPrefix, children }) => {
  const [currentPasskeyInfo, setCurrentPassKeyInfo] = useState<{
    credentialId: string;
    address: string;
    publicKey: string;
    displayName?: string;
    pfpUrl?: string;
    completedOnboarding: boolean;
  }>();
  const [showPasskeyPrompt, setShowPasskeyPrompt] = useState<{
    value: boolean;
  }>({ value: false });
  const [passkeyRegistrationComplete, setPasskeyRegistrationComplete] =
    useState<boolean | undefined>();
  const [passkeyRegistrationError, setPasskeyRegistrationError] =
    useState<string>();
  const exportKey = async (credentialId: string): Promise<string> => {
    const cred = await authenticate(fqAppPrefix, { credentialId });
    if (!cred.largeBlob) {
      throw new Error('No key material in credential response');
    }
    return cred.largeBlob;
  };

  const signWithPasskey = async (credentialId: string, payload: string) => {
    const cred = await authenticate(fqAppPrefix, { credentialId });
    if (!cred.largeBlob) {
      throw new Error('No key material in credential response');
    }
    // authenticate() normalizes all paths to return a hex string of the private key.
    // Legacy data may be JSON with a .private_key field; handle both formats.
    let privateKeyB64: string;
    if (cred.largeBlob.startsWith('{')) {
      privateKeyB64 = Buffer.from(
        new Uint8Array(JSON.parse(cred.largeBlob).private_key)
      ).toString('base64');
    } else {
      privateKeyB64 = Buffer.from(cred.largeBlob, 'hex').toString('base64');
    }
    return ch.js_sign_ed448(privateKeyB64, payload);
  };

  const updateStoredPasskey = (
    credentialId: string,
    storedPasskey: StoredPasskey
  ) => {
    updatePasskey(credentialId, storedPasskey);
    setCurrentPassKeyInfo(storedPasskey);
  };

  useEffect(() => {
    getStoredPasskeys().then((p) => {
      if (p.length > 0) {
        setCurrentPassKeyInfo({ ...p[0] });
        setPasskeyRegistrationComplete(true);
      }
    });
  }, [passkeyRegistrationComplete]);

  return (
    <PasskeysContext.Provider
      value={{
        currentPasskeyInfo,
        showPasskeyPrompt,
        setShowPasskeyPrompt,
        passkeyRegistrationComplete,
        setPasskeyRegistrationComplete,
        passkeyRegistrationError,
        setPasskeyRegistrationError,
        signWithPasskey,
        exportKey,
        updateStoredPasskey,
      }}
    >
      {children}
    </PasskeysContext.Provider>
  );
};

const PasskeysContext = createContext<PasskeysContextValue>({
  currentPasskeyInfo: undefined,
  showPasskeyPrompt: undefined as never,
  setShowPasskeyPrompt: () => undefined,
  passkeyRegistrationComplete: undefined,
  setPasskeyRegistrationComplete: () => undefined,
  passkeyRegistrationError: undefined,
  setPasskeyRegistrationError: () => undefined,
  signWithPasskey: async () => undefined as unknown as Promise<string>,
  exportKey: async () => undefined as unknown as string,
  updateStoredPasskey: (credentialId: string, storedPasskey: StoredPasskey) =>
    undefined as unknown,
});

const usePasskeysContext = () => useContext(PasskeysContext);

export { PasskeysProvider, usePasskeysContext };
