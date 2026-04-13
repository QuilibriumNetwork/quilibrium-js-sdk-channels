import React from 'react';
import { usePasskeysContext } from '../context/PasskeysContext';
import { useDropzone } from 'react-dropzone';
import { usePasskeyFlow } from '../../hooks/usePasskeyFlow';
import * as secureChannel from '../../channel/channel';
import './PasskeyModal.css';

export const PasskeyModal = ({
  fqAppPrefix,
  getUserRegistration,
  uploadRegistration,
}: {
  fqAppPrefix: string;
  getUserRegistration: (address: string) => Promise<secureChannel.UserRegistration>;
  uploadRegistration: ({ address, registration }: {
    address: string;
    registration: secureChannel.UserRegistration;
  }) => Promise<void>;
}) => {
  const {
    showPasskeyPrompt,
    passkeyRegistrationComplete,
    passkeyRegistrationError,
  } = usePasskeysContext();

  const hook = usePasskeyFlow({
    fqAppPrefix,
    getUserRegistration,
    uploadRegistration,
  });

  const { getRootProps, getInputProps, acceptedFiles, inputRef } = useDropzone({
    accept: { 'text/plain': ['.key'] },
    minSize: 0,
    maxSize: 1 * 1024 * 1024,
  });

  // --- Button click dispatcher ---
  // Maps the single "Continue" button to the appropriate hook action
  // based on current step, preserving original multi-branch behavior.
  const handlePrimaryClick = async () => {
    switch (hook.step) {
      case 'success':
        hook.dismiss();
        break;
      case 'awaiting_completion':
        await hook.completeRegistration();
        break;
      case 'ready_with_keypair':
        await hook.startRegistration();
        break;
      case 'ready':
        if (hook.isImportMode && acceptedFiles.length) {
          await hook.importKeyFile(acceptedFiles[0]);
        } else if (!hook.isImportMode) {
          if (!hook.isPasskeySupported) {
            await hook.proceedWithoutPasskey();
          } else {
            await hook.startRegistration();
          }
        }
        break;
    }
  };

  // Clear the dropzone when file parse fails, so user can drop a new file.
  // The original used (acceptedFiles as any[]).shift() which is a mutation hack.
  // This approach resets the file input instead.
  React.useEffect(() => {
    if (hook.step === 'error' && hook.error?.code === 'invalid_key_file' && inputRef.current) {
      inputRef.current.value = '';
    }
  }, [hook.step, hook.error]);

  // --- Render (preserves exact original JSX structure and CSS classes) ---
  return (
    <div
      className={`passkey-modal-backdrop ${showPasskeyPrompt.value ? '' : 'hidden'}`}
    >
      <div className="passkey-modal-container">
        <h2 className="passkey-modal-header">
          {showPasskeyPrompt.importMode
            ? 'Import Existing Key'
            : 'Create Passkey'}
        </h2>
        <div className="passkey-modal-icon-wrapper">
          <div
            style={{
              backgroundImage:
                passkeyRegistrationComplete !== false &&
                passkeyRegistrationComplete !== true
                  ? 'url("/passkey.png")'
                  : undefined,
            }}
            className={
              'passkey-modal-icon' +
              (passkeyRegistrationComplete === true
                ? ' success'
                : passkeyRegistrationComplete === false
                  ? ' error'
                  : ' default pulsating')
            }
          >
            {passkeyRegistrationComplete === true
              ? '✓'
              : passkeyRegistrationComplete === false
                ? '!'
                : ''}
          </div>
        </div>
        <div className="passkey-modal-content">
          {passkeyRegistrationComplete === false && passkeyRegistrationError ? (
            <>
              <div>
                An error was encountered while attempting to register the
                passkey.
              </div>
              <div className="passkey-modal-error">
                {passkeyRegistrationError}
              </div>
              <div className="passkey-modal-mt-4">
                If your browser told you the passkey option cannot be used with
                the site, you may be running an unsupported browser. If the
                browser provides an option to use a phone for passkeys, use
                this. Alternatively, if you would like to proceed without
                passkeys, click Proceed Without Passkeys.
              </div>
            </>
          ) : passkeyRegistrationComplete === true ? (
            'Your passkey has been successfully created.'
          ) : hook.step === 'awaiting_completion' ? (
            'To save the account, you will need to perform one more passkey interaction. Tap continue to complete.'
          ) : showPasskeyPrompt.importMode ? (
            hook.step === 'ready_with_keypair' ? (
              "Use Passkeys to save your account, with the security of your own device's secure element. This will require two round-trips with your authenticator to complete to fully save the account."
            ) : (
              'To begin, import your existing key file. Drop it in the area below or click on the area below to select the file.'
            )
          ) : (
            "Use Passkeys to access your account, with the security of your own device's secure element. This will require two round-trips with your authenticator to complete to fully register the account."
          )}
        </div>
        {showPasskeyPrompt.importMode &&
          !passkeyRegistrationComplete &&
          hook.step !== 'ready_with_keypair' &&
          hook.step !== 'awaiting_completion' &&
          hook.step !== 'registering' && (
            <div className="passkey-modal-content">
              <div className="passkey-modal-dropzone" {...getRootProps()}>
                <input {...getInputProps()} style={{ display: 'none' }} />
                <div className="passkey-modal-dropzone-text">
                  {acceptedFiles.length
                    ? acceptedFiles[0].name
                    : 'Drop key file here or click to select'}
                </div>
              </div>
            </div>
          )}
        {/* Primary "Continue" button - shown in import mode when file ready or complete */}
        {showPasskeyPrompt.importMode ? (
          acceptedFiles.length ||
          passkeyRegistrationComplete ||
          hook.step === 'ready_with_keypair' ||
          hook.step === 'awaiting_completion' ? (
            <div onClick={handlePrimaryClick} className="passkey-modal-btn primary">
              Continue
            </div>
          ) : (
            <></>
          )
        ) : !hook.isPasskeySupported ? (
          // Incompatibility fallback: show Continue that does proceedWithoutPasskey
          <div onClick={handlePrimaryClick} className="passkey-modal-btn primary">
            Continue
          </div>
        ) : (
          // Normal passkey flow: show Continue
          <div onClick={handlePrimaryClick} className="passkey-modal-btn primary">
            Continue
          </div>
        )}
        {/* "Proceed Without Passkeys" warning button */}
        {/* Original condition: passkeyRegistrationError && (!importMode || keypair) */}
        {/* keypair being set maps to ready_with_keypair or later steps with keypair */}
        {passkeyRegistrationError &&
          (!showPasskeyPrompt.importMode || hook.step === 'ready_with_keypair') && (
            <div
              onClick={() => hook.proceedWithoutPasskey()}
              className="passkey-modal-btn warning"
            >
              Proceed Without Passkeys
            </div>
          )}
        {/* Cancel button */}
        {!passkeyRegistrationComplete && (
          <div
            onClick={() => hook.cancel()}
            className="passkey-modal-btn secondary"
          >
            Cancel
          </div>
        )}
      </div>
    </div>
  );
};
