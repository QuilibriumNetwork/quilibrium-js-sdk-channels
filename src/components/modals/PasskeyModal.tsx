import React, { useState } from 'react';
import { Buffer } from 'buffer';
import {
  completeRegistration,
  register,
  encryptDataSaveKey,
  updateStoredPasskey,
  createKeyFromBuffer,
  encrypt,
} from '../../passkeys/types';
import { usePasskeysContext } from '../context/PasskeysContext';
import { sha256 } from 'multiformats/hashes/sha2';
import { base58btc } from 'multiformats/bases/base58';
import * as secureChannel from '../../channel/channel';
import * as ch from '../../channel/channelwasm';
import { useDropzone } from 'react-dropzone';

export const PasskeyModal = ({
  fqAppPrefix,
  getUserRegistration,
  uploadRegistration,
} : {
  fqAppPrefix: string;
  getUserRegistration: (address: string) => Promise<secureChannel.UserRegistration>;
  uploadRegistration: ({ address, registration, }: {
    address: string;
    registration: secureChannel.UserRegistration;
  }) => Promise<void>;
}) => {
  const {
    showPasskeyPrompt,
    setShowPasskeyPrompt,
    passkeyRegistrationComplete,
    setPasskeyRegistrationComplete,
    passkeyRegistrationError,
    setPasskeyRegistrationError,
  } = usePasskeysContext();
  const [keypair, setKeypair] = useState<string | undefined>();
  const [id, setId] = useState<string | undefined>();

  const { getRootProps, getInputProps, acceptedFiles, inputRef } = useDropzone({
    accept: {
      'text/plain': ['.key'],
    },
    minSize: 0,
    maxSize: 1 * 1024 * 1024,
  });

  // @ts-ignore
  if (window.electron) {
    if (!window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`)) {
      window.localStorage.setItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`, 'true');
    }
  }

  return (
    <div
      className={
        'fixed top-0 left-0 backdrop-blur-lg transition ease-in-out duration-600 w-full h-full bg-black/40' +
        (showPasskeyPrompt.value ? '' : ' hidden')
      }
      style={{zIndex: 10000}}
    >
      <div className="fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[calc(100vw-2rem)] max-w-[480px] max-h-[90vh] overflow-y-auto border border-gray-200 bg-white/90 backdrop-blur-md drop-shadow-2xl rounded-2xl text-gray-800 text-center">
        <h2 className="text-center p-4 font-semibold text-lg sm:text-xl text-gray-900">
          {showPasskeyPrompt.importMode
            ? 'Import Existing Key'
            : 'Create Passkey'}
        </h2>
        <div className="flex justify-center mb-4">
          <div
            style={{
              fontSize: '23pt',
              width: '60px',
              height: '60px',
              backgroundImage: passkeyRegistrationComplete !== false && passkeyRegistrationComplete !== true ? 'url("/passkey.png")' : undefined,
              backgroundColor: passkeyRegistrationComplete !== false && passkeyRegistrationComplete !== true ? '#0287F2' : undefined,
              borderColor: passkeyRegistrationComplete !== false && passkeyRegistrationComplete !== true ? '#0266CC' : undefined,
            }}
            className={
              'relative z-100 font-bold transition ease-in-out duration-300 border border-gray-200 rounded-full p-2 flex items-center justify-center' +
              (passkeyRegistrationComplete === true
                ? ' bg-green-500 border-green-300 text-white'
                : passkeyRegistrationComplete === false
                  ? ' bg-red-500 border-red-300 font-normal text-white'
                  : " bg-cover pulsating")
            }
          >
            {passkeyRegistrationComplete === true
              ? '✓'
              : passkeyRegistrationComplete === false
                ? '!'
                : ''}
          </div>
        </div>
        <div className="mb-4 mx-4 text-sm sm:text-base">
          {passkeyRegistrationComplete === false && passkeyRegistrationError ? (
            <>
              <div>
                An error was encountered while attempting to register the
                passkey.
              </div>
              <div
                className="border-gray-200 text-xs border bg-gray-50 p-4 mt-4 rounded-xl text-gray-700"
                style={{
                  fontFamily:
                    'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                }}
              >
                {passkeyRegistrationError}
              </div>
              <div className="mt-4">
                If your browser told you the passkey option cannot be used with
                the site, you may be running an unsupported browser. If the
                browser provides an option to use a phone for passkeys, use
                this. Alternatively, if you would like to proceed without
                passkeys, click Proceed Without Passkeys.
              </div>
            </>
          ) : passkeyRegistrationComplete === true ? (
            'Your passkey has been successfully created.'
          ) : id ? (
            'To save the account, you will need to perform one more passkey interaction. Tap continue to complete.'
          ) : showPasskeyPrompt.importMode ? (
            keypair ? (
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
          !keypair && (
            <div className="mb-4 mx-4">
              <div
                className="border-2 border-dashed border-gray-300 hover:border-blue-400 bg-gray-50/50 hover:bg-blue-50/50 p-2 rounded-md w-full truncate transition-all duration-200 cursor-pointer"
                {...getRootProps()}
              >
                <input {...getInputProps()} style={{ display: 'none' }} />
                <div className="text-center text-sm sm:text-base">
                  {acceptedFiles.length
                    ? acceptedFiles[0].name
                    : 'Drop key file here or click to select'}
                </div>
              </div>
            </div>
          )}
        {showPasskeyPrompt.importMode ? (
          showPasskeyPrompt.importMode &&
          (acceptedFiles.length || passkeyRegistrationComplete) ? (
            <div
              onClick={async () => {
                if (passkeyRegistrationComplete) {
                  setShowPasskeyPrompt({ ...showPasskeyPrompt, value: false });
                } else if (id) {
                  try {
                    let pair = '';
                    if (keypair) {
                      pair = keypair;
                    } else {
                      pair = ch.js_generate_ed448();
                      setKeypair(pair);
                    }
                    const p = JSON.parse(pair);
                    const h = await sha256.digest(Buffer.from(p.public_key) as unknown as Uint8Array<ArrayBufferLike>);
                    const address = base58btc.baseEncode(h.bytes);
                    await completeRegistration(fqAppPrefix, {
                      credentialId: id,
                      largeBlob: Buffer.from(p.private_key).toString('hex'),
                      publicKey: Buffer.from(p.public_key).toString('hex'),
                      address: address,
                    });
                    const senderIdent = secureChannel.NewUserKeyset({
                      type: 'ed448',
                      private_key: [...p.private_key],
                      public_key: [...p.public_key],
                    });
                    const senderDevice = await secureChannel.NewDeviceKeyset();
                    let existing: secureChannel.UserRegistration | undefined;
                    try {
                      existing = (await getUserRegistration(address));
                    } catch {}

                    const senderRegistration =
                      await secureChannel.ConstructUserRegistration(
                        senderIdent,
                        existing?.device_registrations ?? [],
                        [senderDevice]
                      );
                    const key = await createKeyFromBuffer(
                      new Uint8Array(p.private_key) as unknown as ArrayBuffer
                    );
                    const inner = await encrypt(
                      Buffer.from(
                        JSON.stringify({
                          identity: senderIdent,
                          device: senderDevice,
                        }),
                        'utf-8'
                      ),
                      key
                    );
                    const envelope = Buffer.from(
                      JSON.stringify({
                        iv: [...inner.iv],
                        ciphertext: [...new Uint8Array(inner.ciphertext)],
                      }),
                      'utf-8'
                    );
                    await encryptDataSaveKey(2, envelope);
                    uploadRegistration({
                      address: address,
                      registration: senderRegistration,
                    });
                    setPasskeyRegistrationComplete(true);
                    setKeypair(undefined);
                    setId(undefined);
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                  } catch (e: any) {
                    setPasskeyRegistrationComplete(false);
                    setPasskeyRegistrationError(e.toString());
                  }
                } else if (keypair) {
                  try {
                    let pair = keypair;
                    const p = JSON.parse(pair);
                    const h = await sha256.digest(Buffer.from(p.public_key) as unknown as Uint8Array<ArrayBufferLike>);
                    const r = await register(fqAppPrefix, base58btc.baseEncode(h.bytes));
                    setId(r.id);
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                  } catch (e: any) {
                    setPasskeyRegistrationComplete(false);
                    setPasskeyRegistrationError(e.toString());
                  }
                } else {
                  try {
                    const data = await acceptedFiles[0].arrayBuffer();
                    let key: string;
                    if (data.byteLength == 57) {
                      key = Buffer.from(data).toString('hex');
                    } else {
                      key = Buffer.from(data).toString('utf-8');
                    }

                    if (key.length != 114) {
                      if (key.startsWith('{')) {
                        key = Buffer.from(
                          new Uint8Array(JSON.parse(key).private_key)
                        ).toString('hex');
                      }
                    }

                    if (key.length != 114) {
                      throw new Error(
                        'Corrupted key file, try a different file or cancel and create a new account'
                      );
                    }

                    const pubkey = Buffer.from(
                      ch.js_get_pubkey_ed448(
                        Buffer.from(key, 'hex').toString('base64')
                      ),
                      'base64'
                    );

                    setKeypair(
                      JSON.stringify({
                        public_key: [...new Uint8Array(pubkey)],
                        private_key: [
                          ...new Uint8Array(Buffer.from(key, 'hex')),
                        ],
                      })
                    );
                  } catch (e: any) {
                    (acceptedFiles as any[]).shift();
                    setPasskeyRegistrationComplete(false);
                    setPasskeyRegistrationError(e.toString());
                  }
                }
              }}
              style={{ backgroundColor: '#0287F2' }}
              onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#0266CC'}
              onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#0287F2'}
              className="text-white transition ease-in-out duration-300 cursor-pointer rounded-xl px-4 py-2 border-0 mt-2 mb-4 mx-4 font-medium shadow-sm text-sm sm:text-base"
            >
              Continue
            </div>
          ) : (
            <></>
          )
        ) : !window.localStorage.getItem(
            `${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`
          ) ? (
          <div
            onClick={async () => {
              if (passkeyRegistrationComplete) {
                setShowPasskeyPrompt({ ...showPasskeyPrompt, value: false });
              } else if (id) {
                try {
                  let pair = '';
                  if (keypair) {
                    pair = keypair;
                  } else {
                    pair = ch.js_generate_ed448();
                    setKeypair(pair);
                  }
                  const p = JSON.parse(pair);
                  const h = await sha256.digest(Buffer.from(p.public_key) as unknown as Uint8Array<ArrayBufferLike>);
                  const address = base58btc.baseEncode(h.bytes);
                  await completeRegistration(
                    fqAppPrefix,
                    {
                      credentialId: id,
                      largeBlob: Buffer.from(p.private_key).toString('hex'),
                      publicKey: Buffer.from(p.public_key).toString('hex'),
                      address: address,
                    },
                  );
                  const senderIdent = secureChannel.NewUserKeyset({
                    type: 'ed448',
                    private_key: [...p.private_key],
                    public_key: [...p.public_key],
                  });
                  const senderDevice = await secureChannel.NewDeviceKeyset();
                  let existing: secureChannel.UserRegistration | undefined;
                  try {
                    existing = (await getUserRegistration(address));
                  } catch {}

                  const senderRegistration =
                    await secureChannel.ConstructUserRegistration(
                      senderIdent,
                      existing?.device_registrations ?? [],
                      [senderDevice]
                    );
                  const key = await createKeyFromBuffer(
                    new Uint8Array(p.private_key) as unknown as ArrayBuffer
                  );
                  const inner = await encrypt(
                    Buffer.from(
                      JSON.stringify({
                        identity: senderIdent,
                        device: senderDevice,
                      }),
                      'utf-8'
                    ),
                    key
                  );
                  const envelope = Buffer.from(
                    JSON.stringify({
                      iv: [...inner.iv],
                      ciphertext: [...new Uint8Array(inner.ciphertext)],
                    }),
                    'utf-8'
                  );
                  await encryptDataSaveKey(2, envelope);
                  uploadRegistration({
                    address: address,
                    registration: senderRegistration,
                  });
                  setPasskeyRegistrationComplete(true);
                  setKeypair(undefined);
                  setId(undefined);
                  // eslint-disable-next-line @typescript-eslint/no-explicit-any
                } catch (e: any) {
                  setPasskeyRegistrationComplete(false);
                  setPasskeyRegistrationError(e.toString());
                }
              } else {
                try {
                  let pair = '';
                  if (keypair) {
                    pair = keypair;
                  } else {
                    pair = ch.js_generate_ed448();
                    setKeypair(pair);
                  }
                  const p = JSON.parse(pair);
                  const h = await sha256.digest(Buffer.from(p.public_key) as unknown as Uint8Array<ArrayBufferLike>);
                  const r = await register(fqAppPrefix, base58btc.baseEncode(h.bytes));
                  setId(r.id);
                  // eslint-disable-next-line @typescript-eslint/no-explicit-any
                } catch (e: any) {
                  setPasskeyRegistrationComplete(false);
                  setPasskeyRegistrationError(e.toString());
                }
              }
            }}
            style={{ backgroundColor: '#0287F2' }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#0266CC'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#0287F2'}
            className="text-white transition ease-in-out duration-300 cursor-pointer rounded-xl px-4 py-2 border-0 mt-2 mb-4 mx-4 font-medium shadow-sm text-sm sm:text-base"
          >
            Continue
          </div>
        ) : (
          <></>
        )}
        {passkeyRegistrationError &&
          (!showPasskeyPrompt.importMode || keypair) && (
            <div
              onClick={async () => {
                window.localStorage.setItem(
                  `${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`,
                  'true'
                );
                let pair = '';
                if (keypair) {
                  pair = keypair;
                } else {
                  pair = ch.js_generate_ed448();
                  setKeypair(pair);
                }
                const p = JSON.parse(pair);
                const h = await sha256.digest(Buffer.from(p.public_key) as unknown as Uint8Array<ArrayBufferLike>);
                const address = base58btc.baseEncode(h.bytes);
                setId('not-passkey');
                await encryptDataSaveKey(
                  1,
                  Buffer.from(new Uint8Array(p.private_key))
                );

                updateStoredPasskey('not-passkey', {
                  credentialId: 'not-passkey',
                  address: address,
                  publicKey: p.publicKey,
                  completedOnboarding: false,
                });
                const senderIdent = secureChannel.NewUserKeyset({
                  type: 'ed448',
                  private_key: [...p.private_key],
                  public_key: [...p.public_key],
                });
                const senderDevice = await secureChannel.NewDeviceKeyset();
                let existing: secureChannel.UserRegistration | undefined;
                try {
                  existing = (await getUserRegistration(address));
                } catch {}

                const senderRegistration =
                  await secureChannel.ConstructUserRegistration(
                    senderIdent,
                    existing?.device_registrations ?? [],
                    [senderDevice]
                  );
                const key = await createKeyFromBuffer(
                  new Uint8Array(p.private_key) as unknown as ArrayBuffer
                );
                const inner = await encrypt(
                  Buffer.from(
                    JSON.stringify({
                      identity: senderIdent,
                      device: senderDevice,
                    }),
                    'utf-8'
                  ),
                  key
                );
                const envelope = Buffer.from(
                  JSON.stringify({
                    iv: [...inner.iv],
                    ciphertext: [...new Uint8Array(inner.ciphertext)],
                  }),
                  'utf-8'
                );
                await encryptDataSaveKey(2, envelope);
                uploadRegistration({
                  address: address,
                  registration: senderRegistration,
                });
                setPasskeyRegistrationComplete(true);
                setKeypair(undefined);
                setId(undefined);
                setPasskeyRegistrationError(undefined);
              }}
              className="bg-amber-600 hover:bg-amber-700 text-white transition ease-in-out duration-300 cursor-pointer rounded-xl px-4 py-2 border-0 mt-2 mb-4 mx-4 font-medium shadow-sm text-sm sm:text-base"
            >
              {window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`)
                ? 'Continue'
                : 'Proceed Without Passkeys'}
            </div>
          )}
        {window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`) &&
          !showPasskeyPrompt.importMode && (
            <div
              onClick={async () => {
                if (passkeyRegistrationComplete) {
                  setShowPasskeyPrompt({ ...showPasskeyPrompt, value: false });
                  return;
                }
                window.localStorage.setItem(
                  `${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`,
                  'true'
                );
                let pair = '';
                if (keypair) {
                  pair = keypair;
                } else {
                  pair = ch.js_generate_ed448();
                  setKeypair(pair);
                }
                const p = JSON.parse(pair);
                const h = await sha256.digest(Buffer.from(p.public_key) as unknown as Uint8Array<ArrayBufferLike>);
                const address = base58btc.baseEncode(h.bytes);
                setId('not-passkey');
                await encryptDataSaveKey(
                  1,
                  Buffer.from(new Uint8Array(p.private_key))
                );

                updateStoredPasskey('not-passkey', {
                  credentialId: 'not-passkey',
                  address: address,
                  publicKey: p.publicKey,
                  completedOnboarding: false,
                });
                const senderIdent = secureChannel.NewUserKeyset({
                  type: 'ed448',
                  private_key: [...p.private_key],
                  public_key: [...p.public_key],
                });
                const senderDevice = await secureChannel.NewDeviceKeyset();
                let existing: secureChannel.UserRegistration | undefined;
                try {
                  existing = (await getUserRegistration(address));
                } catch {}

                const senderRegistration =
                  await secureChannel.ConstructUserRegistration(
                    senderIdent,
                    existing?.device_registrations ?? [],
                    [senderDevice]
                  );
                const key = await createKeyFromBuffer(
                  new Uint8Array(p.private_key) as unknown as ArrayBuffer
                );
                const inner = await encrypt(
                  Buffer.from(
                    JSON.stringify({
                      identity: senderIdent,
                      device: senderDevice,
                    }),
                    'utf-8'
                  ),
                  key
                );
                const envelope = Buffer.from(
                  JSON.stringify({
                    iv: [...inner.iv],
                    ciphertext: [...new Uint8Array(inner.ciphertext)],
                  }),
                  'utf-8'
                );
                await encryptDataSaveKey(2, envelope);
                uploadRegistration({
                  address: address,
                  registration: senderRegistration,
                });
                setPasskeyRegistrationComplete(true);
                setKeypair(undefined);
                setId(undefined);
                setPasskeyRegistrationError(undefined);
              }}
              style={{ backgroundColor: '#0287F2' }}
              onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#0266CC'}
              onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#0287F2'}
              className="text-white transition ease-in-out duration-300 cursor-pointer rounded-xl px-4 py-2 border-0 mt-2 mb-4 mx-4 font-medium shadow-sm text-sm sm:text-base"
            >
              Continue
            </div>
          )}
        {!passkeyRegistrationComplete && (
          <div
            onClick={async () => {
              setPasskeyRegistrationError(undefined);
              setPasskeyRegistrationComplete(undefined);
              setKeypair(undefined);
              setShowPasskeyPrompt({ ...showPasskeyPrompt, value: false });
            }}
            className="bg-gray-400 hover:bg-gray-500 text-white transition ease-in-out duration-300 cursor-pointer rounded-xl px-4 py-2 border-0 mt-2 mb-4 mx-4 font-medium shadow-sm text-sm sm:text-base"
          >
            Cancel
          </div>
        )}
      </div>
    </div>
  );
};
