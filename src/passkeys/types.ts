export const getStoredPasskeys = async () => {
  const passkeysList = window.localStorage.getItem('passkeys-list');
  let passkeys: StoredPasskey[] = [];
  if (passkeysList) {
    passkeys = JSON.parse(passkeysList);
  }

  return passkeys;
};

function makeKeys() {
  return window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encrypt(data: any, keys: any) {
  let iv = window.crypto.getRandomValues(new Uint8Array(12));
  let ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    keys,
    data
  );
  return { iv, ciphertext };
}

export async function decrypt(data: any, iv: any, keys: any) {
  return new Uint8Array(
    await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      keys,
      data
    )
  );
}

export async function createKeyFromBuffer(
  buffer: ArrayBuffer
): Promise<CryptoKey> {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);

  return window.crypto.subtle.importKey(
    'raw',
    hashBuffer,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptDataSaveKey(id: number, data: Buffer) {
  var keys = await makeKeys();
  var encrypted = await encrypt(data, keys);
  callOnStore((store: IDBObjectStore) => {
    store.put({ id: id, keys: keys, encrypted: encrypted });
  });
}

export function loadKeyDecryptData(id: number): Promise<Uint8Array<ArrayBuffer>> {
  return new Promise((resolve, reject) => {
    callOnStore((store) => {
      var getData = store.get(id);
      getData.onsuccess = async function () {
        if (getData.result) {
          var keys = getData.result.keys;
          var encrypted = getData.result.encrypted;
          var data = await decrypt(encrypted.ciphertext, encrypted.iv, keys);
          resolve(data);
        } else {
          reject('no data');
        }
      };
      getData.onerror = async function (e) {
        reject(e);
      };
    });
  });
}

function callOnStore(fn_: (store: IDBObjectStore) => void) {
  let indexedDB =
    window.indexedDB ||
    // @ts-ignore
    window.mozIndexedDB ||
    // @ts-ignore
    window.webkitIndexedDB ||
    // @ts-ignore
    window.msIndexedDB ||
    // @ts-ignore
    window.shimIndexedDB;

  let open = indexedDB.open('KeyDB', 1);

  open.onupgradeneeded = function () {
    let db = open.result;
    db.createObjectStore('KeyObjectStore', { keyPath: 'id' });
  };

  open.onsuccess = function () {
    let db = open.result;
    let tx = db.transaction('KeyObjectStore', 'readwrite');
    let store = tx.objectStore('KeyObjectStore');

    fn_(store);

    tx.oncomplete = function () {
      db.close();
    };
  };
}

export const updateStoredPasskey = async (
  credentialId: string,
  storedPasskey: StoredPasskey
) => {
  const passkeysList = window.localStorage.getItem('passkeys-list');
  let passkeys: StoredPasskey[] = [];
  if (passkeysList) {
    passkeys = JSON.parse(passkeysList);
  }

  if (passkeys.filter((p) => p.credentialId === credentialId)) {
    passkeys = passkeys.filter((p) => p.credentialId !== credentialId);
  }

  passkeys.push(storedPasskey);

  window.localStorage.setItem('passkeys-list', JSON.stringify(passkeys));

  return true;
};

export const register = async (fqAppPrefix: string, account: string) => {
  const challenge = new Uint8Array(32);
  window.crypto.getRandomValues(challenge);
  const authtype = await isPasskeysSupported();
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: challenge,
      rp: {
        name: 'Quilibrium',
        // id: account,
      },
      user: {
        id: Buffer.from(account),
        name: account,
        displayName: account,
      },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required',
      },
      extensions:
        authtype == 'PRF'
          ? {
              prf: {
                eval: {
                  first: new Uint8Array(
                    Buffer.from(fqAppPrefix + 'PRFDomain|||||||||||||||||', 'utf-8')
                  ),
                },
              },
            }
          : {
              // @ts-expect-error
              largeBlob: {
                support: 'required',
              },
            },
    },
  });
  if (!credential) {
    throw new Error('could not register passkey');
  }

  if (
    (authtype == 'PRF' &&
      // @ts-ignore
      !credential.getClientExtensionResults().prf.enabled) ||
      // @ts-ignore
      !credential.getClientExtensionResults().largeBlob
  ) {
    window.localStorage.setItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`, 'true');
  }

  return {
    // @ts-expect-error passkeys
    id: Buffer.from(credential.rawId).toString('base64'),
    // @ts-expect-error passkeys
    rawId: Buffer.from(credential.rawId).toString('base64'),
  };
};

export const completeRegistration = async (
  fqAppPrefix: string,
  request: PasskeyAuthenticationRequestLargeBlob
) => {
  const challenge = new Uint8Array(32);
  window.crypto.getRandomValues(challenge);
  const authtype = await isPasskeysSupported();

  if (window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`)) {
    await encryptDataSaveKey(1, Buffer.from(request.largeBlob, 'utf-8'));
    updateStoredPasskey(request.credentialId, {
      credentialId: request.credentialId,
      address: request.address,
      publicKey: request.publicKey,
      completedOnboarding: false,
    });
    return {
      id: request.credentialId,
      rawId: request.credentialId,
      response: {
        authenticatorData: '',
        clientDataJSON: '',
        signature: '',
        userHandle: '',
      },
    };
  }

  const write = await navigator.credentials.get({
    publicKey: {
      challenge: challenge,
      allowCredentials: [
        {
          id: Buffer.from(request.credentialId, 'base64'),
          type: 'public-key',
        },
      ],
      extensions:
        authtype == 'PRF'
          ? {
              prf: {
                eval: {
                  first: new Uint8Array(
                    Buffer.from(`${fqAppPrefix}PRFDomain|||||||||||||||||`, 'utf-8')
                  ),
                },
              },
            }
          : {
              // @ts-expect-error passkeys
              largeBlob: {
                write: Buffer.from(request.largeBlob, 'utf-8'),
              },
            },
    },
  });

  if (authtype == 'LargeBlob') {
    // @ts-expect-error passkeys
    if (write?.getClientExtensionResults().largeBlob.written) {
      updateStoredPasskey(request.credentialId, {
        credentialId: request.credentialId,
        address: request.address,
        publicKey: request.publicKey,
        completedOnboarding: false,
      });
      return {
        id: request.credentialId,
        rawId: request.credentialId,
        response: {
          authenticatorData: '',
          clientDataJSON: '',
          signature: '',
          userHandle: '',
        },
      };
    } else {
      throw new Error('could not add key to credential');
    }
  } else {
    if (
      // @ts-expect-error passkeys
      typeof credential.getClientExtensionResults().prf === 'undefined'
    ) {
      throw new Error('invalid authenticator');
    }
    const key = Buffer.from(
      // @ts-expect-error passkeys
      credential.getClientExtensionResults().prf.results.first
    );

    const subtleKey = await window.crypto.subtle.importKey(
      'raw',
      key,
      {
        name: 'AES-GCM',
        length: 256,
      },
      false,
      ['encrypt']
    );
    let iv = window.crypto.getRandomValues(new Uint8Array(12));

    const largeBlob = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      subtleKey,
      Buffer.from(request.largeBlob, 'utf-8')
    );
    window.localStorage.setItem(
      `${fqAppPrefix.toLowerCase()}-master`,
      JSON.stringify({
        iv: Buffer.from(iv).toString('hex'),
        ciphertext: Buffer.from(largeBlob).toString('hex'),
      })
    );
    return {
      id: request.credentialId,
      rawId: request.credentialId,
      response: {
        authenticatorData: '',
        clientDataJSON: '',
        signature: '',
        userHandle: '',
      },
    };
  }
};

export const authenticate = async (fqAppPrefix: string, request: PasskeyAuthenticationRequest) => {
  const passkeysList = window.localStorage.getItem('passkeys-list');
  let passkeys: StoredPasskey[] = [];
  if (passkeysList) {
    passkeys = JSON.parse(passkeysList);
  }

  const passkey = passkeys.filter((p) => p.address === request.credentialId)[0];
  if (window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master-prf-incompatibility`)) {
    const data = await loadKeyDecryptData(1);
    let key: string;
    if (data.byteLength == 57) {
      key = Buffer.from(data).toString('hex');
    } else {
      key = Buffer.from(data).toString('utf-8');
    }

    if (key.startsWith('{')) {
      key = Buffer.from(new Uint8Array(JSON.parse(key).private_key)).toString(
        'hex'
      );
    }

    return {
      id: request.credentialId,
      rawId: request.credentialId,
      response: {
        authenticatorData: '',
        clientDataJSON: '',
        signature: '',
        userHandle: '',
      },
      largeBlob: key,
    };
  }

  const challenge = new Uint8Array(32);
  window.crypto.getRandomValues(challenge);
  const authtype = await isPasskeysSupported();

  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: challenge,
      allowCredentials: [
        {
          id: Buffer.from(passkey.credentialId, 'base64'),
          type: 'public-key',
        },
      ],
      extensions:
        authtype === 'PRF'
          ? {
              prf: {
                eval: {
                  first: new Uint8Array(
                    Buffer.from(`${fqAppPrefix}PRFDomain|||||||||||||||||`, 'utf-8')
                  ),
                },
              },
            }
          : {
              // @ts-expect-error passkeys
              largeBlob: {
                read: true,
              },
            },
    },
  });

  if (credential) {
    if (authtype == 'LargeBlob') {
      if (
        // @ts-expect-error passkeys
        typeof credential.getClientExtensionResults().largeBlob === 'undefined'
      ) {
        throw new Error('invalid authenticator');
      }
      const key = Buffer.from(
        // @ts-expect-error passkeys
        credential.getClientExtensionResults().largeBlob.blob
      ).toString('utf-8');
      return {
        id: request.credentialId,
        rawId: request.credentialId,
        response: {
          authenticatorData: '',
          clientDataJSON: '',
          signature: '',
          userHandle: '',
        },
        largeBlob: key,
      };
    } else {
      if (
        // @ts-expect-error passkeys
        typeof credential.getClientExtensionResults().prf === 'undefined'
      ) {
        throw new Error('invalid authenticator');
      }
      const key = Buffer.from(
        // @ts-expect-error passkeys
        credential.getClientExtensionResults().prf.results.first
      );
      const blob = window.localStorage.getItem(`${fqAppPrefix.toLowerCase()}-master`);

      if (!blob) {
        throw new Error('corrupted local store, cannot restore session');
      }

      const ciphertext = JSON.parse(blob);
      const subtleKey = await window.crypto.subtle.importKey(
        'raw',
        key,
        {
          name: 'AES-GCM',
          length: 256,
        },
        false,
        ['decrypt']
      );

      const largeBlob = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: Buffer.from(ciphertext.iv, 'hex') },
        subtleKey,
        Buffer.from(ciphertext.ciphertext, 'hex')
      );

      return {
        id: request.credentialId,
        rawId: request.credentialId,
        response: {
          authenticatorData: '',
          clientDataJSON: '',
          signature: '',
          userHandle: '',
        },
        largeBlob: Buffer.from(largeBlob).toString('utf-8'),
      };
    }
  } else {
    throw new Error('could not authenticate');
  }
};

export const isPasskeysSupported = async () => {
  const matches =
    navigator.userAgent.match(
      /(opera|chrome|safari|firefox|msie|trident(?=\/))\/?\s*(\d+)/i
    ) || [];
  if (/trident/i.test(matches[1])) {
    return null;
  }

  if (matches[1] === 'Chrome') {
    if (navigator.userAgent.match(/\b(OPR)\/(\d+)/) !== null) {
      return null;
    }
    return parseInt(matches[2], 10) >= 131 ? 'PRF' : null;
  }

  if (
    matches[1] === 'Safari' &&
    navigator.userAgent.match(/version\/(\d+)/i) !== null
  ) {
    const versionMatch = navigator.userAgent.match(/version\/(\d+)/i);
    return versionMatch !== null && parseInt(versionMatch[1], 10) >= 17
      ? 'LargeBlob'
      : null;
  }

  return null;
};

export interface PasskeyRegistrationResult {
  id: string;
}

export interface PasskeyAuthenticationRequestLargeBlob {
  credentialId: string;
  address: string;
  publicKey: string;
  largeBlob: string;
  displayName?: string;
}

export interface PasskeyAuthenticationRequest {
  credentialId: string;
}

export interface PasskeyAuthenticationResult {
  id: string;
  rawId: string;
  type?: string;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle: string;
  };
  largeBlob?: string;
}

export interface StoredPasskey {
  credentialId: string;
  address: string;
  publicKey: string;
  displayName?: string;
  pfpUrl?: string;
  completedOnboarding: boolean;
}
