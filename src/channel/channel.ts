import { sha256 } from 'multiformats/hashes/sha2';
import * as ch from './channelwasm';
import { base58btc } from 'multiformats/bases/base58';
import { base58_to_binary } from 'base58-js';

export type NewDoubleRatchetParameters = {
  session_key: number[]; // u8
  sending_header_key: number[]; // u8
  next_receiving_header_key: number[]; // u8
  is_sender: boolean;
  sending_ephemeral_private_key: number[]; // u8
  receiving_ephemeral_key?: number[]; // u8
};

export type NewTripleRatchetParameters = {
  peers: number[][]; // u8
  peer_key: number[]; // u8
  identity_key: number[]; // u8
  signed_pre_key: number[]; // u8
  threshold: number; // u64
  async_dkg_ratchet: boolean;
};

export type EncryptionKeyPair = {
  public_key: number[]; // u8
  private_key: number[]; // u8
};

export type SigningKeyPair = {
  public_key: number[]; // u8
  private_key: number[]; // u8
};

export type SenderX3DH = {
  sending_identity_private_key: number[]; // u8
  sending_ephemeral_private_key: number[]; // u8
  receiving_identity_key: number[]; // u8
  receiving_signed_pre_key: number[]; // u8
  session_key_length: number; // usize
};

export type ReceiverX3DH = {
  sending_identity_private_key: number[]; // u8
  sending_signed_private_key: number[]; // u8
  receiving_identity_key: number[]; // u8
  receiving_ephemeral_key: number[]; // u8
  session_key_length: number; // usize
};

export type DoubleRatchetStateAndEnvelope = {
  ratchet_state: string;
  envelope: string;
};

export type DoubleRatchetStateAndMessage = {
  ratchet_state: string;
  message: number[]; // u8
};

export type TripleRatchetStateAndMetadata = {
  ratchet_state: string;
  metadata: { [key: string]: string };
};

export type TripleRatchetStateAndEnvelope = {
  ratchet_state: string;
  envelope: string;
};

export type TripleRatchetStateAndMessage = {
  ratchet_state: string;
  message: number[]; // u8
};

export type DoubleRatchetParticipant = {
  sending_ephemeral_private_key: string;
  receiving_ephemeral_key: string;
  root_key: string;
  sending_chain_key: string;
  current_sending_header_key: string;
  current_receiving_header_key: string;
  next_sending_header_key: string;
  next_receiving_header_key: string;
  receiving_chain_key: string;
  current_sending_chain_length: number; // u32
  previous_sending_chain_length: number; // u32
  current_receiving_chain_length: number; // u32
  previous_receiving_chain_length: number; // u32
  skipped_keys_map: { [key: string]: { [key: number]: string } };
};

export type MessageCiphertext = {
  ciphertext: string;
  initialization_vector: string;
  associated_data?: string;
};

export type SealedInboxMessageDecryptRequest = {
  inbox_private_key: number[]; // u8
  ephemeral_public_key: number[]; // u8
  ciphertext: MessageCiphertext;
};

export type SealedInboxMessageEncryptRequest = {
  inbox_public_key: number[]; // u8
  ephemeral_private_key: number[]; // u8
  plaintext: number[]; // u8
};

export type Ed448Keypair = {
  type: 'ed448';
  public_key: number[]; // u8
  private_key: number[]; // u8
};

export type X448Keypair = {
  type: 'x448';
  public_key: number[]; // u8
  private_key: number[]; // u8
};

export type Keypair = X448Keypair | Ed448Keypair;

export type UserKeyset = {
  user_key: Ed448Keypair;
  peer_key: X448Keypair;
};

export type DeviceKeyset = {
  identity_key: X448Keypair;
  pre_key: X448Keypair;
  inbox_keyset: InboxKeyset;
};

export type InboxKeyset = {
  inbox_address: string;
  inbox_key: Ed448Keypair;
  inbox_encryption_key: X448Keypair;
};

export type InboxRegistration = {
  inbox_address: string;
  inbox_encryption_public_key: string;
};

export type DeviceRegistration = {
  identity_public_key: string;
  pre_public_key: string;
  inbox_registration: InboxRegistration;
};

export type UserRegistration = {
  user_address: string;
  user_public_key: string;
  peer_public_key: string;
  device_registrations: DeviceRegistration[];
  signature: string;
};

export type SpaceRegistration = {
  space_address: string;
  space_public_key: string;
  owner_public_keys: string[];
  config_public_key: string;
  timestamp: number;
  space_signature: string;
  owner_signatures: string[];
};

export type SpaceManifest = {
  space_address: string;
  space_manifest: string;
  timestamp: number;
  ephemeral_public_key: string;
  owner_public_key: string;
  owner_signature: string;
};

export type SealedMessageWithNetworkTimestamp = {
  inbox_address: string;
  ephemeral_public_key: string;
  envelope: string;
  inbox_public_key: string;
  inbox_signature: string;
  timestamp: number;
};

export type OwnerSealedMessage = {
  inbox_address: string;
  hub_address: string;
  ephemeral_public_key: string;
  envelope: string;
  owner_public_key: string;
  owner_signature: string;
};

export type HubSealedMessage = {
  hub_address: string;
  ephemeral_public_key: string;
  envelope: string;
  hub_public_key: string;
  hub_signature: string;
};

export type HubControlMessage = {
  hub_address: string;
  inbox_public_key: string;
  hub_public_key: string;
  hub_signature: string;
  inbox_signature: string;
};

export type UserConfig = {
  user_address: string;
  user_public_key: string;
  user_config: string;
  timestamp: number;
  signature: string;
};

export type UserAttestation = {
  user_address: string;
  attestation: string;
  attestation_valid_until: number;
  attestation_public_key: string;
  attestation_signature: string;
};

export type SealedMessage = {
  inbox_address: string;
  ephemeral_public_key: string;
  envelope: string;
  inbox_public_key?: string;
  inbox_signature?: string;
};

export type DeleteMessages = {
  inbox_address: string;
  timestamps: number[];
  inbox_public_key: string;
  inbox_signature: string;
};

export type SealedMessageAndMetadata = {
  sealed_message: SealedMessage;
  ratchet_state: string;
  receiving_inbox: InboxKeyset;
  sending_inbox: SendingInbox;
  tag: string;
  sent_accept?: boolean;
};

export type SendingInbox = {
  inbox_address: string;
  inbox_encryption_key: string;
  inbox_public_key: string;
  inbox_private_key: string;
};

export type SignedInboxEnvelopeAndMetadata = {
  inbox_address: string;
  inbox_public_key: string;
  inbox_signature: string;
  envelope: string;
  ratchet_state: string;
};

export type UserProfile = {
  user_address: string;
  display_name?: string;
  user_icon?: string;
};

export type InitializationEnvelope = UserProfile & {
  return_inbox_address: string;
  return_inbox_encryption_key: string;
  return_inbox_public_key: string;
  return_inbox_private_key: string;
  identity_public_key: string;
  tag: string;
  message: string;
  type: string;
};

export type UnsealedEnvelope = InitializationEnvelope & {
  ephemeral_public_key: string;
};

export type NewDoubleRatchetRecipientSession = {
  state: string;
  message: string;
  tag: string;
  return_inbox_address: string;
  return_inbox_encryption_key: string;
  return_inbox_public_key: string;
  return_inbox_private_key: string;
  user_address: string;
  identity_public_key: string;
};

export type InboxAndEncryptionState = {
  inbox_address: string;
  encryption_state: string;
};

export const NewUserKeyset = (user_key: Ed448Keypair) => {
  const peer_key = JSON.parse(ch.js_generate_x448()) as X448Keypair;
  return {
    user_key,
    peer_key,
  } as UserKeyset;
};

export const NewDeviceKeyset = async () => {
  const identity_key = JSON.parse(ch.js_generate_x448()) as X448Keypair;
  const pre_key = JSON.parse(ch.js_generate_x448()) as X448Keypair;
  const inbox_keyset = await NewInboxKeyset();
  return {
    identity_key,
    pre_key,
    inbox_keyset,
  } as DeviceKeyset;
};

export const NewInboxKeyset = async () => {
  const new_inbox_key = JSON.parse(ch.js_generate_ed448()) as Ed448Keypair;
  const new_inbox_encryption_key = JSON.parse(
    ch.js_generate_x448()
  ) as X448Keypair;
  const inbox_digest = await sha256.digest(
    Buffer.from(new_inbox_key.public_key) as unknown as Uint8Array<ArrayBufferLike>
  );
  const inbox_address = base58btc.baseEncode(inbox_digest.bytes);
  return {
    inbox_address,
    inbox_key: new_inbox_key,
    inbox_encryption_key: new_inbox_encryption_key,
  } as InboxKeyset;
};

export const ConstructUserRegistration = async (
  userKeyset: UserKeyset,
  existing_device_keysets: DeviceRegistration[],
  device_keysets: DeviceKeyset[]
) => {
  const user_digest = await sha256.digest(
    Buffer.from(userKeyset.user_key.public_key) as unknown as Uint8Array<ArrayBufferLike>
  );
  const user_address = base58btc.baseEncode(user_digest.bytes);

  return {
    user_address: user_address,
    user_public_key: Buffer.from(
      new Uint8Array(userKeyset.user_key.public_key)
    ).toString('hex'),
    peer_public_key: Buffer.from(
      new Uint8Array(userKeyset.peer_key.public_key)
    ).toString('hex'),
    device_registrations: [
      ...existing_device_keysets,
      ...device_keysets.map((d) => {
        return {
          identity_public_key: Buffer.from(
            new Uint8Array(d.identity_key.public_key)
          ).toString('hex'),
          pre_public_key: Buffer.from(
            new Uint8Array(d.pre_key.public_key)
          ).toString('hex'),
          inbox_registration: {
            inbox_address: d.inbox_keyset.inbox_address,
            inbox_encryption_public_key: Buffer.from(
              new Uint8Array(d.inbox_keyset.inbox_encryption_key.public_key)
            ).toString('hex'),
          },
        } as DeviceRegistration;
      }),
    ],
    signature: Buffer.from(
      JSON.parse(
        ch.js_sign_ed448(
          Buffer.from(new Uint8Array(userKeyset.user_key.private_key)).toString(
            'base64'
          ),
          Buffer.from(
            new Uint8Array([
              ...userKeyset.peer_key.public_key,
              ...existing_device_keysets.flatMap((d) => [
                ...new Uint8Array(Buffer.from(d.identity_public_key, 'hex')),
                ...new Uint8Array(Buffer.from(d.pre_public_key, 'hex')),
                ...base58_to_binary(d.inbox_registration.inbox_address),
                ...new Uint8Array(
                  Buffer.from(
                    d.inbox_registration.inbox_encryption_public_key,
                    'hex'
                  )
                ),
              ]),
              ...device_keysets.flatMap((d) =>
                d.identity_key.public_key
                  .concat(d.pre_key.public_key)
                  .concat([...base58_to_binary(d.inbox_keyset.inbox_address)])
                  .concat(d.inbox_keyset.inbox_encryption_key.public_key)
              ),
            ])
          ).toString('base64')
        )
      ) as string,
      'base64'
    ).toString('hex'),
  } as UserRegistration;
};

export const NewDoubleRatchetSenderSession = async (
  keyset: DeviceKeyset,
  sender_address: string,
  device: DeviceRegistration,
  initial_message: string,
  sender_name?: string,
  sender_photo?: string
) => {
  let outbound: SealedMessageAndMetadata[] = [];

  if (
    device.identity_public_key ===
    Buffer.from(keyset.identity_key.public_key).toString('hex')
  ) {
    return [];
  }

  const ephemeral_key = JSON.parse(ch.js_generate_x448()) as X448Keypair;
  let inbox_key: InboxKeyset;
  let double_ratchet_session: string;
  const receiving_identity_key = [
    ...new Uint8Array(Buffer.from(device.identity_public_key, 'hex')),
  ];
  const receiving_pre_key = [
    ...new Uint8Array(Buffer.from(device.pre_public_key, 'hex')),
  ];

  inbox_key = await NewInboxKeyset();
  const sender_session_key = JSON.parse(
    ch.js_sender_x3dh(
      JSON.stringify({
        sending_identity_private_key: keyset.identity_key.private_key,
        sending_ephemeral_private_key: ephemeral_key.private_key,
        receiving_identity_key: receiving_identity_key,
        receiving_signed_pre_key: receiving_pre_key,
        session_key_length: 96,
      } as SenderX3DH)
    )
  );

  const root_key = [
    ...new Uint8Array(Buffer.from(sender_session_key, 'base64')),
  ];
  double_ratchet_session = ch.js_new_double_ratchet(
    JSON.stringify({
      session_key: root_key.slice(0, 32),
      sending_header_key: root_key.slice(32, 64),
      next_receiving_header_key: root_key.slice(64, 96),
      is_sender: true,
      sending_ephemeral_private_key: ephemeral_key.private_key,
      receiving_ephemeral_key: receiving_pre_key,
    } as NewDoubleRatchetParameters)
  );

  // force early failure on error
  JSON.parse(double_ratchet_session);

  const double_ratchet_envelope = JSON.parse(
    ch.js_double_ratchet_encrypt(
      JSON.stringify({
        ratchet_state: double_ratchet_session,
        message: [
          ...new Uint8Array(Buffer.from(initial_message as string, 'utf-8')),
        ],
      } as DoubleRatchetStateAndMessage)
    )
  ) as DoubleRatchetStateAndEnvelope;
  const ciphertext = ch.js_encrypt_inbox_message(
    JSON.stringify({
      inbox_public_key: [
        ...new Uint8Array(
          Buffer.from(
            device.inbox_registration.inbox_encryption_public_key,
            'hex'
          )
        ),
      ],
      ephemeral_private_key: ephemeral_key.private_key,
      plaintext: [
        ...new Uint8Array(
          Buffer.from(
            JSON.stringify({
              return_inbox_address: inbox_key.inbox_address,
              return_inbox_encryption_key: Buffer.from(
                new Uint8Array(inbox_key.inbox_encryption_key.public_key)
              ).toString('hex'),
              return_inbox_public_key: Buffer.from(
                new Uint8Array(inbox_key.inbox_key.public_key)
              ).toString('hex'),
              return_inbox_private_key: Buffer.from(
                new Uint8Array(inbox_key.inbox_key.private_key)
              ).toString('hex'),
              user_address: sender_address,
              identity_public_key: Buffer.from(
                new Uint8Array(keyset.identity_key.public_key)
              ).toString('hex'),
              tag: keyset.inbox_keyset.inbox_address,
              display_name: sender_name,
              user_icon: sender_photo,
              message: double_ratchet_envelope.envelope,
              type: 'direct',
            } as InitializationEnvelope),
            'utf-8'
          )
        ),
      ],
    } as SealedInboxMessageEncryptRequest)
  );
  outbound.push({
    sealed_message: {
      inbox_address: device.inbox_registration.inbox_address,
      ephemeral_public_key: Buffer.from(
        new Uint8Array(ephemeral_key.public_key)
      ).toString('hex'),
      envelope: ciphertext,
    },
    ratchet_state: double_ratchet_envelope.ratchet_state,
    receiving_inbox: inbox_key,
    sending_inbox: {
      inbox_address: device.inbox_registration.inbox_address,
      inbox_encryption_key:
        device.inbox_registration.inbox_encryption_public_key,
      inbox_private_key: '',
      inbox_public_key: '',
    },
    tag: device.inbox_registration.inbox_address,
    sent_accept: true,
  } as SealedMessageAndMetadata);

  return outbound;
};

export const SealSyncEnvelope = async (
  inbox_address: string,
  hub_address: string,
  hub_keyset: Ed448Keypair,
  owner_keyset: Ed448Keypair,
  message: string,
  configKey?: X448Keypair
) => {
  // Use config key for encryption if provided, otherwise fall back to hub-derived key (legacy)
  let encryptionPubKey: Uint8Array;
  if (configKey) {
    encryptionPubKey = new Uint8Array(configKey.public_key);
    console.log('[SealSyncEnvelope] Using config key, pubKey length:', encryptionPubKey.length);
  } else {
    // Legacy: derive from hub key
    console.log('[SealSyncEnvelope] WARNING: No config key provided, using hub-derived key (legacy)');
    const derived = await window.crypto.subtle.digest(
      'SHA-512',
      Buffer.from(new Uint8Array(hub_keyset.private_key))
    );
    encryptionPubKey = new Uint8Array(
      Buffer.from(
        JSON.parse(
          ch.js_get_pubkey_x448(
            Buffer.from(derived.slice(0, 56)).toString('base64')
          )
        ),
        'base64'
      )
    );
  }
  const ephemeral_key = JSON.parse(ch.js_generate_x448()) as X448Keypair;
  const input = ch.js_encrypt_inbox_message(
    JSON.stringify({
      inbox_public_key: [...encryptionPubKey],
      ephemeral_private_key: ephemeral_key.private_key,
      plaintext: [...new Uint8Array(Buffer.from(message, 'utf-8'))],
    } as SealedInboxMessageEncryptRequest)
  );
  const signature = Buffer.from(
    JSON.parse(
      ch.js_sign_ed448(
        Buffer.from(new Uint8Array(owner_keyset.private_key)).toString(
          'base64'
        ),
        Buffer.from(input, 'utf-8').toString('base64')
      )
    ),
    'base64'
  ).toString('hex');
  return {
    inbox_address: inbox_address,
    hub_address: hub_address,
    owner_public_key: Buffer.from(
      new Uint8Array(owner_keyset.public_key)
    ).toString('hex'),
    ephemeral_public_key: Buffer.from(
      new Uint8Array(ephemeral_key.public_key)
    ).toString('hex'),
    envelope: input,
    owner_signature: signature,
  } as OwnerSealedMessage;
};

export const UnsealSyncEnvelope = async (
  hub_keyset: Ed448Keypair,
  envelope: OwnerSealedMessage,
  configKey?: X448Keypair
) => {
  // Use config key for decryption if provided, otherwise fall back to hub-derived key (legacy)
  let decryptionPrivKey: Uint8Array;
  if (configKey) {
    decryptionPrivKey = new Uint8Array(configKey.private_key);
    console.log('[UnsealSyncEnvelope] Using config key, privKey length:', decryptionPrivKey.length);
  } else {
    // Legacy: derive from hub key
    console.log('[UnsealSyncEnvelope] WARNING: No config key provided, using hub-derived key (legacy)');
    const derived = await window.crypto.subtle.digest(
      'SHA-512',
      Buffer.from(new Uint8Array(hub_keyset.private_key))
    );
    decryptionPrivKey = new Uint8Array(Buffer.from(derived.slice(0, 56)));
  }
  const plaintext = JSON.parse(
    ch.js_decrypt_inbox_message(
      JSON.stringify({
        inbox_private_key: [...decryptionPrivKey],
        ephemeral_public_key: [
          ...new Uint8Array(Buffer.from(envelope.ephemeral_public_key, 'hex')),
        ],
        ciphertext: JSON.parse(envelope.envelope),
      } as SealedInboxMessageDecryptRequest)
    )
  );
  return plaintext;
};

export const UnsealInboxEnvelope = async (
  privKey: number[],
  envelope: {
    inbox_public_key: string;
    ephemeral_public_key: string;
    envelope: string;
  }
) => {
  const plaintext = JSON.parse(
    ch.js_decrypt_inbox_message(
      JSON.stringify({
        inbox_private_key: [...new Uint8Array(privKey)],
        ephemeral_public_key: [
          ...new Uint8Array(Buffer.from(envelope.ephemeral_public_key, 'hex')),
        ],
        ciphertext: JSON.parse(envelope.envelope),
      })
    )
  );
  return plaintext;
};

export const SealInboxEnvelope = async (pubKey: string, message: string) => {
  const ephemeral_key = JSON.parse(ch.js_generate_x448()) as X448Keypair;
  const input = ch.js_encrypt_inbox_message(
    JSON.stringify({
      inbox_public_key: [...new Uint8Array(Buffer.from(pubKey, 'base64'))],
      ephemeral_private_key: ephemeral_key.private_key,
      plaintext: [...new Uint8Array(Buffer.from(message, 'utf-8'))],
    } as SealedInboxMessageEncryptRequest)
  );
  return {
    inbox_public_key: Buffer.from(pubKey, 'base64').toString('hex'),
    ephemeral_public_key: Buffer.from(
      new Uint8Array(ephemeral_key.public_key)
    ).toString('hex'),
    envelope: input,
  };
};

export const SealHubEnvelope = async (
  address: string,
  keyset: Ed448Keypair,
  message: string,
  configKey?: X448Keypair
) => {
  // Use config key for encryption if provided, otherwise fall back to derived key for backwards compatibility
  let encryptionPubKey: Uint8Array;
  if (configKey) {
    encryptionPubKey = new Uint8Array(configKey.public_key);
    const privKeyBytes = new Uint8Array(configKey.private_key);
    console.log('[SealHubEnvelope] Using config key, pubKey length:', encryptionPubKey.length, 'first 8 bytes:', Array.from(encryptionPubKey.slice(0, 8)), 'privKey first 8:', Array.from(privKeyBytes.slice(0, 8)));
    console.log('[SealHubEnvelope] config pubKey hex prefix:', Buffer.from(encryptionPubKey.slice(0, 16)).toString('hex'));
  } else {
    // Legacy: derive X448 key from Ed448 hub key (deprecated)
    const derived = await window.crypto.subtle.digest(
      'SHA-512',
      Buffer.from(new Uint8Array(keyset.private_key))
    );
    encryptionPubKey = new Uint8Array(
      Buffer.from(
        JSON.parse(
          ch.js_get_pubkey_x448(
            Buffer.from(derived.slice(0, 56)).toString('base64')
          )
        ),
        'base64'
      )
    );
  }
  const ephemeral_key = JSON.parse(ch.js_generate_x448()) as X448Keypair;
  console.log('[SealHubEnvelope] ephemeral pubKey hex:', Buffer.from(new Uint8Array(ephemeral_key.public_key)).toString('hex').substring(0, 32));
  const input = ch.js_encrypt_inbox_message(
    JSON.stringify({
      inbox_public_key: [...encryptionPubKey],
      ephemeral_private_key: ephemeral_key.private_key,
      plaintext: [...new Uint8Array(Buffer.from(message, 'utf-8'))],
    } as SealedInboxMessageEncryptRequest)
  );
  console.log('[SealHubEnvelope] encrypt result:', input?.substring(0, 50) + '...');
  const signature = Buffer.from(
    JSON.parse(
      ch.js_sign_ed448(
        Buffer.from(new Uint8Array(keyset.private_key)).toString('base64'),
        Buffer.from(input, 'utf-8').toString('base64')
      )
    ),
    'base64'
  ).toString('hex');
  return {
    hub_address: address,
    hub_public_key: Buffer.from(new Uint8Array(keyset.public_key)).toString(
      'hex'
    ),
    ephemeral_public_key: Buffer.from(
      new Uint8Array(ephemeral_key.public_key)
    ).toString('hex'),
    envelope: input,
    hub_signature: signature,
  } as HubSealedMessage;
};

export const UnsealHubEnvelope = async (
  keyset: Ed448Keypair,
  envelope: HubSealedMessage,
  configKey?: X448Keypair
) => {
  // Use config key for decryption if provided, otherwise fall back to derived key for backwards compatibility
  let decryptionPrivKey: Uint8Array;
  if (configKey) {
    decryptionPrivKey = new Uint8Array(configKey.private_key);
    console.log('[UnsealHubEnvelope] Using config key, privKey length:', decryptionPrivKey.length, 'first 8 bytes:', Array.from(decryptionPrivKey.slice(0, 8)));
    console.log('[UnsealHubEnvelope] ephemeral_public_key from envelope:', envelope.ephemeral_public_key?.substring(0, 32));
  } else {
    // Legacy: derive X448 key from Ed448 hub key (deprecated)
    const derived = await window.crypto.subtle.digest(
      'SHA-512',
      Buffer.from(new Uint8Array(keyset.private_key))
    );
    decryptionPrivKey = new Uint8Array(Buffer.from(derived.slice(0, 56)));
  }
  const ephPubKey = new Uint8Array(Buffer.from(envelope.ephemeral_public_key, 'hex'));
  console.log('[UnsealHubEnvelope] ephemeral pubKey bytes first 8:', Array.from(ephPubKey.slice(0, 8)));
  const decryptInput = {
    inbox_private_key: [...decryptionPrivKey],
    ephemeral_public_key: [...ephPubKey],
    ciphertext: JSON.parse(envelope.envelope),
  };
  console.log('[UnsealHubEnvelope] calling decrypt with inbox_private_key length:', decryptInput.inbox_private_key.length, 'ephemeral length:', decryptInput.ephemeral_public_key.length);
  const decryptResult = ch.js_decrypt_inbox_message(JSON.stringify(decryptInput));
  console.log('[UnsealHubEnvelope] decrypt result preview:', decryptResult?.substring(0, 80));
  const plaintext = JSON.parse(decryptResult);
  return plaintext;
};

export const UnsealInitializationEnvelope = (
  keyset: DeviceKeyset,
  initial_message: SealedMessage
) => {
  const unsealed_envelope = JSON.parse(
    Buffer.from(
      new Uint8Array(
        JSON.parse(
          ch.js_decrypt_inbox_message(
            JSON.stringify({
              inbox_private_key:
                keyset.inbox_keyset.inbox_encryption_key.private_key,
              ephemeral_public_key: [
                ...new Uint8Array(
                  Buffer.from(initial_message.ephemeral_public_key, 'hex')
                ),
              ],
              ciphertext: JSON.parse(initial_message.envelope),
            } as SealedInboxMessageDecryptRequest)
          )
        ) as number[]
      )
    ).toString('utf-8')
  ) as InitializationEnvelope;
  return {
    ...unsealed_envelope,
    ephemeral_public_key: initial_message.ephemeral_public_key,
  } as UnsealedEnvelope;
};

export const NewDoubleRatchetRecipientSession = async (
  keyset: DeviceKeyset,
  initial_message: UnsealedEnvelope
) => {
  if (initial_message.type !== 'direct')
    throw new Error('invalid session type for double ratchet');
  const receiving_identity_key = [
    ...new Uint8Array(Buffer.from(initial_message.identity_public_key, 'hex')),
  ];
  const receiving_ephemeral_key = [
    ...new Uint8Array(Buffer.from(initial_message.ephemeral_public_key, 'hex')),
  ];

  const session_key = JSON.parse(
    ch.js_receiver_x3dh(
      JSON.stringify({
        sending_identity_private_key: keyset.identity_key.private_key,
        sending_signed_private_key: keyset.pre_key.private_key,
        receiving_identity_key: receiving_identity_key,
        receiving_ephemeral_key: receiving_ephemeral_key,
        session_key_length: 96,
      } as ReceiverX3DH)
    )
  );

  const root_key = [...new Uint8Array(Buffer.from(session_key, 'base64'))];
  const double_ratchet_session = ch.js_new_double_ratchet(
    JSON.stringify({
      session_key: root_key.slice(0, 32),
      sending_header_key: root_key.slice(32, 64),
      next_receiving_header_key: root_key.slice(64, 96),
      is_sender: false,
      sending_ephemeral_private_key: keyset.pre_key.private_key,
      receiving_ephemeral_key: receiving_ephemeral_key,
    } as NewDoubleRatchetParameters)
  );

  // force early failure on error
  JSON.parse(double_ratchet_session);

  const decrypted = JSON.parse(
    ch.js_double_ratchet_decrypt(
      JSON.stringify({
        ratchet_state: double_ratchet_session,
        envelope: initial_message.message,
      } as DoubleRatchetStateAndEnvelope)
    )
  ) as DoubleRatchetStateAndMessage;
  return {
    state: decrypted.ratchet_state,
    message: Buffer.from(new Uint8Array(decrypted.message)).toString('utf-8'),
    tag: initial_message.tag,
    return_inbox_address: initial_message.return_inbox_address,
    return_inbox_encryption_key: initial_message.return_inbox_encryption_key,
    return_inbox_public_key: initial_message.return_inbox_public_key,
    return_inbox_private_key: initial_message.return_inbox_private_key,
    user_address: initial_message.user_address,
    identity_public_key: initial_message.identity_public_key,
  } as NewDoubleRatchetRecipientSession;
};

export type DoubleRatchetStateAndInboxKeys = {
  ratchet_state: string;
  receiving_inbox: InboxKeyset;
  sending_inbox: SendingInbox;
  tag: string;
  sent_accept?: boolean;
};

export const DoubleRatchetInboxEncryptForceSenderInit = (
  device_keyset: DeviceKeyset,
  encryption_states: DoubleRatchetStateAndInboxKeys[],
  message: string,
  acceptee: UserRegistration,
  sender_name?: string,
  sender_photo?: string
) => {
  const outbound: SealedMessageAndMetadata[] = [];
  for (const state of encryption_states) {
    const ephemeral_private_key = [
      ...new Uint8Array(
        Buffer.from(
          JSON.parse(state.ratchet_state).sending_ephemeral_private_key,
          'base64'
        )
      ),
    ];
    const ephemeral_public_key = Buffer.from(
      JSON.parse(
        ch.js_get_pubkey_x448(
          JSON.parse(state.ratchet_state).sending_ephemeral_private_key
        )
      ),
      'base64'
    ).toString('hex');
    const envelope = DoubleRatchetEncrypt(state.ratchet_state, message);
    const ciphertext = ch.js_encrypt_inbox_message(
      JSON.stringify({
        inbox_public_key: [
          ...new Uint8Array(
            Buffer.from(state.sending_inbox.inbox_encryption_key, 'hex')
          ),
        ],
        ephemeral_private_key: ephemeral_private_key,
        plaintext: [
          ...new Uint8Array(
            Buffer.from(
              JSON.stringify({
                return_inbox_address: state.receiving_inbox.inbox_address,
                return_inbox_encryption_key: Buffer.from(
                  new Uint8Array(
                    state.receiving_inbox.inbox_encryption_key.public_key
                  )
                ).toString('hex'),
                return_inbox_public_key: Buffer.from(
                  new Uint8Array(state.receiving_inbox.inbox_key.public_key)
                ).toString('hex'),
                return_inbox_private_key: Buffer.from(
                  new Uint8Array(state.receiving_inbox.inbox_key.private_key)
                ).toString('hex'),
                user_address: acceptee.user_address,
                identity_public_key: Buffer.from(
                  new Uint8Array(device_keyset.identity_key.public_key)
                ).toString('hex'),
                tag: device_keyset.inbox_keyset.inbox_address,
                display_name: sender_name,
                user_icon: sender_photo,
                message: envelope.envelope,
                type: 'direct',
              } as InitializationEnvelope),
              'utf-8'
            )
          ),
        ],
      } as SealedInboxMessageEncryptRequest)
    );

    outbound.push({
      sealed_message: {
        inbox_address: state.sending_inbox.inbox_address,
        ephemeral_public_key: ephemeral_public_key,
        envelope: ciphertext,
        inbox_public_key: state.sending_inbox.inbox_public_key,
        inbox_signature:
          state.sending_inbox.inbox_public_key === ''
            ? ''
            : Buffer.from(
                JSON.parse(
                  ch.js_sign_ed448(
                    Buffer.from(
                      state.sending_inbox.inbox_private_key,
                      'hex'
                    ).toString('base64'),
                    Buffer.from(ciphertext, 'utf-8').toString('base64')
                  )
                ),
                'base64'
              ).toString('hex'),
      },
      ratchet_state: envelope.ratchet_state,
      receiving_inbox: state.receiving_inbox,
      sending_inbox: state.sending_inbox,
      tag: state.tag,
      sent_accept: true,
    } as SealedMessageAndMetadata);
  }
  return outbound;
};

export const DoubleRatchetInboxEncrypt = (
  device_keyset: DeviceKeyset,
  encryption_states: DoubleRatchetStateAndInboxKeys[],
  message: string,
  acceptee: UserRegistration,
  sender_name?: string,
  sender_photo?: string
) => {
  const outbound: SealedMessageAndMetadata[] = [];
  for (const state of encryption_states) {
    const ephemeral_key = JSON.parse(ch.js_generate_x448()) as X448Keypair;
    const envelope = DoubleRatchetEncrypt(state.ratchet_state, message);
    const ciphertext = state.sent_accept
      ? ch.js_encrypt_inbox_message(
          JSON.stringify({
            inbox_public_key: [
              ...new Uint8Array(
                Buffer.from(state.sending_inbox.inbox_encryption_key, 'hex')
              ),
            ],
            ephemeral_private_key: ephemeral_key.private_key,
            plaintext: [
              ...new Uint8Array(Buffer.from(envelope.envelope, 'utf-8')),
            ],
          } as SealedInboxMessageEncryptRequest)
        )
      : ch.js_encrypt_inbox_message(
          JSON.stringify({
            inbox_public_key: [
              ...new Uint8Array(
                Buffer.from(state.sending_inbox.inbox_encryption_key, 'hex')
              ),
            ],
            ephemeral_private_key: ephemeral_key.private_key,
            plaintext: [
              ...new Uint8Array(
                Buffer.from(
                  JSON.stringify({
                    return_inbox_address: state.receiving_inbox.inbox_address,
                    return_inbox_encryption_key: Buffer.from(
                      new Uint8Array(
                        state.receiving_inbox.inbox_encryption_key.public_key
                      )
                    ).toString('hex'),
                    return_inbox_public_key: Buffer.from(
                      new Uint8Array(state.receiving_inbox.inbox_key.public_key)
                    ).toString('hex'),
                    return_inbox_private_key: Buffer.from(
                      new Uint8Array(
                        state.receiving_inbox.inbox_key.private_key
                      )
                    ).toString('hex'),
                    user_address: acceptee.user_address,
                    identity_public_key: Buffer.from(
                      new Uint8Array(device_keyset.identity_key.public_key)
                    ).toString('hex'),
                    tag: device_keyset.inbox_keyset.inbox_address,
                    display_name: sender_name,
                    user_icon: sender_photo,
                    message: envelope.envelope,
                    type: 'direct',
                  } as InitializationEnvelope),
                  'utf-8'
                )
              ),
            ],
          } as SealedInboxMessageEncryptRequest)
        );

    outbound.push({
      sealed_message: {
        inbox_address: state.sending_inbox.inbox_address,
        ephemeral_public_key: Buffer.from(
          new Uint8Array(ephemeral_key.public_key)
        ).toString('hex'),
        envelope: ciphertext,
        inbox_public_key: state.sending_inbox.inbox_public_key,
        inbox_signature:
          state.sending_inbox.inbox_public_key === ''
            ? ''
            : Buffer.from(
                JSON.parse(
                  ch.js_sign_ed448(
                    Buffer.from(
                      state.sending_inbox.inbox_private_key,
                      'hex'
                    ).toString('base64'),
                    Buffer.from(ciphertext, 'utf-8').toString('base64')
                  )
                ),
                'base64'
              ).toString('hex'),
      },
      ratchet_state: envelope.ratchet_state,
      receiving_inbox: state.receiving_inbox,
      sending_inbox: state.sending_inbox,
      tag: state.tag,
      sent_accept: true,
    } as SealedMessageAndMetadata);
  }
  return outbound;
};

export const ConfirmDoubleRatchetSenderSession = (
  encryption_state: DoubleRatchetStateAndInboxKeys,
  message: SealedMessage
) => {
  const unsealed_envelope = Buffer.from(
    new Uint8Array(
      JSON.parse(
        ch.js_decrypt_inbox_message(
          JSON.stringify({
            inbox_private_key:
              encryption_state.receiving_inbox.inbox_encryption_key.private_key,
            ephemeral_public_key: [
              ...new Uint8Array(
                Buffer.from(message.ephemeral_public_key, 'hex')
              ),
            ],
            ciphertext: JSON.parse(message.envelope),
          } as SealedInboxMessageDecryptRequest)
        )
      ) as number[]
    )
  ).toString('utf-8');

  if (encryption_state.sending_inbox.inbox_public_key !== '') {
    throw new Error('inbox key already set');
  }

  const maybe_initialization_info_and_message = JSON.parse(
    unsealed_envelope
  ) as InitializationEnvelope;
  if (
    !(
      maybe_initialization_info_and_message.return_inbox_address &&
      maybe_initialization_info_and_message.return_inbox_encryption_key &&
      maybe_initialization_info_and_message.return_inbox_private_key &&
      maybe_initialization_info_and_message.return_inbox_public_key &&
      maybe_initialization_info_and_message.tag &&
      maybe_initialization_info_and_message.message &&
      maybe_initialization_info_and_message.user_address
    )
  ) {
    throw new Error('invalid initialization envelope');
  }

  const result = DoubleRatchetDecrypt(
    encryption_state.ratchet_state,
    maybe_initialization_info_and_message.message
  );
  return {
    ...result,
    receiving_inbox: encryption_state.receiving_inbox,
    user_profile: {
      user_address: maybe_initialization_info_and_message.user_address,
      user_icon: maybe_initialization_info_and_message.user_icon,
      display_name: maybe_initialization_info_and_message.display_name,
    } as UserProfile,
    tag: maybe_initialization_info_and_message.tag,
    sending_inbox: {
      inbox_address: maybe_initialization_info_and_message.return_inbox_address,
      inbox_encryption_key:
        maybe_initialization_info_and_message.return_inbox_encryption_key,
      inbox_public_key:
        maybe_initialization_info_and_message.return_inbox_public_key,
      inbox_private_key:
        maybe_initialization_info_and_message.return_inbox_private_key,
    } as SendingInbox,
  };
};

export const DoubleRatchetInboxDecrypt = (
  encryption_state: DoubleRatchetStateAndInboxKeys,
  message: SealedMessage
) => {
  const unsealed_envelope = Buffer.from(
    new Uint8Array(
      JSON.parse(
        ch.js_decrypt_inbox_message(
          JSON.stringify({
            inbox_private_key:
              encryption_state.receiving_inbox.inbox_encryption_key.private_key,
            ephemeral_public_key: [
              ...new Uint8Array(
                Buffer.from(message.ephemeral_public_key, 'hex')
              ),
            ],
            ciphertext: JSON.parse(message.envelope),
          } as SealedInboxMessageDecryptRequest)
        )
      ) as number[]
    )
  ).toString('utf-8');

  if (encryption_state.sending_inbox.inbox_public_key === '') {
    throw new Error('invalid state, missing sender inbox');
  }

  const maybe_initialization_info_and_message = JSON.parse(unsealed_envelope);
  if (maybe_initialization_info_and_message.user_address) {
    const result = DoubleRatchetDecrypt(
      encryption_state.ratchet_state,
      maybe_initialization_info_and_message.message
    );
    return {
      ...result,
      receiving_inbox: encryption_state.receiving_inbox,
      user_profile: {
        user_address: maybe_initialization_info_and_message.user_address,
        user_icon: maybe_initialization_info_and_message.user_icon,
        display_name: maybe_initialization_info_and_message.display_name,
      } as UserProfile,
      tag: maybe_initialization_info_and_message.tag,
      sending_inbox: {
        inbox_address:
          maybe_initialization_info_and_message.return_inbox_address,
        inbox_encryption_key:
          maybe_initialization_info_and_message.return_inbox_encryption_key,
        inbox_public_key:
          maybe_initialization_info_and_message.return_inbox_public_key,
        inbox_private_key:
          maybe_initialization_info_and_message.return_inbox_private_key,
      } as SendingInbox,
    };
  }

  return DoubleRatchetDecrypt(
    encryption_state.ratchet_state,
    unsealed_envelope
  );
};

const DoubleRatchetEncrypt = (encryption_state: string, message: string) => {
  return JSON.parse(
    ch.js_double_ratchet_encrypt(
      JSON.stringify({
        ratchet_state: encryption_state,
        message: [...new Uint8Array(Buffer.from(message, 'utf-8'))],
      } as DoubleRatchetStateAndMessage)
    )
  ) as DoubleRatchetStateAndEnvelope;
};

const DoubleRatchetDecrypt = (encryption_state: string, envelope: string) => {
  const output = JSON.parse(
    ch.js_double_ratchet_decrypt(
      JSON.stringify({
        ratchet_state: encryption_state,
        envelope: envelope,
      } as DoubleRatchetStateAndEnvelope)
    )
  ) as DoubleRatchetStateAndMessage;

  return {
    ratchet_state: output.ratchet_state,
    message: Buffer.from(new Uint8Array(output.message)).toString('utf-8'),
  };
};

export type PeerMessageSet = {
  [peer: string]: string;
};

export type TripleRatchetInitializationBundle = {
  ratchet_state: string;
  metadata: PeerMessageSet;
};

const CreateTripleRatchetGroupInfo = async () => {
  const pair = ch.js_generate_ed448();
  const p = JSON.parse(pair);
  const user_keyset = NewUserKeyset({
    type: 'ed448',
    ...p,
  });
  const device_keyset = await NewDeviceKeyset();
  const registration = await ConstructUserRegistration(
    user_keyset,
    [],
    [device_keyset]
  );

  return {
    user_keyset,
    device_keyset,
    registration,
  };
};

export const EstablishTripleRatchetSessionForSpace = async (
  user_keyset: UserKeyset,
  device_keyset: DeviceKeyset,
  registration: UserRegistration,
  total: number = 10000,
) => {
  let filteredRegistration = registration;
  if (filteredRegistration.device_registrations.length > 1) {
    const peerpubkey = Buffer.from(
      new Uint8Array(device_keyset.inbox_keyset.inbox_encryption_key.public_key)
    ).toString('hex');
    filteredRegistration.device_registrations =
      filteredRegistration.device_registrations.filter(
        (d) => d.inbox_registration.inbox_encryption_public_key == peerpubkey
      );
  }
  const set = [
    { user_keyset, device_keyset, registration: filteredRegistration },
    ...(await Promise.all(
      [1, 2, 3].map(async () => await CreateTripleRatchetGroupInfo())
    )),
  ];
  let outs = await Promise.all(
    set.map(
      async (i) =>
        await NewTripleRatchetSession(i.device_keyset, [
          ...set.map((i) => i.registration),
        ])
    )
  );
  let inboxes: { [receiver: string]: { [sender: string]: string } } = {};
  const senders = set.map((i) =>
    Buffer.from(
      new Uint8Array(
        i.device_keyset.inbox_keyset.inbox_encryption_key.public_key
      )
    ).toString('base64')
  );
  const steps = [
    TripleRatchetInitRound1,
    TripleRatchetInitRound2,
    TripleRatchetInitRound3,
    TripleRatchetInitRound4,
  ];
  for (const step of steps) {
    inboxes = {};
    for (let i = 0; i < 4; i++) {
      const sender = senders[i];
      if (!inboxes[sender]) inboxes[sender] = {};
      for (const recipient of Object.keys(outs[i].metadata)) {
        if (!inboxes[recipient]) inboxes[recipient] = {};
        inboxes[recipient] = Object.assign(inboxes[recipient], {
          [sender]: outs[i].metadata[recipient],
        });
      }
    }
    outs = outs.map(
      (o, i) =>
        JSON.parse(
          step(
            JSON.stringify({
              ratchet_state: o.ratchet_state,
              metadata: inboxes[senders[i]],
            })
          )
        ) as TripleRatchetInitializationBundle
    );
  }
  const index1 = [0, 1, 2, 3].find(
    (i) => JSON.parse(JSON.parse(outs[i].ratchet_state).dkg_ratchet).id == 1
  );
  const index2 = [0, 1, 2, 3].find(
    (i) => JSON.parse(JSON.parse(outs[i].ratchet_state).dkg_ratchet).id == 2
  );
  const initialize = JSON.parse(
    TripleRatchetEncrypt(
      JSON.stringify({
        ratchet_state: outs[index1!].ratchet_state,
        message: [...new Uint8Array(Buffer.from('initialize', 'utf-8'))],
      } as TripleRatchetStateAndMessage)
    )
  ) as TripleRatchetStateAndEnvelope;
  const initialized_set = [0, 1, 2, 3].map(
    (i) =>
      JSON.parse(
        TripleRatchetDecrypt(
          JSON.stringify({
            ratchet_state: outs[i].ratchet_state,
            envelope: initialize.envelope,
          })
        )
      ) as TripleRatchetStateAndMessage
  );
  const commit_initialize = JSON.parse(
    TripleRatchetEncrypt(
      JSON.stringify({
        ratchet_state: initialized_set[index1!].ratchet_state,
        message: [...new Uint8Array(Buffer.from('commit', 'utf-8'))],
      } as TripleRatchetStateAndMessage)
    )
  ) as TripleRatchetStateAndEnvelope;
  const commit_initialized = [0, 1, 2, 3].map(
    (i) =>
      JSON.parse(
        TripleRatchetDecrypt(
          JSON.stringify({
            ratchet_state: initialized_set[i].ratchet_state,
            envelope: commit_initialize.envelope,
          })
        )
      ) as TripleRatchetStateAndMessage
  );
  const evals = JSON.parse(
    ch.js_triple_ratchet_resize(
      JSON.stringify({
        ratchet_state: commit_initialized[index1!].ratchet_state,
        other: Buffer.from(
          JSON.parse(
            JSON.parse(commit_initialized[index2!].ratchet_state).dkg_ratchet
          ).scalar,
          'base64'
        ).toString('hex'),
        id: 2,
        total: total,
      })
    )
  ) as number[][];
  const state = JSON.parse(commit_initialized[index1!].ratchet_state);
  const stateTemplate = JSON.parse(commit_initialized[index2!].ratchet_state);
  state.current_receiving_chain_length = {
    [Buffer.from(
      new Uint8Array(device_keyset.inbox_keyset.inbox_encryption_key.public_key)
    ).toString('base64')]: 1,
  };
  const secret_pair = JSON.parse(ch.js_generate_x448());
  const eval_priv = evals.shift()!;
  const eval_pub = JSON.parse(
    ch.js_get_pubkey_x448(
      Buffer.from(new Uint8Array(eval_priv)).toString('base64')
    )
  );
  state.dkg_ratchet = JSON.stringify({
    threshold: 2,
    total: 1,
    id: 1,
    frags_for_counterparties: {},
    frags_from_counterparties: {},
    zkpok: JSON.parse(state.dkg_ratchet).zkpok,
    secret: Buffer.from(new Uint8Array(secret_pair.private_key)).toString(
      'base64'
    ),
    scalar: Buffer.from(new Uint8Array(eval_priv)).toString('base64'),
    generator:
      'FPow8lt5CJityNdOLBO9/cQ5fOYc/9M618KgBR6ceIdAmKNsc3PqS2LHyVY3IHaIJLy2bnFGP2kA',
    public_key: JSON.parse(state.dkg_ratchet).public_key,
    point: eval_pub,
    random_commitment_point: Buffer.from(
      new Uint8Array(secret_pair.public_key)
    ).toString('base64'),
    round: 4,
    zkcommits_from_counterparties: {},
    points_from_counterparties: {},
  });
  state.next_dkg_ratchet = state.dkg_ratchet;
  stateTemplate.dkg_ratchet = JSON.stringify({
    threshold: 2,
    total: -1,
    id: -1,
    frags_for_counterparties: {},
    frags_from_counterparties: {},
    zkpok: JSON.parse(state.dkg_ratchet).zkpok,
    secret: '<missing gen priv>',
    scalar: '<missing eval>',
    generator:
      'FPow8lt5CJityNdOLBO9/cQ5fOYc/9M618KgBR6ceIdAmKNsc3PqS2LHyVY3IHaIJLy2bnFGP2kA',
    public_key: JSON.parse(state.dkg_ratchet).public_key,
    point: '<missing raised eval>',
    random_commitment_point: '<missing gen pub>',
    round: 4,
    zkcommits_from_counterparties: {},
    points_from_counterparties: {},
  });
  stateTemplate.next_dkg_ratchet = stateTemplate.dkg_ratchet;
  state.id_peer_map = {
    [1]: {
      public_key: Buffer.from(
        new Uint8Array(
          device_keyset.inbox_keyset.inbox_encryption_key.public_key
        )
      ).toString('base64'),
      identity_public_key: Buffer.from(
        new Uint8Array(device_keyset.identity_key.public_key)
      ).toString('base64'),
      signed_pre_public_key: Buffer.from(
        new Uint8Array(device_keyset.pre_key.public_key)
      ).toString('base64'),
    },
  };
  stateTemplate.id_peer_map = state.id_peer_map;
  state.peer_channels = {};
  stateTemplate.peer_channels = {};
  state.peer_id_map = {
    [Buffer.from(
      new Uint8Array(device_keyset.inbox_keyset.inbox_encryption_key.public_key)
    ).toString('base64')]: 1,
  };
  stateTemplate.peer_id_map = {
    [Buffer.from(
      new Uint8Array(device_keyset.inbox_keyset.inbox_encryption_key.public_key)
    ).toString('base64')]: 1,
  };
  state.peer_key = Buffer.from(
    new Uint8Array(device_keyset.inbox_keyset.inbox_encryption_key.private_key)
  ).toString('base64');
  stateTemplate.peer_key = '<missing ibx priv>';
  state.previous_receiving_chain_length = {};
  stateTemplate.previous_receiving_chain_length = {};
  stateTemplate.ephemeral_private_key = '<missing gen priv>';

  return {
    state: JSON.stringify(state),
    template: stateTemplate,
    evals: evals,
  };
};

const NewTripleRatchetSession = async (
  device_keyset: DeviceKeyset,
  peers: UserRegistration[]
) => {
  const peerpubkey = Buffer.from(
    new Uint8Array(device_keyset.inbox_keyset.inbox_encryption_key.public_key)
  ).toString('hex');
  const self = peers.find((p) =>
    p.device_registrations.find(
      (d) => d.inbox_registration.inbox_encryption_public_key === peerpubkey
    )
  );
  if (!self) throw new Error('self not in peer set');
  const peerset = peers
    .map((p) => p.device_registrations)
    .filter(
      (a) =>
        !a.find(
          (p) => p.inbox_registration.inbox_encryption_public_key === peerpubkey
        )
    )
    .flatMap((p) => p)
    .sort((a, b) =>
      a.inbox_registration.inbox_encryption_public_key.localeCompare(
        b.inbox_registration.inbox_encryption_public_key
      )
    );
  if (peerset.length < 3) throw new Error('insufficient size of peer set');
  const peerbytes = peerset.map((p) => [
    ...new Uint8Array(
      Buffer.from(
        p.inbox_registration.inbox_encryption_public_key +
          p.identity_public_key +
          p.pre_public_key,
        'hex'
      )
    ),
  ]);
  const out = ch.js_new_triple_ratchet(
    JSON.stringify({
      peers: peerbytes,
      peer_key: device_keyset.inbox_keyset.inbox_encryption_key.private_key,
      identity_key: device_keyset.identity_key.private_key,
      signed_pre_key: device_keyset.pre_key.private_key,
      threshold: 2,
      async_dkg_ratchet: true,
    } as NewTripleRatchetParameters)
  );
  const bundle = JSON.parse(out) as TripleRatchetInitializationBundle;
  return bundle;
};

export const TripleRatchetInitRound1 = ch.js_triple_ratchet_init_round_1;
export const TripleRatchetInitRound2 = ch.js_triple_ratchet_init_round_2;
export const TripleRatchetInitRound3 = ch.js_triple_ratchet_init_round_3;
export const TripleRatchetInitRound4 = ch.js_triple_ratchet_init_round_4;
export const TripleRatchetEncrypt = ch.js_triple_ratchet_encrypt;
export const TripleRatchetDecrypt = ch.js_triple_ratchet_decrypt;
