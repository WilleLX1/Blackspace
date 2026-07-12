export type DeliveryState = "queued" | "server-accepted" | "delivered" | "failed";

export interface PendingEnvelope {
  version: number;
  envelope_id: string;
  expires_at: number;
  size_class: number;
  ciphertext: string;
}

export interface MessageRecord {
  id: string;
  contactId: string;
  direction: "incoming" | "outgoing" | "system";
  body: string;
  sentAt: number;
  delivery: DeliveryState;
  error?: string;
  pendingEnvelope?: PendingEnvelope;
}

export interface DepositTarget {
  onion_url: string;
  https_url?: string;
  deposit_capability: string;
}

export interface ContactRecord {
  id: string;
  identityPublicKey: string;
  displayName: string;
  localName?: string;
  status: "pending" | "request" | "accepted" | "blocked";
  verified: boolean;
  unread: number;
  draft: string;
  target: DepositTarget;
  mlsGroupId?: string;
  inboundCapabilityId?: string;
  lastMessageAt: number;
}

export interface AccountState {
  version: 1;
  role?: "primary";
  displayName: string;
  instanceName: string;
  mailboxId: string;
  onionOrigin: string;
  httpsOrigin?: string;
  readCapability: string;
  adminCapability: string;
  identityPublicKey: string;
  mlsClientState: string;
  availableKeyPackages: number;
  contacts: ContactRecord[];
  messages: MessageRecord[];
  createdAt: number;
  companionLink?: CompanionLink;
}

// Primary-side record of the single linked companion device (MVP: N=1).
// The linkSecret and downlink deposit-cap secret let the primary mirror state;
// the *Id fields drive ack dispatch (recognize/skip own downlink, apply uplink)
// and revocation. The uplink deposit-cap secret is never persisted here.
export interface CompanionLink {
  pairingId: string;
  active: boolean;
  createdAt: number;
  confirmedAt?: number;
  lastUplinkAt?: number;
  label?: string;
  linkSecret: string;
  downlinkCap: string;
  downlinkCapId: string;
  uplinkCapId: string;
  downSeq: number;
  upLastApplied: number;
  downlinkOutbox: PendingEnvelope[];
}

// Companion-side link state. Holds the shared read cap and the uplink deposit-cap
// secret; never holds the identity private key or any MLS state.
export interface CompanionSide {
  pairingId: string;
  linkSecret: string;
  downlinkCapId: string;
  uplinkCap: string;
  uplinkCapId: string;
  downLastApplied: number;
  upSeq: number;
  uplinkOutbox: PendingEnvelope[];
  confirmed: boolean;
  lastDownlinkAt?: number;
}

// A companion's read-only view of a contact. No deposit target, MLS group, or
// inbound capability — the companion never talks MLS or mints capabilities.
export interface ContactProjection {
  id: string;
  identityPublicKey: string;
  displayName: string;
  localName?: string;
  status: "pending" | "request" | "accepted" | "blocked";
  verified: boolean;
  unread: number;
  draft: string;
  lastMessageAt: number;
}

// The reduced, MLS-free projection persisted on a companion device.
export interface CompanionAccountState {
  version: 1;
  role: "companion";
  displayName: string;
  instanceName: string;
  mailboxId: string;
  onionOrigin: string;
  httpsOrigin?: string;
  createdAt: number;
  readCapability: string;
  identityPublicKey: string;
  link: CompanionSide;
  contacts: ContactProjection[];
  messages: MessageRecord[];
}

// What the vault actually stores; the role discriminant selects the client shell.
export type StoredAccount = AccountState | CompanionAccountState;

export interface KeyPackageWire {
  package_id: string;
  protocol_version: number;
  ciphersuite: string;
  identity_public_key: string;
  key_package: string;
  expires_at: number;
}

export interface ServerInfo {
  instance_name: string;
  onion_origin?: string;
  https_origin?: string;
  protocol_versions: number[];
  envelope_size_classes: number[];
  maximum_envelope_bytes: number;
  features: {
    opaque_transport: boolean;
    key_packages: boolean;
    mls: boolean;
    registration_invites: boolean;
    recovery_takeover: boolean;
  };
}

export interface JoinInvitation {
  onionOrigin: string;
  httpsOrigin?: string;
  token: string;
}

export interface ContactInvitation {
  onionOrigin: string;
  httpsOrigin?: string;
  capability: string;
  identityPublicKey: string;
  inviteId: string;
}
