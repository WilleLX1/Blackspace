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
}

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
