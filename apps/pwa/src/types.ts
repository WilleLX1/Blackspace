import type { components } from "./generated";

export type TransportMode = components["schemas"]["TransportMode"];
export type FeatureFlagsV1 = components["schemas"]["FeatureFlagsV1"];
export type ServerInfoV1 = components["schemas"]["ServerInfoV1"];
export type MailboxProvisionRequestV1 = components["schemas"]["MailboxProvisionRequestV1"];
export type MailboxProvisionResponseV1 = components["schemas"]["MailboxProvisionResponseV1"];
export type EnvelopeV1 = components["schemas"]["EnvelopeV1"];
export type PulledEnvelopeV1 = components["schemas"]["PulledEnvelopeV1"];
export type PullResponseV1 = components["schemas"]["PullResponseV1"];
export type DepositTargetV1 = components["schemas"]["DepositTargetV1"];

export interface MailboxSession {
  mailboxId: string;
  readCapability: string;
  adminCapability: string;
  initialDepositCapabilityId: string;
  initialDepositCapability: string;
}

export interface TorStatus {
  phase: "starting" | "bootstrapping" | "ready" | "failed" | "stopped";
  bootstrap_percent: number;
  message: string;
}
