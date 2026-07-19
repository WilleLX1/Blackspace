import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Archive, ArrowLeft, Check, CheckCheck, CircleAlert, Copy, Download,
  Fingerprint, Inbox, KeyRound, Lock, LogOut, MessageCircle, Plus,
  RefreshCw, Save, Search, Send, Server, Settings, ShieldCheck, Trash2, UserPlus, Users, X,
} from "lucide-react";
import QRCode from "qrcode";
import {
  acknowledgeEnvelopes, claimEnrollmentParcel, claimKeyPackage, createDepositCapability, depositEnvelope, diagnosticServerInfo,
  finalizeEnrollmentParcel as finalizeEnrollmentParcelRequest, getMlsState, listDevices, ownOrigin, parkEnrollmentParcel,
  provisionMailbox, publishKeyPackages, pullEnvelopes, putMlsState, registerDevice, revokeDepositCapability, serverInfo,
  recoverMailbox, rotateReadCapability, secureDeviceReset, type DeviceRecord,
} from "./api";
import {
  capabilityVerifier, envelopeForPacket,
  formatContactInvitation,
  packetFromEnvelope, parseContactInvitation, parseJoinInvitation, randomCapability,
  type SecureContent,
} from "./crypto";
import { base64Url } from "./crypto";
import { errorMessage, explainErrorMessage } from "./errors";
import { contactFingerprint, decodeSecureContent, encodeSecureContent, mlsCreateMessage, mlsGenerate, mlsGroupHint, mlsJoin, mlsProcessMessage, mlsRecoveryIdentitySnapshot, mlsReplenish, mlsStart } from "./mls";
import type { AccountState, CompanionAccountState, ContactRecord, DeliveryState, DepositTarget, KeyPackageWire, MessageRecord, PendingEnvelope, ServerInfo, StoredAccount } from "./model";
import { onboardingError, type OnboardingStage } from "./onboarding";
import { applyDownlinkEvent, buildSnapshot, newMessage, projectContact } from "./companion";
import { classify, openLinkEvent, sealLinkEvent, type DownlinkEvent, type UplinkCommand } from "./link";
import { createCompanionPairingOffer, createPrimaryPairingResponse, openPrimaryPairingResponse, type CompanionPairingOffer, type PairingBundle } from "./pairing";
import { detectTransportMode, deriveTransportMode, modeLabel, validateServerUrl } from "./security";
import { createRecoveryKit, deleteVault, lockVault, openRecoveryKit, saveVault, unlockVault, vaultExists } from "./vault";
import { pairingQrImage } from "./qr";
import { QrScanControls } from "./qrscan";
import { createSerialRunner } from "./serial";
import {
  createEnrollmentOffer, enrollmentSas, finalizeEnrollmentParcel, openEnrollmentParcel, openMlsState,
  parseEnrollmentOffer, prepareEnrollmentParcel, randomRootSecret, sealMlsState,
  type EnrollmentBundle, type EnrollmentOffer, type PreparedEnrollmentParcel,
} from "./account";
import { RollbackError, serverTransport, withMlsState } from "./mlsstate";
import { applyShared, extractShared, parseShared, serializeShared, type SharedState } from "./sharedstate";

type Screen = "loading" | "welcome" | "locked" | "messenger";
type Dialog = "add" | "invite" | "settings" | "security" | "link" | "device" | null;
type SettingsSection = "account" | "devices" | "privacy" | "network" | "recovery";

const initials = (name: string) => name.split(/\s+/).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "?";
const deviceLabel = () => (navigator.userAgent.includes("Mobile") ? "Phone" : "Browser");
const DELIVERY_LABELS: Record<DeliveryState, string> = { queued: "Queued", "server-accepted": "Server accepted", delivered: "Delivered", failed: "Failed" };
const deliveryLabel = (state: DeliveryState) => DELIVERY_LABELS[state] ?? state;
const formatTime = (value: number) => new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(value);
const formatDay = (value: number) => new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(value);
const wirePackages = (packages: string[], identity: string): KeyPackageWire[] => {
  // Leave a full day of clock-skew margin below the server's 30-day maximum.
  const expires = Math.floor(Date.now() / 1000) + 29 * 24 * 60 * 60;
  return packages.map((key_package) => ({ package_id: crypto.randomUUID(), protocol_version: 1, ciphersuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", identity_public_key: identity, key_package, expires_at: expires }));
};
const validateClaimedPackage = (claimed: KeyPackageWire, identity: string) => {
  if (claimed.protocol_version !== 1 || claimed.ciphersuite !== "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" || claimed.identity_public_key !== identity || claimed.expires_at <= Date.now() / 1000) {
    throw new Error("The claimed OpenMLS key package is invalid, expired, or belongs to another identity.");
  }
};
const advertisedOrigins = (info: ServerInfo, fallbackOnion: string): { onionOrigin: string; httpsOrigin?: string } => ({
  onionOrigin: validateServerUrl(info.onion_origin ?? fallbackOnion, "tor-native"),
  httpsOrigin: info.https_origin ? validateServerUrl(info.https_origin, "https-web") : undefined,
});

function ModeBadge() {
  const mode = detectTransportMode();
  return <span className={`mode-badge ${mode}`}><ShieldCheck size={14} />{modeLabel(mode)}</span>;
}

function Notice({ error, onClose }: { error: string; onClose(): void }) {
  const [open, setOpen] = useState(false);
  const help = explainErrorMessage(error);
  return <div className="toast" role="alert">
    <CircleAlert size={18} />
    <div className="toast-body">
      <span>{error}</span>
      {help && <button className="toast-more" onClick={() => setOpen((value) => !value)}>{open ? "Hide details" : "What does this mean?"}</button>}
      {open && help && <p className="toast-detail">{help}</p>}
    </div>
    <button className="toast-close" onClick={onClose} aria-label="Dismiss"><X size={16} /></button>
  </div>;
}

function WelcomeScreen({ onComplete }: { onComplete(state: StoredAccount, passphrase: string): void }) {
  const [invitation, setInvitation] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [linking, setLinking] = useState(false);
  const [enrolling, setEnrolling] = useState(false);
  const recoveryInput = useRef<HTMLInputElement>(null);
  const attempt = useRef<{
    key: string;
    readCapability: string;
    adminCapability: string;
    identityPublicKey: string;
    mlsClientState: string;
    request: object;
  } | null>(null);

  const create = async () => {
    setBusy(true); setError("");
    let stage: OnboardingStage = "server check";
    try {
      if (displayName.trim().length < 2 || displayName.trim().length > 64) throw new Error("Choose a display name between 2 and 64 characters.");
      if (passphrase.length < 10 || passphrase !== confirm) throw new Error("Use a matching vault passphrase of at least 10 characters.");
      const join = parseJoinInvitation(invitation);
      const origin = ownOrigin(join.onionOrigin, join.httpsOrigin);
      const info = await serverInfo(origin);
      const advertised = advertisedOrigins(info, join.onionOrigin);
      if (!info.features.mls || !info.features.registration_invites) throw new Error("This server does not support the v0.1 private-alpha protocol.");
      const attemptKey = `${invitation.trim()}\0${displayName.trim()}`;
      if (!attempt.current || attempt.current.key !== attemptKey) {
        const readCapability = randomCapability();
        const adminCapability = randomCapability();
        const depositCapability = randomCapability();
        const identity = await mlsGenerate(20);
        attempt.current = {
          key: attemptKey,
          readCapability,
          adminCapability,
          identityPublicKey: identity.identity_public_key,
          mlsClientState: identity.client_state,
          request: {
            identity_public_key: identity.identity_public_key,
            read_capability_verifier: await capabilityVerifier("read", readCapability),
            admin_capability_verifier: await capabilityVerifier("admin", adminCapability),
            initial_deposit_capability_verifier: await capabilityVerifier("deposit", depositCapability),
            initial_deposit_expires_at: null,
            key_packages: wirePackages(identity.key_packages, identity.identity_public_key),
          },
        };
      }
      const current = attempt.current;
      stage = "mailbox registration";
      const provisioned = await provisionMailbox(origin, join.token, current.request);
      const state: AccountState = {
        version: 1, displayName: displayName.trim(), instanceName: info.instance_name,
        mailboxId: provisioned.mailbox_id, onionOrigin: advertised.onionOrigin, httpsOrigin: advertised.httpsOrigin,
        readCapability: current.readCapability, adminCapability: current.adminCapability, identityPublicKey: current.identityPublicKey,
        mlsClientState: current.mlsClientState, availableKeyPackages: 20,
        contacts: [], messages: [], createdAt: Date.now(),
      };
      stage = "encrypted local storage";
      await saveVault(state, passphrase);
      attempt.current = null;
      onComplete(state, passphrase);
    } catch (cause) { setError(onboardingError(cause, stage)); }
    finally { setBusy(false); }
  };

  const recover = async (file?: File) => {
    if (!file) return;
    const recoveryPassphrase = prompt("Enter the separate recovery-kit passphrase you chose when exporting this file:");
    const newVaultPassphrase = prompt("Choose a new local vault passphrase (at least 10 characters):");
    if (!recoveryPassphrase || !newVaultPassphrase) return;
    if (newVaultPassphrase.length < 10) { setError("Use at least 10 characters for the new local vault passphrase."); return; }
    setBusy(true); setError("");
    try {
      const restored = await openRecoveryKit(new Uint8Array(await file.arrayBuffer()), recoveryPassphrase);
      const origin = ownOrigin(restored.onionOrigin, restored.httpsOrigin);
      const readCapability = randomCapability(); const adminCapability = randomCapability();
      const depositCapabilities = await Promise.all(restored.contacts.map(async () => {
        const capability = randomCapability();
        return { capability, verifier: await capabilityVerifier("deposit", capability) };
      }));
      if (!depositCapabilities.length) {
        const capability = randomCapability(); depositCapabilities.push({ capability, verifier: await capabilityVerifier("deposit", capability) });
      }
      const replenished = await mlsReplenish(restored.mlsClientState, 20);
      const packages = wirePackages(replenished.key_packages, restored.identityPublicKey);
      const recovered = await recoverMailbox(origin, restored.adminCapability, {
        identity_public_key: restored.identityPublicKey,
        read_capability_verifier: await capabilityVerifier("read", readCapability),
        admin_capability_verifier: await capabilityVerifier("admin", adminCapability),
        deposit_capabilities: depositCapabilities.map((item) => ({ verifier: item.verifier, expires_at: null })),
        key_packages: packages,
      });
      restored.readCapability = readCapability; restored.adminCapability = adminCapability; restored.mlsClientState = replenished.client_state; restored.availableKeyPackages = 20;
      restored.contacts.forEach((contact, index) => { contact.inboundCapabilityId = recovered.deposit_capability_ids[index]; });
      for (let index = 0; index < restored.contacts.length; index += 1) {
        const contact = restored.contacts[index];
        try {
          const claimed = await claimKeyPackage(contact.target);
          validateClaimedPackage(claimed, contact.identityPublicKey);
          const replyInvitation = formatContactInvitation({ onion_url: restored.onionOrigin, https_url: restored.httpsOrigin, deposit_capability: depositCapabilities[index].capability }, restored.identityPublicKey, crypto.randomUUID());
          const content: SecureContent = { version: 1, type: "session_reset", messageId: crypto.randomUUID(), sentAt: Date.now(), senderIdentity: restored.identityPublicKey, displayName: restored.displayName, replyInvitation };
          const bootstrap = await mlsStart(restored.mlsClientState, contact.identityPublicKey, claimed.key_package, await encodeSecureContent(content)); restored.mlsClientState = bootstrap.client_state;
          await depositEnvelope(contact.target, envelopeForPacket({ kind: "mls_bootstrap", welcome: bootstrap.welcome, firstMessage: bootstrap.first_message })); contact.mlsGroupId = bootstrap.group_id;
          restored.messages.push({ id: content.messageId, contactId: contact.id, direction: "system", body: "Security session refreshed after recovery.", sentAt: content.sentAt, delivery: "server-accepted" });
        } catch { contact.status = "pending"; contact.mlsGroupId = undefined; }
      }
      await saveVault(restored, newVaultPassphrase); onComplete(restored, newVaultPassphrase);
    } catch (cause) { setError(errorMessage(cause, "Recovery failed.")); }
    finally { setBusy(false); if (recoveryInput.current) recoveryInput.current.value = ""; }
  };

  if (enrolling) return <EnrollDeviceScreen onComplete={onComplete} onCancel={() => setEnrolling(false)} />;
  if (linking) return <LinkCompanionScreen onComplete={onComplete} onCancel={() => setLinking(false)} />;
  return <main className="auth-shell">
    <section className="auth-brand">
      <div className="brand-mark"><MessageCircle /></div>
      <span className="eyebrow">BLACKSPACE PRIVATE ALPHA</span>
      <h1>Your conversations.<br />Your keys. Your server.</h1>
      <p>Invite-only, end-to-end encrypted messaging designed to keep plaintext on your devices.</p>
      <div className="assurance-list"><span><ShieldCheck /> End-to-end encrypted</span><span><Server /> Self-hosted mailbox</span><span><KeyRound /> No phone or email</span></div>
    </section>
    <section className="auth-card">
      <div><span className="step">01 / 03</span><h2>Join your server</h2><p>Your server operator provides a one-time invitation.</p></div>
      <label>Server invitation<textarea rows={4} value={invitation} onChange={(event) => setInvitation(event.target.value)} placeholder="blackspace://join/v1?onion=…#token=…" spellCheck={false} /></label>
      <label>Private display name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="How contacts will see you" maxLength={64} /></label>
      <div className="field-grid"><label>Vault passphrase<input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label><label>Confirm passphrase<input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label></div>
      {error && <p className="form-error"><CircleAlert size={16} />{error}</p>}
      <button className="primary wide" onClick={create} disabled={busy}>{busy ? <><RefreshCw className="spin" /> Creating encrypted identity…</> : <>Create my private space <Send size={17} /></>}</button>
      <input ref={recoveryInput} hidden type="file" accept=".blackspace-recovery,application/blackspace-recovery" onChange={(event) => void recover(event.target.files?.[0])} />
      <button className="text-button" onClick={() => recoveryInput.current?.click()} disabled={busy}><Archive size={15} /> Recover this device</button>
      <button className="text-button" onClick={() => setEnrolling(true)} disabled={busy}><Users size={15} /> Add this device to my account</button>
      <button className="text-button" onClick={() => setLinking(true)} disabled={busy}><Users size={15} /> Link as a companion (mirror)</button>
      <p className="fine-print">Unaudited private alpha. Do not use for high-risk communications.</p>
      <ModeBadge />
    </section>
  </main>;
}

function LinkCompanionScreen({ onComplete, onCancel }: { onComplete(state: CompanionAccountState, passphrase: string): void; onCancel(): void }) {
  const [offer, setOffer] = useState<CompanionPairingOffer>();
  const [offerQr, setOfferQr] = useState("");
  const [response, setResponse] = useState("");
  const [opened, setOpened] = useState<{ bundle: PairingBundle; sas: string }>();
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  useEffect(() => { void createCompanionPairingOffer().then(async (value) => { setOffer(value); setOfferQr(await pairingQrImage(value.qr)); }).catch((cause) => setError(errorMessage(cause, "Could not start pairing."))); }, []);
  const inspect = async () => {
    if (!offer) return;
    try { setOpened(await openPrimaryPairingResponse(offer, response)); setError(""); }
    catch (cause) { setError(errorMessage(cause, "The pairing response is invalid.")); }
  };
  const finish = async () => {
    if (!offer || !opened) return;
    try {
      if (passphrase.length < 10 || passphrase !== confirm) throw new Error("Use a matching local passphrase of at least 10 characters.");
      const value = opened.bundle;
      const state: CompanionAccountState = {
        version: 1, role: "companion", displayName: value.displayName, instanceName: value.instanceName,
        mailboxId: "linked", onionOrigin: value.onionOrigin, httpsOrigin: value.httpsOrigin, createdAt: Date.now(),
        readCapability: value.readCapability, identityPublicKey: value.identityPublicKey, contacts: [], messages: [],
        link: { pairingId: offer.pairingId, linkSecret: value.linkSecret, downlinkCapId: value.downlinkCapId, uplinkCap: value.uplinkCap, uplinkCapId: value.uplinkCapId, downLastApplied: 0, upSeq: 0, uplinkOutbox: [], confirmed: true },
      };
      await saveVault(state, passphrase); onComplete(state, passphrase);
    } catch (cause) { setError(errorMessage(cause, "Could not save this linked device.")); }
  };
  return <main className="lock-shell"><section className="lock-card"><span className="eyebrow">LINKED COMPANION</span><h1>Link this device</h1><p>Show this first code to your primary device. It contains only a temporary public key.</p>{offerQr && <img className="pairing-qr" src={offerQr} alt="Companion pairing offer" />}<textarea readOnly rows={4} value={offer?.qr ?? "Preparing…"} />{!opened ? <><label>Response from primary<textarea rows={5} value={response} onChange={(event) => setResponse(event.target.value)} /></label><QrScanControls label="Scan response QR" onValue={(value) => { setResponse(value); setError(""); }} onError={setError} /><button className="primary wide" onClick={inspect} disabled={!response.trim()}>Open response</button></> : <><p>Compare this code on both devices before confirming:</p><code>{opened.sas}</code><label>Local vault passphrase<input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label><label>Confirm passphrase<input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label><button className="primary wide" onClick={finish}>Codes match — link device</button></>}{error && <p className="form-error"><CircleAlert size={16} />{error}</p>}<button className="text-button" onClick={onCancel}>Cancel</button></section></main>;
}

// New-device onboarding for multi-device: show one enrollment QR, wait for the
// trusted device to seal a parcel, confirm the emoji, then bootstrap the full
// account from the shared state blob. One scan (of this screen) plus one tap.
function EnrollDeviceScreen({ onComplete, onCancel }: { onComplete(state: StoredAccount, passphrase: string): void; onCancel(): void }) {
  const [onion, setOnion] = useState("");
  const [https, setHttps] = useState("");
  const [session, setSession] = useState<{ offer: EnrollmentOffer; origin: string; image: string }>();
  const [claimed, setClaimed] = useState<{ bundle: EnrollmentBundle; sas: string }>();
  const [pendingSas, setPendingSas] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const start = async () => {
    setError(""); setBusy(true);
    try {
      const onionOrigin = onion.trim();
      const httpsOrigin = https.trim() || undefined;
      const origin = ownOrigin(onionOrigin, httpsOrigin);
      const offer = await createEnrollmentOffer(onionOrigin, httpsOrigin);
      setSession({ offer, origin, image: await pairingQrImage(offer.qr) });
    } catch (cause) { setError(errorMessage(cause, "Enter your server's onion address from the other device's Settings.")); }
    finally { setBusy(false); }
  };

  useEffect(() => {
    if (!session || claimed) return;
    let cancelled = false;
    const timer = window.setInterval(() => {
      void (async () => {
        try {
          const parcel = await claimEnrollmentParcel(session.origin, session.offer.claimSecret);
          if (!parcel || cancelled) return;
          const sas = await enrollmentSas(session.offer, parcel.eph_pub);
          if (parcel.status === "pending_confirmation") {
            if (!cancelled) setPendingSas(sas);
            return;
          }
          if (!parcel.nonce || !parcel.size_class || !parcel.ciphertext) throw new Error("The approved enrollment parcel is incomplete.");
          const opened = await openEnrollmentParcel(session.offer, {
            eph_pub: parcel.eph_pub, nonce: parcel.nonce, size_class: parcel.size_class, ciphertext: parcel.ciphertext,
          });
          if (cancelled) return;
          window.clearInterval(timer);
          setClaimed(opened);
        } catch { /* keep polling until the parcel appears */ }
      })();
    }, 2_500);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [session, claimed]);

  const finish = async () => {
    if (!session || !claimed) return;
    setError(""); setBusy(true);
    try {
      if (passphrase.length < 10 || passphrase !== confirm) throw new Error("Use a matching local passphrase of at least 10 characters.");
      const bundle = claimed.bundle;
      const sealed = await getMlsState(session.origin, bundle.adminCapability);
      if (!sealed) throw new Error("The account has no shared state yet. Open your other device once, then retry.");
      const shared = parseShared(await openMlsState(bundle.rootSecret, bundle.mailboxId, sealed));
      const state: AccountState = {
        version: 1, displayName: bundle.displayName, instanceName: bundle.instanceName,
        mailboxId: bundle.mailboxId, onionOrigin: bundle.onionOrigin, httpsOrigin: bundle.httpsOrigin,
        readCapability: bundle.readCapability, adminCapability: bundle.adminCapability, identityPublicKey: bundle.identityPublicKey,
        mlsClientState: shared.mlsClientState, availableKeyPackages: shared.availableKeyPackages,
        contacts: shared.contacts.map((contact) => ({ ...contact, draft: "" })), messages: shared.messages, createdAt: Date.now(),
        rootSecret: bundle.rootSecret, deviceId: bundle.deviceId, mlsStateVersion: sealed.version,
      };
      await saveVault(state, passphrase);
      onComplete(state, passphrase);
    } catch (cause) { setError(errorMessage(cause, "Could not finish adding this device.")); }
    finally { setBusy(false); }
  };

  return <main className="lock-shell"><section className="lock-card">
    <span className="eyebrow">ADD THIS DEVICE</span><h1>Add to your account</h1>
    {!session ? <>
      <p>Enter your Blackspace server address (shown under Settings → Identity on a device that is already signed in).</p>
      <label>Server onion address<input value={onion} onChange={(event) => setOnion(event.target.value)} placeholder="http://…onion" /></label>
      <label>HTTPS gateway (optional)<input value={https} onChange={(event) => setHttps(event.target.value)} placeholder="https://…" /></label>
      <button className="primary wide" onClick={start} disabled={busy || !onion.trim()}>Show enrollment code</button>
    </> : !claimed ? <>
      <p>On your other device, open Settings → Devices → Add a device and scan this code.</p>
      {session.image && <img className="pairing-qr" src={session.image} alt="Device enrollment code" />}
      <textarea readOnly rows={3} value={session.offer.qr} />
      {pendingSas ? <>
        <p>Compare this code with the trusted device. Account secrets remain withheld until that device approves:</p>
        <code>{pendingSas}</code>
        <p className="fine-print">Waiting for approval on your trusted device…</p>
      </> : <p className="fine-print">Waiting for your trusted device to scan the code…</p>}
    </> : <>
      <p>Confirm this emoji code matches the one shown on your other device:</p>
      <code>{claimed.sas}</code>
      <label>Local vault passphrase<input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label>
      <label>Confirm passphrase<input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label>
      <button className="primary wide" onClick={finish} disabled={busy}>Codes match — add device</button>
    </>}
    {error && <p className="form-error"><CircleAlert size={16} />{error}</p>}
    <button className="text-button" onClick={onCancel}>Cancel</button>
  </section></main>;
}

function LockedScreen({ onUnlock, onReset }: { onUnlock(state: StoredAccount, passphrase: string): void; onReset(): void }) {
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const unlock = async () => {
    setBusy(true); setError("");
    try { onUnlock(await unlockVault(passphrase), passphrase); }
    catch (cause) { setError(errorMessage(cause, "Unlock failed.")); }
    finally { setBusy(false); }
  };
  return <main className="lock-shell"><section className="lock-card">
    <div className="brand-mark large"><Lock /></div><span className="eyebrow">ENCRYPTED VAULT</span><h1>Welcome back</h1><p>Unlock your local Blackspace identity and conversations.</p>
    <label>Vault passphrase<input autoFocus type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} onKeyDown={(event) => event.key === "Enter" && void unlock()} /></label>
    {error && <p className="form-error"><CircleAlert size={16} />{error}</p>}
    <button className="primary wide" onClick={unlock} disabled={busy}>{busy ? "Unlocking…" : "Unlock Blackspace"}</button>
    <button className="text-button danger" onClick={onReset}>Reset this device</button><ModeBadge />
  </section></main>;
}

interface ModalProps { title: string; children: ReactNode; onClose(): void }
function Modal({ title, children, onClose }: ModalProps) {
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className="modal" role="dialog" aria-modal="true"><header><h2>{title}</h2><button className="icon-button" onClick={onClose}><X /></button></header>{children}</section></div>;
}

function Messenger({ initial, passphrase, onLock, onReset }: { initial: AccountState; passphrase: string; onLock(): void; onReset(): void }) {
  const [account, setAccount] = useState(initial);
  const accountRef = useRef(account);
  const [selectedId, setSelectedId] = useState(initial.contacts.find((contact) => contact.status === "accepted")?.id ?? "");
  const [dialog, setDialog] = useState<Dialog>(null);
  const [settingsSection, setSettingsSection] = useState<SettingsSection>("account");
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [online, setOnline] = useState(navigator.onLine);
  const [mobileList, setMobileList] = useState(true);
  const [inviteValue, setInviteValue] = useState("");
  const [inviteQr, setInviteQr] = useState("");
  const [busy, setBusy] = useState(false);
  const [linkSetup, setLinkSetup] = useState<{ pairingId: string; qr: string; qrImage: string; sas: string; linkSecret: string; downlinkCap: string; downlinkCapId: string; uplinkCapId: string }>();
  const [addDeviceSetup, setAddDeviceSetup] = useState<{ prepared: PreparedEnrollmentParcel; parcelId: string; deviceId: string }>();
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [sending, setSending] = useState(false);
  const sendingRef = useRef(false);
  const syncing = useRef(false);
  const syncFailures = useRef(0);
  const resumedPendingRotation = useRef(false);
  accountRef.current = account;

  const persist = useCallback(async (next: AccountState) => {
    accountRef.current = next; setAccount(next); await saveVault(next, passphrase);
  }, [passphrase]);

  const ownServer = ownOrigin(account.onionOrigin, account.httpsOrigin);
  const openSettings = (section: SettingsSection = "account") => {
    setSettingsSection(section);
    setDialog("settings");
  };

  // Serialize every clone→mutate→persist cycle (poll processing, sends, accepts,
  // retries, mirror snapshots, one-field edits) through one runner so they never
  // interleave. A stale clone persisted mid-poll would revert mlsClientState and
  // fork the ratchet, or revert companionLink.downSeq and reuse an AEAD nonce.
  // Never await queueMirrorSnapshot from inside a runExclusive task — it enqueues
  // on the same runner, so that would deadlock. Call it after the task completes.
  const runExclusive = useRef(createSerialRunner()).current;

  const queueMirrorSnapshot = useCallback((): Promise<void> => runExclusive(async () => {
    let next = structuredClone(accountRef.current); if (!next.companionLink?.active) return;
    next.companionLink.downSeq += 1; await persist(next);
    const event: DownlinkEvent = { type: "snapshot", eventId: crypto.randomUUID(), ts: Date.now(), payload: buildSnapshot(next) };
    const packet = await sealLinkEvent(next.companionLink.linkSecret, next.companionLink.pairingId, "down", next.companionLink.downSeq, event);
    next = structuredClone(accountRef.current); const outbox = next.companionLink!.downlinkOutbox;
    if (outbox.length >= 200) outbox.splice(0, outbox.length);
    outbox.push(envelopeForPacket(packet)); await persist(next);
  }), [persist, runExclusive]);

  // The single choke point for every conversation-state change. When this device
  // has been upgraded to multi-device, the authoritative state is the shared,
  // encrypted CAS blob on the server: download it, run `op` against it, and
  // compare-and-swap it back (withMlsState), so concurrent devices never fork the
  // ratchet and every device converges on one history. Before upgrade it behaves
  // exactly as before — a purely local read-modify-write on the vault. Callers
  // must already hold the in-process lock (runExclusive); `op` mutates the given
  // SharedState in place, and any network side effect (deposit/ack) goes in
  // `deferred`, which runs only after the state it depends on has committed.
  const mutateState = useCallback(async <T,>(op: (shared: SharedState) => Promise<{ changed: boolean; value: T; deferred?: () => Promise<void> }>): Promise<T> => {
    const base = accountRef.current;
    if (base.rootSecret !== undefined && base.mlsStateVersion !== undefined) {
      const transport = serverTransport(ownServer, base.adminCapability, getMlsState, putMlsState);
      const outcome = await withMlsState(
        { transport, rootSecret: base.rootSecret, mailboxId: base.mailboxId, knownVersion: base.mlsStateVersion },
        async (stateStr) => {
          const shared = stateStr ? parseShared(stateStr) : extractShared(accountRef.current);
          const result = await op(shared);
          return { changed: result.changed, state: result.changed ? serializeShared(shared) : undefined, deferred: result.deferred, result: { shared, value: result.value } };
        },
      );
      const merged = applyShared(accountRef.current, outcome.result.shared);
      merged.mlsStateVersion = outcome.version;
      await persist(merged);
      return outcome.result.value;
    }
    // Legacy single-device: no server blob, operate on the local vault directly.
    const shared = extractShared(accountRef.current);
    const result = await op(shared);
    if (result.changed) await persist(applyShared(accountRef.current, shared));
    if (result.deferred) await result.deferred();
    return result.value;
  }, [ownServer, persist]);

  // Opt-in migration of a legacy single-device account to multi-device: mint a
  // root secret, publish the current state as blob version 1, and register this
  // device. Guarded so a mailbox that already has shared state is never clobbered.
  const ensureUpgraded = useCallback((): Promise<void> => runExclusive(async () => {
    const acct = accountRef.current;
    if (acct.rootSecret !== undefined && acct.mlsStateVersion !== undefined) return;
    if (await getMlsState(ownServer, acct.adminCapability)) {
      throw new Error("This mailbox already has shared multi-device state. Enroll this device from one that is already linked.");
    }
    const rootSecret = randomRootSecret();
    const deviceId = crypto.randomUUID();
    const sealed = await sealMlsState(rootSecret, acct.mailboxId, serializeShared(extractShared(acct)));
    const put = await putMlsState(ownServer, acct.adminCapability, 0, sealed);
    if (put === "conflict") throw new Error("Another device just set up multi-device. Reload, then enroll this device.");
    await registerDevice(ownServer, acct.adminCapability, deviceId, deviceLabel());
    const next = structuredClone(accountRef.current);
    next.rootSecret = rootSecret; next.deviceId = deviceId; next.mlsStateVersion = put.version;
    await persist(next);
  }), [ownServer, persist, runExclusive]);

  // Trusted device, stage one: park only an ephemeral public key. The account
  // bundle is not created until approveDevice confirms the human SAS comparison.
  const addDevice = useCallback(async (offerCode: string): Promise<void> => {
    await ensureUpgraded();
    const base = accountRef.current;
    if (base.rootSecret === undefined) throw new Error("This device is not set up for multi-device.");
    const offer = parseEnrollmentOffer(offerCode);
    const deviceId = crypto.randomUUID();
    const prepared = await prepareEnrollmentParcel(offer);
    const parked = await parkEnrollmentParcel(ownServer, base.adminCapability, prepared.request);
    setAddDeviceSetup({ prepared, parcelId: parked.parcel_id, deviceId });
  }, [ensureUpgraded, ownServer]);

  // Trusted device, stage two: the button wording is the authorization boundary.
  // Only after it is pressed do reusable account capabilities enter ciphertext.
  const approveDevice = useCallback(async (): Promise<void> => {
    if (!addDeviceSetup) return;
    const base = accountRef.current;
    if (base.rootSecret === undefined) throw new Error("This device is not set up for multi-device.");
    const bundle: EnrollmentBundle = {
      rootSecret: base.rootSecret, readCapability: base.readCapability, adminCapability: base.adminCapability,
      identityPublicKey: base.identityPublicKey, mailboxId: base.mailboxId, onionOrigin: base.onionOrigin,
      httpsOrigin: base.httpsOrigin, displayName: base.displayName, instanceName: base.instanceName, deviceId: addDeviceSetup.deviceId,
    };
    const parcel = await finalizeEnrollmentParcel(addDeviceSetup.prepared, bundle);
    // Register the device before making its secret parcel claimable. If the
    // registry write fails, no reusable account secret has left this device.
    await registerDevice(ownServer, base.adminCapability, addDeviceSetup.deviceId, deviceLabel());
    await finalizeEnrollmentParcelRequest(ownServer, base.adminCapability, addDeviceSetup.parcelId, parcel);
    setAddDeviceSetup(undefined);
    setDevices(await listDevices(ownServer, base.adminCapability));
    setSettingsSection("devices"); setDialog("settings");
  }, [addDeviceSetup, ownServer]);

  const refreshDevices = useCallback(async () => {
    try { setDevices(await listDevices(ownServer, accountRef.current.adminCapability)); }
    catch { setDevices([]); }
  }, [ownServer]);

  const secureRemoveDevice = useCallback(async (id: string) => {
    const target = devices.find((device) => device.id === id);
    const otherCount = devices.filter((device) => !device.revoked && device.id !== accountRef.current.deviceId).length;
    if (!confirm(`Securely remove ${target?.label ?? "this device"}? Blackspace will rotate mailbox and shared-state keys, signing out ${otherCount === 1 ? "the other device" : `all ${otherCount} other devices`}. Trusted devices can be added again afterward.`)) return;
    await runExclusive(async () => {
      const base = accountRef.current;
      if (!base.rootSecret || !base.deviceId || base.mlsStateVersion === undefined) throw new Error("Set up multi-device before managing enrolled devices.");
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const currentBlob = await getMlsState(ownServer, base.adminCapability);
        if (!currentBlob) throw new Error("The shared account state is unavailable.");
        if (currentBlob.version < base.mlsStateVersion) throw new RollbackError(currentBlob.version, base.mlsStateVersion);
        const sharedText = await openMlsState(base.rootSecret, base.mailboxId, currentBlob);
        const nextRootSecret = randomRootSecret();
        const nextReadCapability = randomCapability();
        const nextAdminCapability = randomCapability();
        const rekeyed = await sealMlsState(nextRootSecret, base.mailboxId, sharedText);
        const reset = await secureDeviceReset(ownServer, base.adminCapability, {
          current_device_id: base.deviceId,
          read_capability_verifier: await capabilityVerifier("read", nextReadCapability),
          admin_capability_verifier: await capabilityVerifier("admin", nextAdminCapability),
          revoke_deposit_capability_ids: base.companionLink ? [base.companionLink.downlinkCapId, base.companionLink.uplinkCapId] : [],
          expected_mls_state_version: currentBlob.version,
          mls_state_size_class: rekeyed.size_class,
          mls_state_ciphertext: rekeyed.ciphertext,
        });
        if (reset === "conflict") continue;
        const next = applyShared(accountRef.current, parseShared(sharedText));
        next.rootSecret = nextRootSecret;
        next.readCapability = nextReadCapability;
        next.adminCapability = nextAdminCapability;
        next.mlsStateVersion = reset.version;
        next.pendingReadCapability = undefined;
        next.companionLink = undefined;
        await persist(next);
        setDevices(await listDevices(ownServer, nextAdminCapability));
        return;
      }
      throw new Error("Another device kept changing the account. Try the secure removal again.");
    });
  }, [devices, ownServer, persist, runExclusive]);

  const selected = account.contacts.find((contact) => contact.id === selectedId);
  const messages = account.messages.filter((message) => message.contactId === selectedId).sort((a, b) => a.sentAt - b.sentAt);
  const filtered = account.contacts.filter((contact) => contact.status !== "blocked" && (contact.localName ?? contact.displayName).toLowerCase().includes(search.toLowerCase()));
  const requests = filtered.filter((contact) => contact.status === "request");
  const conversations = filtered.filter((contact) => contact.status !== "request");

  useEffect(() => {
    let cancelled = false;
    void serverInfo(ownServer).then(async (info) => {
      if (cancelled) return;
      const advertised = advertisedOrigins(info, accountRef.current.onionOrigin);
      const current = accountRef.current;
      if (current.onionOrigin === advertised.onionOrigin && current.httpsOrigin === advertised.httpsOrigin) return;
      await runExclusive(async () => {
        let next = structuredClone(accountRef.current); next.onionOrigin = advertised.onionOrigin; next.httpsOrigin = advertised.httpsOrigin;
        await persist(next);
        // Existing contacts learned our old gateway inside an authenticated MLS
        // profile. Send a fresh, encrypted reply target so they can replace it
        // without trusting an unsigned contact-invitation update.
        for (const existing of [...next.contacts]) {
          if (!existing.mlsGroupId || existing.status === "blocked") continue;
          const replacementCapability = randomCapability();
          let replacementId = "";
          try {
            replacementId = (await createDepositCapability(ownServer, next.adminCapability, await capabilityVerifier("deposit", replacementCapability))).capability_id;
            const replyInvitation = formatContactInvitation({ onion_url: next.onionOrigin, https_url: next.httpsOrigin, deposit_capability: replacementCapability }, next.identityPublicKey, crypto.randomUUID());
            const content: SecureContent = { version: 1, type: "profile", messageId: crypto.randomUUID(), sentAt: Date.now(), senderIdentity: next.identityPublicKey, displayName: next.displayName, replyInvitation };
            const encrypted = await mlsCreateMessage(next.mlsClientState, existing.mlsGroupId, await encodeSecureContent(content));
            next = structuredClone(accountRef.current); next.mlsClientState = encrypted.client_state; await persist(next);
            await depositEnvelope(existing.target, envelopeForPacket({ kind: "mls", hint: await mlsGroupHint(existing.mlsGroupId), message: encrypted.message }));
            const updated = structuredClone(accountRef.current); const contact = updated.contacts.find((item) => item.id === existing.id);
            if (contact) { const previousId = contact.inboundCapabilityId; contact.inboundCapabilityId = replacementId; await persist(updated); if (previousId) await revokeDepositCapability(ownServer, updated.adminCapability, previousId).catch(() => undefined); }
            next = accountRef.current;
          } catch {
            if (replacementId) await revokeDepositCapability(ownServer, accountRef.current.adminCapability, replacementId).catch(() => undefined);
          }
        }
      });
      await queueMirrorSnapshot();
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [ownServer, persist, queueMirrorSnapshot, runExclusive]);

  useEffect(() => {
    if (!accountRef.current.pendingReadCapability || resumedPendingRotation.current) return; resumedPendingRotation.current = true;
    void runExclusive(async () => {
      const current = accountRef.current; const pending = current.pendingReadCapability; if (!pending) return;
      const link = current.companionLink;
      await rotateReadCapability(ownServer, current.adminCapability, await capabilityVerifier("read", pending));
      let next = structuredClone(accountRef.current); next.readCapability = pending; await persist(next);
      if (link) { await revokeDepositCapability(ownServer, next.adminCapability, link.downlinkCapId); await revokeDepositCapability(ownServer, next.adminCapability, link.uplinkCapId); }
      next = structuredClone(accountRef.current); next.pendingReadCapability = undefined; next.companionLink = undefined; await persist(next);
    }).catch(() => undefined);
  }, [ownServer, persist, runExclusive]);

  useEffect(() => {
    const onlineHandler = () => setOnline(true); const offlineHandler = () => setOnline(false);
    window.addEventListener("online", onlineHandler); window.addEventListener("offline", offlineHandler);
    return () => { window.removeEventListener("online", onlineHandler); window.removeEventListener("offline", offlineHandler); };
  }, []);

  // Advances the MLS ratchet — callers must already be inside a runExclusive task.
  const sendReceipt = useCallback(async (state: AccountState, contact: ContactRecord, messageId: string) => {
    if (!contact.mlsGroupId) return;
    const content: SecureContent = { version: 1, type: "delivery_receipt", messageId: crypto.randomUUID(), sentAt: Date.now(), senderIdentity: state.identityPublicKey, deliveredIds: [messageId] };
    const encrypted = await mlsCreateMessage(state.mlsClientState, contact.mlsGroupId, await encodeSecureContent(content));
    state.mlsClientState = encrypted.client_state;
    await persist(structuredClone(state));
    await depositEnvelope(contact.target, envelopeForPacket({ kind: "mls", hint: await mlsGroupHint(contact.mlsGroupId), message: encrypted.message }));
  }, [persist]);

  // Multi-device receive/send loop: every MLS operation runs against the shared
  // CAS blob via mutateState. Structurally mirrors the legacy poll below, minus
  // the companion downlink (multi-device and companion linking are exclusive).
  const pollShared = useCallback(async () => {
    const base = accountRef.current;
    const readOrigin = ownOrigin(base.onionOrigin, base.httpsOrigin);

    // 1. Drain the outbox: deposit queued envelopes (idempotent), then mark them
    // accepted in the shared state. Reads from the local cache, which mirrors the
    // last committed shared state.
    await runExclusive(async () => {
      const queued = accountRef.current.messages.filter((message) => message.direction === "outgoing" && message.delivery === "queued" && message.pendingEnvelope);
      const deposited: string[] = [];
      for (const message of queued) {
        const contact = accountRef.current.contacts.find((item) => item.id === message.contactId);
        if (!contact || !message.pendingEnvelope) continue;
        try { await depositEnvelope(contact.target, message.pendingEnvelope); deposited.push(message.id); } catch { /* retried next poll */ }
      }
      if (deposited.length) {
        await mutateState(async (shared) => {
          for (const id of deposited) { const message = shared.messages.find((item) => item.id === id); if (message) { message.delivery = "server-accepted"; message.pendingEnvelope = undefined; } }
          return { changed: true, value: undefined };
        });
      }
    });

    // 2. Receive: pull, process each inbound envelope through the shared ratchet,
    // ack only after the resulting state commits.
    const pulled = await pullEnvelopes(readOrigin, base.readCapability);
    if (pulled.length) {
      const receipts = await runExclusive(() => mutateState(async (shared) => {
        const acknowledged: string[] = [];
        const gathered: Array<{ contactId: string; messageId: string }> = [];
        let changed = false;
        for (const envelope of pulled) {
          try {
            const packet = packetFromEnvelope(envelope.ciphertext);
            if (packet.kind === "mls_bootstrap") {
              const opened = await mlsJoin(shared.mlsClientState, packet.welcome, packet.firstMessage);
              const content = await decodeSecureContent(opened.first_payload);
              if (content.senderIdentity !== opened.peer_identity || !content.replyInvitation) throw new Error("The MLS credential does not match the profile card.");
              const reply = parseContactInvitation(content.replyInvitation);
              if (reply.identityPublicKey !== opened.peer_identity) throw new Error("The reply identity does not match the MLS credential.");
              shared.mlsClientState = opened.client_state;
              shared.availableKeyPackages = Math.max(0, shared.availableKeyPackages - 1);
              let contact = shared.contacts.find((item) => item.identityPublicKey === opened.peer_identity);
              if (!contact) {
                contact = { id: crypto.randomUUID(), identityPublicKey: opened.peer_identity, displayName: content.displayName ?? "New contact", status: "request", verified: false, unread: 1, target: { onion_url: reply.onionOrigin, https_url: reply.httpsOrigin, deposit_capability: reply.capability }, mlsGroupId: opened.group_id, inboundCapabilityId: envelope.deposit_capability_id, lastMessageAt: content.sentAt };
                shared.contacts.push(contact);
              } else {
                contact.mlsGroupId = opened.group_id;
                contact.target = { onion_url: reply.onionOrigin, https_url: reply.httpsOrigin, deposit_capability: reply.capability };
                contact.inboundCapabilityId = envelope.deposit_capability_id;
                if (content.displayName) contact.displayName = content.displayName.slice(0, 64);
              }
              if (content.body && !shared.messages.some((message) => message.id === content.messageId)) {
                shared.messages.push({ id: content.messageId, contactId: contact.id, direction: "incoming", body: content.body, sentAt: content.sentAt, delivery: "delivered" });
                gathered.push({ contactId: contact.id, messageId: content.messageId });
              }
              changed = true;
            } else if (packet.kind === "mls") {
              const hints = await Promise.all(shared.contacts.map(async (contact) => ({ contact, hint: contact.mlsGroupId ? await mlsGroupHint(contact.mlsGroupId) : "" })));
              const contact = hints.find((item) => item.hint === packet.hint)?.contact;
              if (!contact?.mlsGroupId) throw new Error("No local MLS group can decrypt this envelope.");
              contact.inboundCapabilityId = envelope.deposit_capability_id;
              const opened = await mlsProcessMessage(shared.mlsClientState, contact.mlsGroupId, packet.message);
              const content = await decodeSecureContent(opened.payload);
              if (content.senderIdentity !== contact.identityPublicKey) throw new Error("The sender identity does not match the MLS credential.");
              shared.mlsClientState = opened.client_state;
              if (content.type === "text" && content.body && !shared.messages.some((message) => message.id === content.messageId)) {
                shared.messages.push({ id: content.messageId, contactId: contact.id, direction: "incoming", body: content.body, sentAt: content.sentAt, delivery: "delivered" });
                contact.lastMessageAt = content.sentAt; if (contact.id !== selectedId) contact.unread += 1;
                gathered.push({ contactId: contact.id, messageId: content.messageId });
              } else if (content.type === "delivery_receipt") {
                for (const id of content.deliveredIds ?? []) { const message = shared.messages.find((item) => item.id === id); if (message) message.delivery = "delivered"; }
              } else if (content.type === "profile" && content.displayName) {
                contact.displayName = content.displayName.slice(0, 64);
                if (content.replyInvitation) { const reply = parseContactInvitation(content.replyInvitation); if (reply.identityPublicKey === contact.identityPublicKey) contact.target = { onion_url: reply.onionOrigin, https_url: reply.httpsOrigin, deposit_capability: reply.capability }; }
              }
              changed = true;
            } else {
              throw new Error("Legacy transport packets are not accepted by this private-alpha client.");
            }
            acknowledged.push(envelope.acknowledgement_token);
          } catch {
            acknowledged.push(envelope.acknowledgement_token);
          }
        }
        const deferred = async () => { if (acknowledged.length) await acknowledgeEnvelopes(readOrigin, base.readCapability, acknowledged); };
        return { changed, deferred, value: gathered };
      }));

      // 3. Send a delivery receipt per newly received message (each advances the
      // ratchet, so each is its own committed mutation).
      for (const receipt of receipts) {
        await runExclusive(() => mutateState(async (shared) => {
          const contact = shared.contacts.find((item) => item.id === receipt.contactId);
          if (!contact?.mlsGroupId) return { changed: false, value: undefined };
          const content: SecureContent = { version: 1, type: "delivery_receipt", messageId: crypto.randomUUID(), sentAt: Date.now(), senderIdentity: shared.identityPublicKey, deliveredIds: [receipt.messageId] };
          const encrypted = await mlsCreateMessage(shared.mlsClientState, contact.mlsGroupId, await encodeSecureContent(content));
          shared.mlsClientState = encrypted.client_state;
          const envelope = envelopeForPacket({ kind: "mls", hint: await mlsGroupHint(contact.mlsGroupId), message: encrypted.message });
          const target = { ...contact.target };
          return { changed: true, deferred: async () => { await depositEnvelope(target, envelope).catch(() => undefined); }, value: undefined };
        })).catch(() => undefined);
      }
    }

    // 4. Replenish key packages when the pool runs low.
    await runExclusive(() => mutateState(async (shared) => {
      if (shared.availableKeyPackages >= 5) return { changed: false, value: undefined };
      const generated = await mlsReplenish(shared.mlsClientState, 20 - shared.availableKeyPackages);
      shared.mlsClientState = generated.client_state; shared.availableKeyPackages = 20;
      const identity = shared.identityPublicKey;
      const adminCapability = accountRef.current.adminCapability;
      return { changed: true, deferred: async () => { await publishKeyPackages(readOrigin, adminCapability, wirePackages(generated.key_packages, identity)); }, value: undefined };
    }));
  }, [mutateState, runExclusive, selectedId]);

  const poll = useCallback(async () => {
    if (!navigator.onLine || syncing.current) return;
    syncing.current = true;
    try {
      if (accountRef.current.rootSecret !== undefined && accountRef.current.mlsStateVersion !== undefined) {
        await pollShared();
        syncFailures.current = 0;
        return;
      }
      await runExclusive(async () => {
      let current = structuredClone(accountRef.current);
      if (current.companionLink?.active && current.companionLink.downlinkOutbox.length) {
        const target: DepositTarget = { onion_url: current.onionOrigin, https_url: current.httpsOrigin, deposit_capability: current.companionLink.downlinkCap };
        const remaining: PendingEnvelope[] = [];
        for (const [index, envelope] of current.companionLink.downlinkOutbox.entries()) {
          try { await depositEnvelope(target, envelope); }
          catch { remaining.push(...current.companionLink.downlinkOutbox.slice(index)); break; }
        }
        current.companionLink.downlinkOutbox = remaining;
        await persist(current);
      }
      let outboxChanged = false;
      for (const message of current.messages.filter((item) => item.direction === "outgoing" && item.delivery === "queued" && item.pendingEnvelope)) {
        const contact = current.contacts.find((item) => item.id === message.contactId);
        if (!contact || !message.pendingEnvelope) continue;
        try {
          await depositEnvelope(contact.target, message.pendingEnvelope);
          message.delivery = "server-accepted"; message.pendingEnvelope = undefined; message.error = undefined;
        } catch (cause) {
          message.delivery = "failed"; message.error = errorMessage(cause, "Send failed");
        }
        outboxChanged = true;
      }
      if (outboxChanged) await persist(current);
      const pulled = await pullEnvelopes(ownOrigin(current.onionOrigin, current.httpsOrigin), current.readCapability);
      if (!pulled.length) { syncFailures.current = 0; return; }
      let next = structuredClone(current);
      const acknowledged: string[] = [];
      const receipts: Array<{ contactId: string; messageId: string }> = [];
      let mirrorChanged = false;
      const pruneDownlinks = Boolean(next.companionLink?.active && pulled.filter((envelope) => envelope.deposit_capability_id === next.companionLink?.downlinkCapId).length >= 80);
      for (const envelope of pulled) {
        const disposition = classify(envelope.deposit_capability_id, "primary", next.companionLink);
        if (disposition.action === "skip") { if (pruneDownlinks) { acknowledged.push(envelope.acknowledgement_token); mirrorChanged = true; } continue; }
        try {
          const packet = packetFromEnvelope(envelope.ciphertext);
          if (disposition.action === "applyUplink") {
            if (!next.companionLink?.active || packet.kind !== "link" || packet.dir !== "up" || packet.pid !== next.companionLink.pairingId) throw new Error("Invalid companion uplink.");
            if (packet.seq <= next.companionLink.upLastApplied) { acknowledged.push(envelope.acknowledgement_token); continue; }
            const command = await openLinkEvent<UplinkCommand>(next.companionLink.linkSecret, packet);
            next.companionLink.upLastApplied = packet.seq; next.companionLink.lastUplinkAt = Date.now(); mirrorChanged = true;
            if (command.type === "hello") { next.companionLink.confirmedAt = Date.now(); next.companionLink.label = command.label; }
            else if (command.type === "send_text" && !next.messages.some((message) => message.id === command.commandId)) {
              const contact = next.contacts.find((item) => item.id === command.contactId);
              if (!contact?.mlsGroupId) throw new Error("Companion selected an unavailable conversation.");
              const content: SecureContent = { version: 1, type: "text", messageId: command.commandId, sentAt: command.clientSentAt, senderIdentity: next.identityPublicKey, body: command.body.slice(0, 16_384) };
              const encrypted = await mlsCreateMessage(next.mlsClientState, contact.mlsGroupId, await encodeSecureContent(content));
              const pendingEnvelope = envelopeForPacket({ kind: "mls", hint: await mlsGroupHint(contact.mlsGroupId), message: encrypted.message });
              next.mlsClientState = encrypted.client_state; next.messages.push({ id: command.commandId, contactId: contact.id, direction: "outgoing", body: content.body!, sentAt: content.sentAt, delivery: "queued", pendingEnvelope });
              try { await depositEnvelope(contact.target, pendingEnvelope); const sent = next.messages.find((item) => item.id === command.commandId)!; sent.delivery = "server-accepted"; sent.pendingEnvelope = undefined; }
              catch (cause) { const failed = next.messages.find((item) => item.id === command.commandId)!; failed.delivery = "failed"; failed.error = errorMessage(cause, "Relay failed"); }
            } else if (command.type === "retry_message") {
              const message = next.messages.find((item) => item.id === command.messageId && item.direction === "outgoing");
              const contact = message && next.contacts.find((item) => item.id === message.contactId);
              if (!message?.pendingEnvelope || !contact) throw new Error("The encrypted relay record is unavailable.");
              try { await depositEnvelope(contact.target, message.pendingEnvelope); message.delivery = "server-accepted"; message.pendingEnvelope = undefined; message.error = undefined; }
              catch (cause) { message.delivery = "failed"; message.error = errorMessage(cause, "Relay retry failed"); }
            } else if (command.type === "accept_request") { const contact = next.contacts.find((item) => item.id === command.contactId); if (contact) contact.status = "accepted"; }
            else if (command.type === "block_contact") { const contact = next.contacts.find((item) => item.id === command.contactId); if (contact) { contact.status = "blocked"; if (contact.inboundCapabilityId) await revokeDepositCapability(ownServer, next.adminCapability, contact.inboundCapabilityId); } }
            else if (command.type === "set_verified") { const contact = next.contacts.find((item) => item.id === command.contactId); if (contact) contact.verified = true; }
            else if (command.type === "set_nickname") { const contact = next.contacts.find((item) => item.id === command.contactId); if (contact) contact.localName = command.name.slice(0, 64) || undefined; }
            else if (command.type === "mark_read") { const contact = next.contacts.find((item) => item.id === command.contactId); if (contact) contact.unread = 0; }
          } else if (packet.kind === "mls_bootstrap") {
            const opened = await mlsJoin(next.mlsClientState, packet.welcome, packet.firstMessage);
            const content = await decodeSecureContent(opened.first_payload);
            if (content.senderIdentity !== opened.peer_identity || !content.replyInvitation) throw new Error("The MLS credential does not match the profile card.");
            const reply = parseContactInvitation(content.replyInvitation);
            if (reply.identityPublicKey !== opened.peer_identity) throw new Error("The reply identity does not match the MLS credential.");
            next.mlsClientState = opened.client_state;
            next.availableKeyPackages = Math.max(0, next.availableKeyPackages - 1);
            let contact = next.contacts.find((item) => item.identityPublicKey === opened.peer_identity);
            if (!contact) {
              contact = { id: crypto.randomUUID(), identityPublicKey: opened.peer_identity, displayName: content.displayName ?? "New contact", status: "request", verified: false, unread: 1, draft: "", target: { onion_url: reply.onionOrigin, https_url: reply.httpsOrigin, deposit_capability: reply.capability }, mlsGroupId: opened.group_id, inboundCapabilityId: envelope.deposit_capability_id, lastMessageAt: content.sentAt };
              next.contacts.push(contact);
            } else {
              contact.mlsGroupId = opened.group_id;
              contact.target = { onion_url: reply.onionOrigin, https_url: reply.httpsOrigin, deposit_capability: reply.capability };
              contact.inboundCapabilityId = envelope.deposit_capability_id;
              if (content.displayName) contact.displayName = content.displayName.slice(0, 64);
              if (content.type === "session_reset" && !next.messages.some((message) => message.id === content.messageId)) next.messages.push({ id: content.messageId, contactId: contact.id, direction: "system", body: "Security session refreshed after recovery.", sentAt: content.sentAt, delivery: "delivered" });
            }
            if (content.body && !next.messages.some((message) => message.id === content.messageId)) {
              next.messages.push({ id: content.messageId, contactId: contact.id, direction: "incoming", body: content.body, sentAt: content.sentAt, delivery: "delivered" });
              receipts.push({ contactId: contact.id, messageId: content.messageId });
            }
          } else if (packet.kind === "mls") {
            const hints = await Promise.all(next.contacts.map(async (contact) => ({ contact, hint: contact.mlsGroupId ? await mlsGroupHint(contact.mlsGroupId) : "" })));
            const contact = hints.find((item) => item.hint === packet.hint)?.contact;
            if (!contact?.mlsGroupId) throw new Error("No local MLS group can decrypt this envelope.");
            contact.inboundCapabilityId = envelope.deposit_capability_id;
            const opened = await mlsProcessMessage(next.mlsClientState, contact.mlsGroupId, packet.message);
            const content = await decodeSecureContent(opened.payload);
            if (content.senderIdentity !== contact.identityPublicKey) throw new Error("The sender identity does not match the MLS credential.");
            next.mlsClientState = opened.client_state;
            if (content.type === "text" && content.body && !next.messages.some((message) => message.id === content.messageId)) {
              next.messages.push({ id: content.messageId, contactId: contact.id, direction: "incoming", body: content.body, sentAt: content.sentAt, delivery: "delivered" });
              contact.lastMessageAt = content.sentAt; if (contact.id !== selectedId) contact.unread += 1;
              receipts.push({ contactId: contact.id, messageId: content.messageId });
              mirrorChanged = true;
            } else if (content.type === "delivery_receipt") {
              for (const id of content.deliveredIds ?? []) { const message = next.messages.find((item) => item.id === id); if (message) message.delivery = "delivered"; }
            } else if (content.type === "profile" && content.displayName) {
              contact.displayName = content.displayName.slice(0, 64);
              if (content.replyInvitation) {
                const reply = parseContactInvitation(content.replyInvitation);
                if (reply.identityPublicKey !== contact.identityPublicKey) throw new Error("The refreshed reply target does not match the MLS identity.");
                contact.target = { onion_url: reply.onionOrigin, https_url: reply.httpsOrigin, deposit_capability: reply.capability };
              }
            }
          } else {
            throw new Error("Legacy transport packets are not accepted by this private-alpha client.");
          }
          acknowledged.push(envelope.acknowledgement_token);
        } catch {
          // Malformed or undecryptable envelopes are terminal for this client.
          // Delete them so one abusive deposit capability cannot pin the queue.
          acknowledged.push(envelope.acknowledgement_token);
        }
      }
      if (next.availableKeyPackages < 5) {
        const generated = await mlsReplenish(next.mlsClientState, 20 - next.availableKeyPackages);
        next.mlsClientState = generated.client_state;
        await publishKeyPackages(ownOrigin(next.onionOrigin, next.httpsOrigin), next.adminCapability, wirePackages(generated.key_packages, next.identityPublicKey));
        next.availableKeyPackages = 20;
      }
      if (next.companionLink?.active && (mirrorChanged || acknowledged.length)) {
        next.companionLink.downSeq += 1;
        await persist(next);
        const event: DownlinkEvent = { type: "snapshot", eventId: crypto.randomUUID(), ts: Date.now(), payload: buildSnapshot(next) };
        const packet = await sealLinkEvent(next.companionLink.linkSecret, next.companionLink.pairingId, "down", next.companionLink.downSeq, event);
        next = structuredClone(accountRef.current);
        const outbox = next.companionLink!.downlinkOutbox;
        if (outbox.length >= 200) outbox.splice(0, outbox.length);
        outbox.push(envelopeForPacket(packet));
      }
      if (acknowledged.length) {
        await persist(next);
        await acknowledgeEnvelopes(ownOrigin(next.onionOrigin, next.httpsOrigin), next.readCapability, acknowledged);
        for (const receipt of receipts) {
          const contact = next.contacts.find((item) => item.id === receipt.contactId);
          if (contact) await sendReceipt(next, contact, receipt.messageId).catch(() => undefined);
        }
      }
      });
      syncFailures.current = 0;
    } catch (cause) {
      syncFailures.current += 1;
      const message = errorMessage(cause, "Mailbox sync failed.");
      if (message === "Tor is not ready. Blackspace will not use a direct connection.") return;
      if (navigator.onLine && syncFailures.current >= 3) setError(message);
    }
    finally { syncing.current = false; }
  }, [persist, selectedId, sendReceipt, runExclusive, pollShared]);

  useEffect(() => { void poll(); const timer = window.setInterval(() => void poll(), 5_000); return () => clearInterval(timer); }, [poll]);
  useEffect(() => { if (dialog === "settings") void refreshDevices(); }, [dialog, refreshDevices]);

  const selectContact = async (contact: ContactRecord) => {
    setSelectedId(contact.id); setMobileList(false);
    if (contact.unread) await runExclusive(() => mutateState(async (shared) => { const match = shared.contacts.find((item) => item.id === contact.id); if (match) match.unread = 0; return { changed: Boolean(match), value: undefined }; }));
  };

  const makeInvite = async () => {
    setBusy(true); setError("");
    try {
      const info = await serverInfo(ownServer);
      const advertised = advertisedOrigins(info, accountRef.current.onionOrigin);
      let current = accountRef.current;
      if (current.onionOrigin !== advertised.onionOrigin || current.httpsOrigin !== advertised.httpsOrigin) {
        current = await runExclusive(async () => { const next = structuredClone(accountRef.current); next.onionOrigin = advertised.onionOrigin; next.httpsOrigin = advertised.httpsOrigin; await persist(next); return next; });
      }
      const capability = randomCapability();
      await createDepositCapability(ownServer, current.adminCapability, await capabilityVerifier("deposit", capability));
      const value = formatContactInvitation({ onion_url: current.onionOrigin, https_url: current.httpsOrigin, deposit_capability: capability }, current.identityPublicKey, crypto.randomUUID());
      setInviteValue(value); setInviteQr(await QRCode.toDataURL(value, { width: 768, margin: 4, errorCorrectionLevel: "L", color: { dark: "#17121f", light: "#ffffff" } })); setDialog("invite");
    } catch (cause) { setError(errorMessage(cause, "Could not create an invitation.")); }
    finally { setBusy(false); }
  };

  const prepareDeviceLink = async (offerCode: string) => {
    if (accountRef.current.companionLink?.active) throw new Error("Unlink the existing companion before linking another.");
    const base = accountRef.current;
    const linkSecret = randomCapability(); const downlinkCap = randomCapability(); const uplinkCap = randomCapability();
    let downlinkCapId = ""; let uplinkCapId = "";
    try {
      downlinkCapId = (await createDepositCapability(ownServer, base.adminCapability, await capabilityVerifier("deposit", downlinkCap))).capability_id;
      uplinkCapId = (await createDepositCapability(ownServer, base.adminCapability, await capabilityVerifier("deposit", uplinkCap))).capability_id;
      const bundle: PairingBundle = { readCapability: base.readCapability, downlinkCap, downlinkCapId, uplinkCap, uplinkCapId, linkSecret, onionOrigin: base.onionOrigin, httpsOrigin: base.httpsOrigin, identityPublicKey: base.identityPublicKey, displayName: base.displayName, instanceName: base.instanceName };
      const response = await createPrimaryPairingResponse(offerCode, bundle);
      setLinkSetup({ pairingId: response.pairingId, qr: response.qr, qrImage: await pairingQrImage(response.qr), sas: response.sas, linkSecret, downlinkCap, downlinkCapId, uplinkCapId });
    } catch (cause) {
      if (downlinkCapId) await revokeDepositCapability(ownServer, base.adminCapability, downlinkCapId).catch(() => undefined);
      if (uplinkCapId) await revokeDepositCapability(ownServer, base.adminCapability, uplinkCapId).catch(() => undefined);
      throw cause;
    }
  };

  const confirmDeviceLink = async () => {
    if (!linkSetup) return;
    await runExclusive(async () => {
      let next = structuredClone(accountRef.current);
      next.companionLink = { pairingId: linkSetup.pairingId, active: true, createdAt: Date.now(), linkSecret: linkSetup.linkSecret, downlinkCap: linkSetup.downlinkCap, downlinkCapId: linkSetup.downlinkCapId, uplinkCapId: linkSetup.uplinkCapId, downSeq: 1, upLastApplied: 0, downlinkOutbox: [] };
      // Persist the sequence before using it as an AEAD nonce.
      await persist(next);
      const event: DownlinkEvent = { type: "snapshot", eventId: crypto.randomUUID(), ts: Date.now(), payload: buildSnapshot(next) };
      const packet = await sealLinkEvent(next.companionLink.linkSecret, next.companionLink.pairingId, "down", next.companionLink.downSeq, event);
      next = structuredClone(accountRef.current); next.companionLink!.downlinkOutbox.push(envelopeForPacket(packet)); await persist(next);
    });
    setLinkSetup(undefined); setSettingsSection("devices"); setDialog("settings");
  };

  const cancelDeviceLink = async () => {
    if (linkSetup) {
      await revokeDepositCapability(ownServer, accountRef.current.adminCapability, linkSetup.downlinkCapId).catch(() => undefined);
      await revokeDepositCapability(ownServer, accountRef.current.adminCapability, linkSetup.uplinkCapId).catch(() => undefined);
    }
    setLinkSetup(undefined); setDialog(null);
  };

  const unlinkDevice = async () => {
    await runExclusive(async () => {
      const base = accountRef.current; const link = base.companionLink; if (!link) return;
      const readCapability = randomCapability();
      let next = structuredClone(base); next.pendingReadCapability = readCapability; await persist(next);
      await rotateReadCapability(ownServer, base.adminCapability, await capabilityVerifier("read", readCapability));
      next = structuredClone(accountRef.current); next.readCapability = readCapability; await persist(next);
      await revokeDepositCapability(ownServer, next.adminCapability, link.downlinkCapId);
      await revokeDepositCapability(ownServer, next.adminCapability, link.uplinkCapId);
      next = structuredClone(accountRef.current); next.pendingReadCapability = undefined; next.companionLink = undefined; await persist(next);
    });
    setDialog(null);
  };

  const addContact = async (value: string, firstMessage: string) => {
    setBusy(true); setError("");
    try {
      const base = accountRef.current;
      const invite = parseContactInvitation(value);
      if (base.contacts.some((contact) => contact.identityPublicKey === invite.identityPublicKey)) throw new Error("This contact is already in your Blackspace.");
      const target: DepositTarget = { onion_url: invite.onionOrigin, https_url: invite.httpsOrigin, deposit_capability: invite.capability };
      // Capability minting and key-package claim don't touch shared MLS state, so
      // they run outside the CAS; only the group bootstrap is inside it.
      const claimed = await claimKeyPackage(target);
      validateClaimedPackage(claimed, invite.identityPublicKey);
      const returnCapability = randomCapability();
      const returnGrant = await createDepositCapability(ownServer, base.adminCapability, await capabilityVerifier("deposit", returnCapability));
      const replyInvitation = formatContactInvitation({ onion_url: base.onionOrigin, https_url: base.httpsOrigin, deposit_capability: returnCapability }, base.identityPublicKey, crypto.randomUUID());
      const messageId = crypto.randomUUID();
      const contactId = crypto.randomUUID();
      await runExclusive(() => mutateState(async (shared) => {
        const content: SecureContent = { version: 1, type: "profile", messageId, sentAt: Date.now(), senderIdentity: shared.identityPublicKey, displayName: shared.displayName, replyInvitation, body: firstMessage.trim() || "Hello — I added you on Blackspace." };
        const bootstrap = await mlsStart(shared.mlsClientState, invite.identityPublicKey, claimed.key_package, await encodeSecureContent(content));
        shared.mlsClientState = bootstrap.client_state;
        const pendingEnvelope = envelopeForPacket({ kind: "mls_bootstrap", welcome: bootstrap.welcome, firstMessage: bootstrap.first_message });
        shared.contacts.push({ id: contactId, identityPublicKey: invite.identityPublicKey, displayName: "New contact", status: "accepted", verified: false, unread: 0, target, mlsGroupId: bootstrap.group_id, inboundCapabilityId: returnGrant.capability_id, lastMessageAt: content.sentAt });
        shared.messages.push({ id: messageId, contactId, direction: "outgoing", body: content.body!, sentAt: content.sentAt, delivery: "queued", pendingEnvelope });
        return { changed: true, value: undefined };
      }));
      setSelectedId(contactId); setDialog(null); setMobileList(false);
      await queueMirrorSnapshot();
      void poll();
    } catch (cause) { setError(errorMessage(cause, "Could not add the contact.")); }
    finally { setBusy(false); }
  };

  const sendMessage = async () => {
    // Synchronous re-entry guard: a laggy send must never fire twice from repeated
    // clicks or Enter presses. Set before any await so the second call bails here.
    if (sendingRef.current) return;
    if (!selected?.mlsGroupId || !selected.draft.trim()) return;
    sendingRef.current = true; setSending(true);
    const body = selected.draft.trim(); const messageId = crypto.randomUUID(); const sentAt = Date.now(); const contactId = selected.id;
    try {
      // Show the message immediately as Queued and clear the draft (both device-local),
      // so it appears the instant you hit send — before any network round-trip.
      const optimistic = structuredClone(accountRef.current);
      const localContact = optimistic.contacts.find((item) => item.id === contactId);
      if (localContact) { localContact.draft = ""; localContact.lastMessageAt = sentAt; }
      optimistic.messages.push({ id: messageId, contactId, direction: "outgoing", body, sentAt, delivery: "queued" });
      await persist(optimistic);
      // Encrypt and commit the ratchet advance + queued envelope to the shared state.
      // The op is idempotent w.r.t. the optimistic message (it attaches the envelope
      // to it when present, else adds it) so the local and multi-device paths agree.
      await runExclusive(async () => {
        await mutateState(async (shared) => {
          const contact = shared.contacts.find((item) => item.id === contactId);
          if (!contact?.mlsGroupId) throw new Error("This conversation is unavailable.");
          const content: SecureContent = { version: 1, type: "text", messageId, sentAt, senderIdentity: shared.identityPublicKey, body };
          const encrypted = await mlsCreateMessage(shared.mlsClientState, contact.mlsGroupId, await encodeSecureContent(content));
          const pendingEnvelope = envelopeForPacket({ kind: "mls", hint: await mlsGroupHint(contact.mlsGroupId), message: encrypted.message });
          shared.mlsClientState = encrypted.client_state; contact.lastMessageAt = sentAt;
          const existing = shared.messages.find((item) => item.id === messageId);
          if (existing) { existing.pendingEnvelope = pendingEnvelope; existing.delivery = "queued"; existing.error = undefined; }
          else shared.messages.push({ id: messageId, contactId, direction: "outgoing", body, sentAt, delivery: "queued", pendingEnvelope });
          return { changed: true, value: undefined };
        });
        await queueMirrorSnapshot();
      });
      void poll();
    } catch (cause) {
      // The optimistic message could not be encrypted/committed; mark it failed so
      // the user can retry rather than leaving it stuck as Queued.
      const failedState = structuredClone(accountRef.current);
      const message = failedState.messages.find((item) => item.id === messageId);
      if (message) { message.delivery = "failed"; message.error = errorMessage(cause, "Send failed"); await persist(failedState); }
      setError(errorMessage(cause, "Send failed"));
    } finally {
      sendingRef.current = false; setSending(false);
    }
  };

  const retryMessage = async (message: MessageRecord) => {
    // Re-queue the failed message inside the lock (re-reading the record, since the
    // render-time prop may be stale), then let the poll's outbox drain redeposit it.
    await runExclusive(() => mutateState(async (shared) => {
      const record = shared.messages.find((item) => item.id === message.id);
      if (!record || record.direction !== "outgoing" || record.delivery !== "failed" || !record.pendingEnvelope) return { changed: false, value: undefined };
      record.delivery = "queued"; record.error = undefined;
      return { changed: true, value: undefined };
    }));
    void poll();
  };

  const updateDraft = (value: string) => {
    const next = structuredClone(account); const contact = next.contacts.find((item) => item.id === selectedId); if (contact) contact.draft = value; setAccount(next);
  };

  const blockContact = async (contactId: string) => {
    const contact = accountRef.current.contacts.find((item) => item.id === contactId);
    if (contact?.inboundCapabilityId) await revokeDepositCapability(ownServer, accountRef.current.adminCapability, contact.inboundCapabilityId);
    const changed = await runExclusive(() => mutateState(async (shared) => {
      const match = shared.contacts.find((item) => item.id === contactId);
      if (!match) return { changed: false, value: false };
      match.status = "blocked";
      return { changed: true, value: true };
    }));
    if (changed) { setSelectedId(""); await queueMirrorSnapshot(); }
  };

  const acceptRequest = async (accepted: boolean) => {
    if (!selected) return;
    if (!accepted) {
      try { await blockContact(selected.id); }
      catch (cause) { setError(errorMessage(cause, "Could not revoke this contact's mailbox access.")); }
      return;
    }
    const contactId = selected.id;
    await runExclusive(() => mutateState(async (shared) => {
      const contact = shared.contacts.find((item) => item.id === contactId); if (!contact) return { changed: false, value: undefined };
      contact.status = "accepted";
      if (!contact.mlsGroupId) return { changed: true, value: undefined };
      const content: SecureContent = { version: 1, type: "profile", messageId: crypto.randomUUID(), sentAt: Date.now(), senderIdentity: shared.identityPublicKey, displayName: shared.displayName };
      const encrypted = await mlsCreateMessage(shared.mlsClientState, contact.mlsGroupId, await encodeSecureContent(content));
      shared.mlsClientState = encrypted.client_state;
      const envelope = envelopeForPacket({ kind: "mls", hint: await mlsGroupHint(contact.mlsGroupId), message: encrypted.message });
      const target = { ...contact.target };
      return { changed: true, deferred: async () => { await depositEnvelope(target, envelope).catch((cause) => setError(errorMessage(cause, "The contact was accepted, but your profile could not be sent."))); }, value: undefined };
    }));
    await queueMirrorSnapshot();
  };

  const updateDisplayName = async (value: string) => {
    const displayName = value.trim();
    if (displayName.length < 2 || displayName.length > 64) throw new Error("Choose a display name between 2 and 64 characters.");
    await runExclusive(() => mutateState(async (shared) => {
      if (shared.displayName === displayName) return { changed: false, value: undefined };
      shared.displayName = displayName;
      const updates: Array<{ target: DepositTarget; envelope: ReturnType<typeof envelopeForPacket> }> = [];
      for (const contact of shared.contacts) {
        if (contact.status !== "accepted" || !contact.mlsGroupId) continue;
        const content: SecureContent = { version: 1, type: "profile", messageId: crypto.randomUUID(), sentAt: Date.now(), senderIdentity: shared.identityPublicKey, displayName };
        const encrypted = await mlsCreateMessage(shared.mlsClientState, contact.mlsGroupId, await encodeSecureContent(content));
        shared.mlsClientState = encrypted.client_state;
        updates.push({ target: { ...contact.target }, envelope: envelopeForPacket({ kind: "mls", hint: await mlsGroupHint(contact.mlsGroupId), message: encrypted.message }) });
      }
      return {
        changed: true,
        deferred: async () => {
          let failures = 0;
          await Promise.all(updates.map(({ target, envelope }) => depositEnvelope(target, envelope).catch(() => { failures += 1; })));
          if (failures) setError(`Your display name was saved, but ${failures} contact update${failures === 1 ? "" : "s"} could not be delivered yet.`);
        },
        value: undefined,
      };
    }));
    await queueMirrorSnapshot();
  };

  const clearHistory = async () => {
    const count = accountRef.current.messages.length;
    if (!count || !confirm(`Clear ${count} message${count === 1 ? "" : "s"} from this account's synchronized history? Other people may still retain their copies.`)) return;
    await runExclusive(() => mutateState(async (shared) => {
      if (!shared.messages.length) return { changed: false, value: undefined };
      shared.messages = [];
      return { changed: true, value: undefined };
    }));
    await queueMirrorSnapshot();
  };

  const clearDrafts = async () => {
    const count = accountRef.current.contacts.filter((contact) => contact.draft).length;
    if (!count || !confirm(`Clear ${count} saved draft${count === 1 ? "" : "s"} from this device?`)) return;
    const next = structuredClone(accountRef.current);
    for (const contact of next.contacts) contact.draft = "";
    await persist(next);
  };

  const exportRecovery = async () => {
    const recoveryPassphrase = prompt("Choose a separate recovery-kit passphrase (at least 10 characters; this is not your local vault passphrase):"); if (!recoveryPassphrase) return;
    if (recoveryPassphrase.length < 10) { setError("Use at least 10 characters for the recovery-kit passphrase."); return; }
    const recoveryConfirmation = prompt("Confirm the recovery-kit passphrase:");
    if (recoveryConfirmation !== recoveryPassphrase) { setError("The recovery-kit passphrases do not match."); return; }
    try {
      const recoveryState = structuredClone(account);
      recoveryState.mlsClientState = await mlsRecoveryIdentitySnapshot(account.mlsClientState);
      recoveryState.availableKeyPackages = 0;
      for (const contact of recoveryState.contacts) contact.mlsGroupId = undefined;
      for (const message of recoveryState.messages) {
        message.pendingEnvelope = undefined;
        if (message.delivery === "queued") message.delivery = "failed";
      }
      const kit = await createRecoveryKit(recoveryState, recoveryPassphrase);
      const kitBuffer = new ArrayBuffer(kit.byteLength); new Uint8Array(kitBuffer).set(kit);
      const url = URL.createObjectURL(new Blob([kitBuffer], { type: "application/blackspace-recovery" }));
      const anchor = document.createElement("a"); anchor.href = url; anchor.download = `blackspace-${account.displayName.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-")}.blackspace-recovery`; anchor.click(); URL.revokeObjectURL(url);
    } catch (cause) { setError(errorMessage(cause, "Recovery export failed.")); }
  };

  const transportMode = deriveTransportMode(window.location);
  return <main className="workspace">
    {!online && <div className="offline-banner"><CircleAlert size={14} /> Offline — messages remain queued until Blackspace reconnects.</div>}
    <aside className="server-rail">
      <button className="server-tile active" aria-label="Blackspace home"><MessageCircle /></button>
      <button className="server-tile" aria-label={account.companionLink?.active ? "Unlink companion" : "Link companion"} onClick={() => account.companionLink?.active ? void unlinkDevice().catch((cause) => setError(errorMessage(cause, "Could not unlink this device."))) : setDialog("link")}><Users /></button>
      <span className="rail-spacer" /><button className="avatar small" onClick={() => openSettings()}>{initials(account.displayName)}</button>
    </aside>
    <aside className={`conversation-sidebar ${mobileList ? "mobile-visible" : ""}`}>
      <header className="workspace-header"><div><span className="eyebrow">PRIVATE WORKSPACE</span><h1>{account.instanceName}</h1></div><button className="icon-button" onClick={() => openSettings()}><Settings /></button></header>
      <div className="search-box"><Search /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search conversations" /></div>
      <nav className="primary-nav"><div className="active"><MessageCircle /> Direct messages <span>{conversations.reduce((sum, contact) => sum + contact.unread, 0) || ""}</span></div><div><Inbox /> Message requests <span>{requests.length || ""}</span></div></nav>
      {requests.length > 0 && <ContactSection title="Requests" contacts={requests} selectedId={selectedId} onSelect={selectContact} />}
      <ContactSection title="Direct messages" contacts={conversations} selectedId={selectedId} onSelect={selectContact} />
      {!filtered.length && <div className="sidebar-empty"><Users /><p>No conversations yet.</p></div>}
      <div className="sidebar-actions"><button className="secondary" onClick={() => setDialog("add")}><UserPlus /> Add contact</button><button className="icon-button" onClick={makeInvite} disabled={busy} title="Create invitation"><Plus /></button></div>
      <footer><ModeBadge /><button className="network-status" onClick={() => openSettings("network")} title="Open network settings"><span className={`network-dot ${online ? "online" : ""}`} />{online ? "Connected" : "Offline"}</button></footer>
    </aside>
    <section className={`chat-panel ${!mobileList ? "mobile-visible" : ""}`}>
      {selected ? <>
        <header className="chat-header"><button className="icon-button mobile-back" onClick={() => setMobileList(true)}><ArrowLeft /></button><div className="avatar">{initials(selected.localName ?? selected.displayName)}</div><div><h2>{selected.localName ?? selected.displayName}</h2><p>{selected.verified ? <><ShieldCheck size={13} /> Identity verified</> : "Identity not verified"}</p></div><span className="chat-spacer" /><button className="icon-button" onClick={() => setDialog("security")}><Fingerprint /></button></header>
        {selected.status === "request" && <div className="request-banner"><div><strong>New message request</strong><span>Review the message and verify this contact before sharing sensitive information.</span></div><button className="secondary" onClick={() => acceptRequest(false)}>Block</button><button className="primary" onClick={() => acceptRequest(true)}>Accept</button></div>}
        <div className="message-scroll">
          <div className="conversation-start"><div className="avatar hero-avatar">{initials(selected.displayName)}</div><h2>{selected.displayName}</h2><p>This is the beginning of your private Blackspace conversation.</p><button className="text-button" onClick={() => setDialog("security")}><Fingerprint /> Verify identity</button></div>
          {messages.map((message, index) => <MessageItem key={message.id} message={message} previous={messages[index - 1]} contact={selected} onRetry={retryMessage} />)}
        </div>
        <div className="composer-wrap"><div className="composer"><textarea value={selected.draft} onChange={(event) => updateDraft(event.target.value)} onBlur={() => void persist(accountRef.current)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void sendMessage(); } }} maxLength={16_384} placeholder={`Message ${selected.localName ?? selected.displayName}`} rows={1} disabled={selected.status === "request"} /><span>{selected.draft.length > 14_000 ? `${selected.draft.length}/16384` : "Enter to send"}</span><button className="send-button" onClick={sendMessage} disabled={!selected.draft.trim() || selected.status === "request" || sending}><Send /></button></div></div>
      </> : <EmptyChat onAdd={() => setDialog("add")} onInvite={makeInvite} />}
    </section>
    {dialog === "add" && <AddContactModal busy={busy} onAdd={addContact} onClose={() => setDialog(null)} />}
    {dialog === "invite" && <InviteModal value={inviteValue} qr={inviteQr} onClose={() => setDialog(null)} />}
    {dialog === "settings" && <SettingsModal account={account} mode={transportMode ? modeLabel(transportMode) : "Blocked"} online={online} initialSection={settingsSection} devices={devices} onUpdateDisplayName={updateDisplayName} onClearHistory={clearHistory} onClearDrafts={clearDrafts} onExport={exportRecovery} onLink={() => setDialog("link")} onAddDevice={() => { setAddDeviceSetup(undefined); setDialog("device"); }} onSecureRemove={(id) => void secureRemoveDevice(id).catch((cause) => setError(errorMessage(cause, "Could not securely remove the device.")))} onUnlink={() => void unlinkDevice().catch((cause) => setError(errorMessage(cause, "Could not unlink this device.")))} onLock={onLock} onReset={onReset} onClose={() => setDialog(null)} />}
    {dialog === "link" && <LinkDeviceModal setup={linkSetup} onPrepare={(code) => void prepareDeviceLink(code).catch((cause) => setError(errorMessage(cause, "Could not prepare device pairing.")))} onConfirm={() => void confirmDeviceLink().catch((cause) => setError(errorMessage(cause, "Could not finish device pairing.")))} onClose={() => void cancelDeviceLink()} />}
    {dialog === "device" && <DeviceModal setup={addDeviceSetup} onScan={(code) => void addDevice(code).catch((cause) => setError(errorMessage(cause, "Could not prepare secure device enrollment.")))} onApprove={() => void approveDevice().catch((cause) => setError(errorMessage(cause, "Could not approve the device.")))} onClose={() => { setSettingsSection("devices"); setDialog("settings"); setAddDeviceSetup(undefined); }} />}
    {dialog === "security" && selected && <SecurityModal account={account} contact={selected} onNickname={async (nickname) => runExclusive(() => mutateState(async (shared) => { const match = shared.contacts.find((item) => item.id === selected.id); if (match) match.localName = nickname.trim() || undefined; return { changed: Boolean(match), value: undefined }; }))} onBlock={async () => { if (confirm(`Block ${selected.localName ?? selected.displayName} and revoke their mailbox access?`)) { try { await blockContact(selected.id); setDialog(null); } catch (cause) { setError(errorMessage(cause, "Could not block this contact.")); } } }} onVerified={async () => { await runExclusive(() => mutateState(async (shared) => { const match = shared.contacts.find((item) => item.id === selected.id); if (match) match.verified = true; return { changed: Boolean(match), value: undefined }; })); setDialog(null); }} onClose={() => setDialog(null)} />}
    {error && <Notice error={error} onClose={() => setError("")} />}
  </main>;
}

function ContactSection({ title, contacts, selectedId, onSelect }: { title: string; contacts: ContactRecord[]; selectedId: string; onSelect(contact: ContactRecord): void }) {
  return <section className="contact-section"><h3>{title}<span>{contacts.length}</span></h3>{contacts.sort((a, b) => b.lastMessageAt - a.lastMessageAt).map((contact) => <button key={contact.id} className={`contact-row ${selectedId === contact.id ? "active" : ""}`} onClick={() => onSelect(contact)}><span className="avatar small">{initials(contact.localName ?? contact.displayName)}</span><span className="contact-copy"><strong>{contact.localName ?? contact.displayName}</strong><small>{contact.status === "request" ? "Wants to connect" : contact.verified ? "Verified contact" : "Encrypted conversation"}</small></span>{contact.unread > 0 && <span className="unread">{contact.unread}</span>}</button>)}</section>;
}

function MessageItem({ message, previous, contact, onRetry }: { message: MessageRecord; previous?: MessageRecord; contact: ContactRecord; onRetry(message: MessageRecord): void }) {
  const grouped = previous?.direction === message.direction && message.sentAt - previous.sentAt < 5 * 60_000;
  return <div className={`message-row ${message.direction} ${grouped ? "grouped" : ""}`}>
    {message.direction === "incoming" && !grouped && <span className="avatar small">{initials(contact.displayName)}</span>}
    <div className="message-body">{!grouped && <div className="message-meta"><strong>{message.direction === "system" ? "Blackspace" : message.direction === "outgoing" ? "You" : contact.localName ?? contact.displayName}</strong><span>{formatDay(message.sentAt)} at {formatTime(message.sentAt)}</span></div>}<div className="bubble">{message.body}</div>{message.direction === "outgoing" && <span className={`delivery ${message.delivery}`}>{message.delivery === "delivered" ? <CheckCheck /> : message.delivery === "failed" ? <CircleAlert /> : <Check />}{deliveryLabel(message.delivery)}{message.delivery === "failed" && <button className="retry-link" onClick={() => onRetry(message)}>Retry</button>}</span>}</div>
  </div>;
}

function EmptyChat({ onAdd, onInvite }: { onAdd(): void; onInvite(): void }) {
  return <div className="empty-chat"><div className="empty-orbit"><MessageCircle /></div><span className="eyebrow">WELCOME TO BLACKSPACE</span><h2>Start a private conversation</h2><p>Add someone using their contact invitation, or create an invitation for someone you trust.</p><div><button className="primary" onClick={onAdd}><UserPlus /> Add a contact</button><button className="secondary" onClick={onInvite}><Copy /> Create invitation</button></div><small><Lock /> Messages are encrypted before they leave this device.</small></div>;
}

function AddContactModal({ busy, onAdd, onClose }: { busy: boolean; onAdd(value: string, first: string): void; onClose(): void }) {
  const [value, setValue] = useState(""); const [first, setFirst] = useState(""); const [scanError, setScanError] = useState("");
  return <Modal title="Add a contact" onClose={onClose}><div className="modal-content"><div className="modal-icon"><UserPlus /></div><p>Paste the invitation shared directly by your contact. Blackspace verifies their signed key package before sending.</p><label>Contact invitation<textarea rows={5} value={value} onChange={(event) => setValue(event.target.value)} placeholder="blackspace://contact/v1?onion=…#cap=…" spellCheck={false} /></label><QrScanControls label="Scan invitation QR" onValue={(scanned) => { setValue(scanned); setScanError(""); }} onError={setScanError} />{scanError && <p className="form-error"><CircleAlert size={16} />{scanError}</p>}<label>First message<textarea rows={3} value={first} maxLength={16_384} onChange={(event) => setFirst(event.target.value)} placeholder="Hello…" /></label><div className="modal-actions"><button className="secondary" onClick={onClose}>Cancel</button><button className="primary" onClick={() => onAdd(value, first)} disabled={busy || !value.trim()}>{busy ? "Establishing session…" : "Add and send"}</button></div></div></Modal>;
}

function InviteModal({ value, qr, onClose }: { value: string; qr: string; onClose(): void }) {
  const [copied, setCopied] = useState(false);
  return <Modal title="Your contact invitation" onClose={onClose}><div className="invite-modal"><p>Share this invitation with one person through a trusted channel. It grants write-only access to your mailbox.</p>{qr && <img src={qr} alt="Blackspace contact invitation QR code" />}<textarea readOnly value={value} rows={5} /><button className="primary wide" onClick={async () => { await navigator.clipboard.writeText(value); setCopied(true); }}>{copied ? <><Check /> Copied</> : <><Copy /> Copy invitation</>}</button><small>Revoke this invitation if it is exposed or abused.</small></div></Modal>;
}

interface SettingsModalProps {
  account: AccountState;
  mode: string;
  online: boolean;
  initialSection: SettingsSection;
  devices: DeviceRecord[];
  onUpdateDisplayName(value: string): Promise<void>;
  onClearHistory(): Promise<void>;
  onClearDrafts(): Promise<void>;
  onExport(): void;
  onLink(): void;
  onAddDevice(): void;
  onSecureRemove(id: string): void;
  onUnlink(): void;
  onLock(): void;
  onReset(): void;
  onClose(): void;
}

function SettingsModal({ account, mode, online, initialSection, devices, onUpdateDisplayName, onClearHistory, onClearDrafts, onExport, onLink, onAddDevice, onSecureRemove, onUnlink, onLock, onReset, onClose }: SettingsModalProps) {
  const [section, setSection] = useState<SettingsSection>(initialSection);
  const [filter, setFilter] = useState("");
  const [displayName, setDisplayName] = useState(account.displayName);
  const [running, setRunning] = useState("");
  const [actionError, setActionError] = useState("");
  const [identityCopied, setIdentityCopied] = useState(false);

  useEffect(() => setDisplayName(account.displayName), [account.displayName]);
  useEffect(() => setActionError(""), [section]);
  const active = devices.filter((device) => !device.revoked);
  const sections: Array<{ id: SettingsSection; label: string; detail: string; icon: ReactNode }> = [
    { id: "account", label: "Account", detail: "Profile and identity", icon: <KeyRound /> },
    { id: "devices", label: "Devices", detail: `${active.length} enrolled`, icon: <Users /> },
    { id: "privacy", label: "Privacy & data", detail: "Storage and metadata", icon: <ShieldCheck /> },
    { id: "network", label: "Network", detail: mode, icon: <Server /> },
    { id: "recovery", label: "Recovery", detail: "Backup and lock", icon: <Archive /> },
  ];
  const visibleSections = sections.filter((item) => `${item.label} ${item.detail}`.toLowerCase().includes(filter.toLowerCase()));
  const row = (label: string, value: string, icon: ReactNode) => <div className="settings-value-row">{icon}<span><strong>{label}</strong><small>{value}</small></span></div>;
  const run = async (name: string, action: () => Promise<void>) => {
    setRunning(name); setActionError("");
    try { await action(); }
    catch (cause) { setActionError(errorMessage(cause, "The setting could not be changed.")); }
    finally { setRunning(""); }
  };

  return <div className="modal-backdrop settings-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="settings-window" role="dialog" aria-modal="true" aria-label="Settings">
      <aside className="settings-sidebar">
        <div className="settings-profile"><span className="avatar large">{initials(account.displayName)}</span><div><h3>{account.displayName}</h3><p>{account.instanceName}</p></div></div>
        <div className="settings-search"><Search /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Search settings" /></div>
        <nav>{visibleSections.map((item) => <button key={item.id} className={section === item.id ? "active" : ""} onClick={() => setSection(item.id)}>{item.icon}<span><strong>{item.label}</strong><small>{item.detail}</small></span></button>)}</nav>
        <span className="settings-sidebar-spacer" />
        <button className="settings-lock" onClick={onLock}><LogOut /> Lock Blackspace</button>
      </aside>
      <div className="settings-main">
        <header><div><span className="eyebrow">BLACKSPACE SETTINGS</span><h2>{sections.find((item) => item.id === section)?.label}</h2></div><button className="icon-button" onClick={onClose} aria-label="Close settings"><X /></button></header>
        <div className="settings-scroll">
          {section === "account" && <section className="settings-page">
            <div className="settings-page-heading"><div className="modal-icon"><KeyRound /></div><div><h3>Account and identity</h3><p>Change how contacts see you and manage the public identity information you share.</p></div></div>
            <div className="settings-card settings-edit-card">
              <label>Display name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} minLength={2} maxLength={64} /></label>
              <p>Saving updates the encrypted shared account state and sends a signed profile update to established contacts.</p>
              <button className="primary" disabled={running === "name" || displayName.trim() === account.displayName || displayName.trim().length < 2} onClick={() => void run("name", () => onUpdateDisplayName(displayName))}><Save />{running === "name" ? "Saving…" : "Save display name"}</button>
            </div>
            <div className="settings-card settings-action-card settings-followup-card"><div><Fingerprint /><span><strong>Public identity key</strong><small>{account.identityPublicKey.slice(0, 32)}…</small></span><button className="secondary" onClick={() => void navigator.clipboard.writeText(account.identityPublicKey).then(() => setIdentityCopied(true)).catch((cause) => setActionError(errorMessage(cause, "Could not copy the identity key.")))}>{identityCopied ? <><Check /> Copied</> : <><Copy /> Copy</>}</button></div><div><Server /><span><strong>Home instance</strong><small>{account.instanceName}</small></span></div></div>
            {actionError && <p className="settings-inline-error"><CircleAlert />{actionError}</p>}
          </section>}
          {section === "devices" && <section className="settings-page">
            <div className="settings-page-heading"><div className="modal-icon secure"><Users /></div><div><h3>Authorized devices</h3><p>New devices receive account secrets only after both screens show the same security code and you approve here.</p></div></div>
            <div className="settings-card device-card-list">
              {active.length ? active.map((device) => <div className="device-management-row" key={device.id}>
                <span className={`device-glyph ${device.id === account.deviceId ? "current" : ""}`}><MessageCircle /></span>
                <span><strong>{device.label}</strong><small>Added {formatDay(device.enrolled_at * 1000)} · {device.id === account.deviceId ? "This device" : `ID ${device.id.slice(0, 8)}`}</small></span>
                {device.id === account.deviceId ? <em>Current</em> : <button className="secondary danger-action" onClick={() => onSecureRemove(device.id)}>Securely remove</button>}
              </div>) : <div className="settings-empty"><Users /><p>No registered devices yet.</p></div>}
            </div>
            <div className="settings-actions-grid"><button className="primary" onClick={onAddDevice}><Plus /> Add a full device</button>{account.companionLink?.active ? <button className="secondary danger-action" onClick={onUnlink}><Users /> Unlink companion</button> : <button className="secondary" onClick={onLink}><Users /> Link a companion mirror</button>}</div>
            <p className="settings-security-note"><ShieldCheck /> Secure removal rotates mailbox read/admin access and the shared-state encryption key. Protocol v1 signs out every other full device so trusted ones can be enrolled again. A stolen device may retain data it already decrypted.</p>
          </section>}
          {section === "privacy" && <section className="settings-page">
            <div className="settings-page-heading"><div className="modal-icon secure"><ShieldCheck /></div><div><h3>Privacy and local data</h3><p>Control synchronized conversation history and device-local compose drafts.</p></div></div>
            <div className="settings-card settings-action-card"><div><Trash2 /><span><strong>Clear message history</strong><small>{account.messages.length ? `${account.messages.length} message${account.messages.length === 1 ? "" : "s"} across enrolled devices` : "No saved messages"}</small></span><button className="secondary danger-action" disabled={!account.messages.length || running === "history"} onClick={() => void run("history", onClearHistory)}>{running === "history" ? "Clearing…" : "Clear history"}</button></div><div><MessageCircle /><span><strong>Clear saved drafts</strong><small>{account.contacts.filter((contact) => contact.draft).length ? `${account.contacts.filter((contact) => contact.draft).length} device-local conversation draft${account.contacts.filter((contact) => contact.draft).length === 1 ? "" : "s"}` : "No device-local drafts"}</small></span><button className="secondary" disabled={!account.contacts.some((contact) => contact.draft) || running === "drafts"} onClick={() => void run("drafts", onClearDrafts)}>{running === "drafts" ? "Clearing…" : "Clear drafts"}</button></div></div>
            <p className="settings-security-note"><CircleAlert /> Clearing synchronized history cannot erase messages another person retained, and browser or SSD storage cannot guarantee physical erasure of old encrypted pages. The mailbox can still observe timing, size class, expiry and capability use.</p>
            {actionError && <p className="settings-inline-error"><CircleAlert />{actionError}</p>}
          </section>}
          {section === "network" && <section className="settings-page">
            <div className="settings-page-heading"><div className="modal-icon"><Server /></div><div><h3>Network and transport</h3><p>Blackspace keeps Tor and HTTPS transport modes separate and never silently falls back.</p></div></div>
            <div className="settings-card">
              {row("Active transport", mode, <ShieldCheck />)}
              {row("Onion service", account.onionOrigin.replace(/^https?:\/\//, ""), <Server />)}
              {row("HTTPS gateway", account.httpsOrigin ?? "Not configured", <Server />)}
              {row("Device network", online ? "Online" : "Offline", <MessageCircle />)}
              {row("Mailbox", account.mailboxId, <Inbox />)}
            </div>
            <ConnectionDiagnostics account={account} />
          </section>}
          {section === "recovery" && <section className="settings-page">
            <div className="settings-page-heading"><div className="modal-icon"><Archive /></div><div><h3>Recovery and access</h3><p>Recovery kits are encrypted client exports. The server cannot recover a lost identity or passphrase.</p></div></div>
            <div className="settings-card settings-action-card"><div><Download /><span><strong>Encrypted recovery kit</strong><small>Preserves your identity and history for mailbox takeover recovery.</small></span><button className="secondary" onClick={onExport}>Export</button></div><div><LogOut /><span><strong>Lock this device</strong><small>Clears unlocked key material from the running application.</small></span><button className="secondary" onClick={onLock}>Lock now</button></div><div><Trash2 /><span><strong>Remove from this device</strong><small>Deletes this device's encrypted local vault. It does not delete the mailbox or data on other devices.</small></span><button className="secondary danger-action" onClick={onReset}>Remove</button></div></div>
          </section>}
        </div>
      </div>
    </section>
  </div>;
}

// Trusted-device side of staged enrollment. Scanning parks only an ephemeral key;
// pressing the explicit approval button is the boundary that releases secrets.
function DeviceModal({ setup, onScan, onApprove, onClose }: { setup?: { prepared: PreparedEnrollmentParcel }; onScan(code: string): void; onApprove(): void; onClose(): void }) {
  const [pasted, setPasted] = useState("");
  const [scanError, setScanError] = useState("");
  return <Modal title="Add a device securely" onClose={onClose}><div className="modal-content">{!setup ? <>
    <p>On your new device choose “Add this device to my account,” then scan the code it shows.</p>
    <QrScanControls label="Scan enrollment QR" onValue={(code) => { setScanError(""); onScan(code); }} onError={setScanError} />
    <label>Or paste the enrollment code<textarea rows={4} value={pasted} onChange={(event) => setPasted(event.target.value)} placeholder="blackspace://enroll/v1…" /></label>
    {scanError && <p className="form-error"><CircleAlert size={16} />{scanError}</p>}
    <button className="primary wide" onClick={() => onScan(pasted)} disabled={!pasted.trim()}>Start secure enrollment</button>
  </> : <>
    <div className="modal-icon secure"><ShieldCheck /></div>
    <p>Compare this code with the new device. No reusable account secret has been uploaded yet.</p>
    <code>{setup.prepared.sas}</code>
    <button className="primary wide" onClick={onApprove}><ShieldCheck /> Codes match — approve device</button>
    <button className="secondary wide" onClick={onClose}>Codes do not match — cancel</button>
  </>}</div></Modal>;
}

type DiagnosticPhase = "checking" | "ok" | "error" | "unconfigured";

// Each probe has an explicit transport. In the native client the Tor probe uses
// the managed SOCKS client and the HTTPS probe uses the dedicated TLS-only command.
// These checks never participate in normal mailbox routing or fallback behavior.
function TransportDiagnostic({ label, origin, transport, revision }: { label: string; origin?: string; transport: "tor" | "https"; revision: number }) {
  const [info, setInfo] = useState<ServerInfo>();
  const [phase, setPhase] = useState<DiagnosticPhase>(origin ? "checking" : "unconfigured");
  const [latency, setLatency] = useState<number>();
  const [detail, setDetail] = useState("");

  useEffect(() => {
    let cancelled = false;
    if (!origin) {
      setInfo(undefined); setLatency(undefined); setDetail(""); setPhase("unconfigured");
      return () => { cancelled = true; };
    }
    setInfo(undefined); setLatency(undefined); setDetail(""); setPhase("checking");
    const started = performance.now();
    void diagnosticServerInfo(origin, transport).then((result) => {
      if (cancelled) return;
      setInfo(result); setLatency(Math.round(performance.now() - started)); setPhase("ok");
    }).catch((cause) => {
      if (cancelled) return;
      setDetail(errorMessage(cause, `Could not reach the mailbox over ${label}.`)); setPhase("error");
    });
    return () => { cancelled = true; };
  }, [label, origin, revision, transport]);

  const status = phase === "checking" ? "Checking…" : phase === "ok" ? `Reachable${latency !== undefined ? ` · ${latency} ms` : ""}` : phase === "error" ? "Unreachable" : "Not configured";
  const explanation = detail ? explainErrorMessage(detail) : "";
  return <article className={`transport-diagnostic ${phase}`}>
    <header><div><span className={`network-dot ${phase === "ok" ? "online" : ""}`} /><strong>{label}</strong></div><span>{status}</span></header>
    <div className="diagnostic-details">
      <div><Server /><span><strong>Address</strong><small>{origin?.replace(/^https?:\/\//, "") ?? "No HTTPS gateway advertised"}</small></span></div>
      <div><ShieldCheck /><span><strong>Route</strong><small>{transport === "tor" ? "Managed Tor · isolated SOCKS circuit" : "Direct HTTPS · TLS required"}</small></span></div>
      {info && <>
        <div><Server /><span><strong>Instance</strong><small>{info.instance_name}</small></span></div>
        <div><KeyRound /><span><strong>Protocol</strong><small>v{info.protocol_versions.join(", v")}</small></span></div>
      </>}
    </div>
    {phase === "error" && <div className="diagnostic-error"><CircleAlert /><span><strong>{detail}</strong>{explanation && <small>{explanation}</small>}</span></div>}
  </article>;
}

function ConnectionDiagnostics({ account }: { account: AccountState }) {
  const [revision, setRevision] = useState(0);
  return <section className="connection-diagnostics" aria-labelledby="connection-diagnostics-title">
    <header><div><h4 id="connection-diagnostics-title">Connection diagnostics</h4><p>Independent reachability checks for each configured transport. Blackspace never switches between them automatically.</p></div><button className="secondary" onClick={() => setRevision((value) => value + 1)}><RefreshCw size={15} /> Recheck both</button></header>
    <div className="diagnostic-grid">
      <TransportDiagnostic label="Tor" origin={account.onionOrigin} transport="tor" revision={revision} />
      <TransportDiagnostic label="HTTPS" origin={account.httpsOrigin} transport="https" revision={revision} />
    </div>
  </section>;
}

function LinkDeviceModal({ setup, onPrepare, onConfirm, onClose }: { setup?: { qr: string; qrImage: string; sas: string }; onPrepare(code: string): void; onConfirm(): void; onClose(): void }) {
  const [offer, setOffer] = useState("");
  const [scanError, setScanError] = useState("");
  return <Modal title="Link a companion" onClose={onClose}><div className="modal-content">{!setup ? <><p>Paste or scan the temporary code shown by the companion. It contains no reusable account secret.</p><label>Companion offer<textarea rows={5} value={offer} onChange={(event) => setOffer(event.target.value)} /></label><QrScanControls label="Scan companion QR" onValue={(value) => { setOffer(value); setScanError(""); }} onError={setScanError} />{scanError && <p className="form-error"><CircleAlert size={16} />{scanError}</p>}<button className="primary wide" onClick={() => onPrepare(offer)} disabled={!offer.trim()}>Create encrypted response</button></> : <><p>Show this response to the companion, then compare the six-digit code on both devices.</p><img className="pairing-qr" src={setup.qrImage} alt="Encrypted primary pairing response" /><textarea readOnly rows={5} value={setup.qr} /><code>{setup.sas}</code><button className="primary wide" onClick={onConfirm}>Codes match — finish linking</button></>}<button className="secondary wide" onClick={onClose}>Cancel</button></div></Modal>;
}

function SecurityModal({ account, contact, onNickname, onBlock, onVerified, onClose }: { account: AccountState; contact: ContactRecord; onNickname(value: string): void; onBlock(): void; onVerified(): void; onClose(): void }) {
  const [fingerprint, setFingerprint] = useState<{ hex: string; words: string[] }>();
  const [verificationQr, setVerificationQr] = useState("");
  const [nickname, setNickname] = useState(contact.localName ?? "");
  useEffect(() => {
    void contactFingerprint(account.identityPublicKey, contact.identityPublicKey).then(async (value) => {
      setFingerprint(value);
      setVerificationQr(await QRCode.toDataURL(`blackspace://verify/v1#fingerprint=${encodeURIComponent(value.hex)}`, { width: 180, margin: 2 }));
    });
  }, [account.identityPublicKey, contact.identityPublicKey]);
  return <Modal title="Contact and security" onClose={onClose}><div className="security-modal"><div className="modal-icon secure"><Fingerprint /></div><p>Compare this fingerprint with {contact.displayName} over another trusted channel. It changes if either identity changes.</p>{verificationQr && <img className="verification-qr" src={verificationQr} alt="Verification fingerprint QR code" />}<code>{fingerprint?.hex || "Calculating…"}</code><strong className="verification-words">{fingerprint?.words.join(" · ")}</strong><div className="identity-pair"><span>You <small>{account.identityPublicKey.slice(0, 22)}…</small></span><span>{contact.displayName} <small>{contact.identityPublicKey.slice(0, 22)}…</small></span></div><label>Local nickname<input value={nickname} maxLength={64} placeholder={contact.displayName} onChange={(event) => setNickname(event.target.value)} onBlur={() => onNickname(nickname)} /></label><button className="primary wide" onClick={onVerified}><ShieldCheck /> Mark as verified</button><button className="secondary wide danger-action" onClick={onBlock}>Block and revoke mailbox access</button></div></Modal>;
}

// Companion (linked-device) shell. A read-only mirror for now; pairing populates
// this state (M3) and relay/live-sync fill in the composer and downlink apply (M2/M4).
function CompanionMessenger({ initial, onLock }: { initial: CompanionAccountState; passphrase: string; onLock(): void }) {
  const [selectedId, setSelectedId] = useState(initial.contacts.find((contact) => contact.status === "accepted")?.id ?? "");
  const selected = initial.contacts.find((contact) => contact.id === selectedId);
  const messages = initial.messages.filter((message) => message.contactId === selectedId).sort((a, b) => a.sentAt - b.sentAt);
  const conversations = initial.contacts.filter((contact) => contact.status !== "blocked").sort((a, b) => b.lastMessageAt - a.lastMessageAt);
  return <main className="workspace">
    <aside className="server-rail"><button className="server-tile active" aria-label="Blackspace home"><MessageCircle /></button><span className="rail-spacer" /><button className="avatar small" onClick={onLock} title="Lock this device"><LogOut size={16} /></button></aside>
    <aside className="conversation-sidebar mobile-visible">
      <header className="workspace-header"><div><span className="eyebrow">LINKED DEVICE</span><h1>{initial.instanceName}</h1></div></header>
      <section className="contact-section"><h3>Direct messages<span>{conversations.length}</span></h3>{conversations.map((contact) => <button key={contact.id} className={`contact-row ${selectedId === contact.id ? "active" : ""}`} onClick={() => setSelectedId(contact.id)}><span className="avatar small">{initials(contact.localName ?? contact.displayName)}</span><span className="contact-copy"><strong>{contact.localName ?? contact.displayName}</strong><small>{contact.verified ? "Verified contact" : "Encrypted conversation"}</small></span>{contact.unread > 0 && <span className="unread">{contact.unread}</span>}</button>)}</section>
      <footer><span className="network-dot online" /> Companion mirror</footer>
    </aside>
    <section className="chat-panel mobile-visible">
      {selected ? <>
        <header className="chat-header"><div className="avatar">{initials(selected.localName ?? selected.displayName)}</div><div><h2>{selected.localName ?? selected.displayName}</h2><p>Mirrored from your primary device</p></div></header>
        <div className="message-scroll">{messages.map((message) => <div key={message.id} className={`message-row ${message.direction}`}><div className="message-body"><div className="bubble">{message.body}</div></div></div>)}</div>
        <div className="composer-wrap"><div className="composer"><textarea placeholder="Companion sending arrives in a later step…" rows={1} disabled /></div></div>
      </> : <div className="empty-chat"><div className="empty-orbit"><MessageCircle /></div><span className="eyebrow">LINKED DEVICE</span><h2>Companion mirror</h2><p>This device mirrors your Blackspace conversations.</p></div>}
    </section>
  </main>;
}

function LinkedCompanionMessenger({ initial, passphrase, onLock, onReset }: { initial: CompanionAccountState; passphrase: string; onLock(): void; onReset(): void }) {
  const [account, setAccount] = useState(initial); const accountRef = useRef(account); accountRef.current = account;
  const [selectedId, setSelectedId] = useState(initial.contacts.find((contact) => contact.status === "accepted")?.id ?? "");
  const [error, setError] = useState(""); const [unlinked, setUnlinked] = useState(false); const [now, setNow] = useState(Date.now());
  const syncing = useRef(false);
  const syncFailures = useRef(0);
  // One runner for poll and commands: upSeq is the uplink AEAD nonce, so a poll
  // persisting a clone taken before a command bumped it would reuse a nonce.
  const runLinked = useRef(createSerialRunner()).current;
  const persist = useCallback(async (next: CompanionAccountState) => { accountRef.current = next; setAccount(next); await saveVault(next, passphrase); }, [passphrase]);
  const ownServer = ownOrigin(account.onionOrigin, account.httpsOrigin);

  const queueCommand = useCallback((command: UplinkCommand): Promise<void> => runLinked(async () => {
    let next = structuredClone(accountRef.current); next.link.upSeq += 1; await persist(next);
    const packet = await sealLinkEvent(next.link.linkSecret, next.link.pairingId, "up", next.link.upSeq, command);
    next = structuredClone(accountRef.current); next.link.uplinkOutbox.push(envelopeForPacket(packet)); await persist(next);
  }), [persist, runLinked]);

  const poll = useCallback(async () => {
    if (syncing.current || unlinked || !navigator.onLine) return; syncing.current = true;
    try {
      // queueCommand shares runLinked, so the resnapshot request must be sent
      // after this task releases the runner — awaiting it inside would deadlock.
      const gap = await runLinked(async () => {
        let next = structuredClone(accountRef.current);
        const target: DepositTarget = { onion_url: next.onionOrigin, https_url: next.httpsOrigin, deposit_capability: next.link.uplinkCap };
        const remaining: PendingEnvelope[] = [];
        for (const [index, envelope] of next.link.uplinkOutbox.entries()) { try { await depositEnvelope(target, envelope); } catch { remaining.push(...next.link.uplinkOutbox.slice(index)); break; } }
        next.link.uplinkOutbox = remaining; await persist(next);
        const pulled = await pullEnvelopes(ownOrigin(next.onionOrigin, next.httpsOrigin), next.readCapability);
        const acknowledged: string[] = []; let sawGap = false;
        for (const envelope of pulled) {
          const disposition = classify(envelope.deposit_capability_id, "companion", { downlinkCapId: next.link.downlinkCapId, uplinkCapId: next.link.uplinkCapId });
          if (disposition.action !== "applyDownlink") continue;
          try {
            const packet = packetFromEnvelope(envelope.ciphertext);
            if (packet.kind !== "link" || packet.dir !== "down" || packet.pid !== next.link.pairingId) throw new Error("Invalid companion downlink.");
            if (packet.seq <= next.link.downLastApplied) { acknowledged.push(envelope.acknowledgement_token); continue; }
            if (packet.seq > next.link.downLastApplied + 1) sawGap = true;
            const event = await openLinkEvent<DownlinkEvent>(next.link.linkSecret, packet);
            next = applyDownlinkEvent(next, event).state; next.link.downLastApplied = packet.seq;
            acknowledged.push(envelope.acknowledgement_token);
          } catch { acknowledged.push(envelope.acknowledgement_token); }
        }
        await persist(next);
        if (acknowledged.length) await acknowledgeEnvelopes(ownOrigin(next.onionOrigin, next.httpsOrigin), next.readCapability, acknowledged);
        return sawGap;
      });
      if (gap) await queueCommand({ type: "request_resnapshot", commandId: crypto.randomUUID(), ts: Date.now(), reason: "sequence gap" });
      syncFailures.current = 0;
    } catch (cause) {
      syncFailures.current += 1;
      const message = errorMessage(cause, "Companion sync failed.");
      if (/401|authorization failed/i.test(message)) setUnlinked(true);
      else if (message === "Tor is not ready. Blackspace will not use a direct connection.") return;
      else if (syncFailures.current >= 3) setError(message);
    } finally { syncing.current = false; }
  }, [persist, queueCommand, runLinked, unlinked]);

  useEffect(() => { void queueCommand({ type: "hello", commandId: crypto.randomUUID(), ts: Date.now(), label: navigator.userAgent.includes("Mobile") ? "Phone" : "Browser", downLastApplied: accountRef.current.link.downLastApplied }).then(poll); }, []); // pairing hello once per unlock
  useEffect(() => { void poll(); const timer = window.setInterval(() => { setNow(Date.now()); void poll(); }, 5_000); return () => clearInterval(timer); }, [poll]);

  const selected = account.contacts.find((contact) => contact.id === selectedId); const messages = account.messages.filter((message) => message.contactId === selectedId).sort((a, b) => a.sentAt - b.sentAt);
  const conversations = account.contacts.filter((contact) => contact.status !== "blocked").sort((a, b) => b.lastMessageAt - a.lastMessageAt);
  const primaryOffline = Boolean(account.link.lastDownlinkAt && now - account.link.lastDownlinkAt > 20_000);
  const send = async () => {
    if (!selected?.draft.trim()) return; const body = selected.draft.trim(); const id = crypto.randomUUID(); const contactId = selected.id;
    await runLinked(async () => {
      const next = structuredClone(accountRef.current); const contact = next.contacts.find((item) => item.id === contactId); if (!contact) return;
      contact.draft = ""; next.messages.push(newMessage(contactId, body, id)); await persist(next);
    });
    await queueCommand({ type: "send_text", commandId: id, ts: Date.now(), contactId, body, clientSentAt: Date.now() }); void poll();
  };
  const relay = (command: UplinkCommand) => { void queueCommand(command).then(poll); };
  return <main className="workspace">
    {unlinked && <div className="offline-banner"><CircleAlert /> This device was unlinked. <button className="retry-link" onClick={onReset}>Wipe local mirror</button></div>}
    {primaryOffline && !unlinked && <div className="offline-banner"><CircleAlert /> Primary offline — sends remain queued.</div>}
    {error && <Notice error={error} onClose={() => setError("")} />}
    <aside className="server-rail"><button className="server-tile active"><MessageCircle /></button><span className="rail-spacer" /><button className="avatar small" onClick={onLock}><LogOut /></button></aside>
    <aside className="conversation-sidebar mobile-visible"><header className="workspace-header"><div><span className="eyebrow">LINKED DEVICE</span><h1>{account.instanceName}</h1></div></header><section className="contact-section"><h3>Direct messages<span>{conversations.length}</span></h3>{conversations.map((contact) => <button key={contact.id} className={`contact-row ${selectedId === contact.id ? "active" : ""}`} onClick={() => { setSelectedId(contact.id); if (contact.unread) relay({ type: "mark_read", commandId: crypto.randomUUID(), ts: Date.now(), contactId: contact.id }); }}><span className="avatar small">{initials(contact.localName ?? contact.displayName)}</span><span className="contact-copy"><strong>{contact.localName ?? contact.displayName}</strong><small>{contact.status === "request" ? "Wants to connect" : contact.verified ? "Verified contact" : "Encrypted conversation"}</small></span>{contact.unread > 0 && <span className="unread">{contact.unread}</span>}</button>)}</section><footer><span className={`network-dot ${primaryOffline ? "" : "online"}`} />{primaryOffline ? "Primary offline" : "Synced companion"}</footer></aside>
    <section className="chat-panel mobile-visible">{selected ? <><header className="chat-header"><div className="avatar">{initials(selected.displayName)}</div><div><h2>{selected.localName ?? selected.displayName}</h2><p>{selected.verified ? "Identity verified by primary" : "Relayed through your primary device"}</p></div><span className="chat-spacer" /><button className="icon-button" title="Ask primary to mark verified" disabled={unlinked || selected.verified} onClick={() => relay({ type: "set_verified", commandId: crypto.randomUUID(), ts: Date.now(), contactId: selected.id })}><Fingerprint /></button></header>
      {selected.status === "request" && <div className="request-banner"><div><strong>New message request</strong><span>Accept or block through your primary device.</span></div><button className="secondary" disabled={unlinked} onClick={() => relay({ type: "block_contact", commandId: crypto.randomUUID(), ts: Date.now(), contactId: selected.id })}>Block</button><button className="primary" disabled={unlinked} onClick={() => relay({ type: "accept_request", commandId: crypto.randomUUID(), ts: Date.now(), contactId: selected.id })}>Accept</button></div>}
      <div className="message-scroll">{messages.map((message) => <div key={message.id} className={`message-row ${message.direction}`}><div className="message-body"><div className="bubble">{message.body}</div>{message.direction === "outgoing" && <span className={`delivery ${message.delivery}`}>{deliveryLabel(message.delivery)}{message.delivery === "failed" && <button className="retry-link" onClick={() => relay({ type: "retry_message", commandId: crypto.randomUUID(), ts: Date.now(), messageId: message.id })}>Retry</button>}</span>}</div></div>)}</div>
      <div className="composer-wrap"><div className="composer"><textarea value={selected.draft} maxLength={16_384} disabled={unlinked || selected.status === "request"} onChange={(event) => { const next = structuredClone(account); const contact = next.contacts.find((item) => item.id === selected.id); if (contact) contact.draft = event.target.value; setAccount(next); }} onBlur={() => void runLinked(async () => persist(accountRef.current))} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void send(); } }} placeholder={primaryOffline ? "Queue a message for your primary…" : "Message through primary"} /><button className="send-button" onClick={() => void send()} disabled={unlinked || selected.status === "request" || !selected.draft.trim()}><Send /></button></div></div></> : <div className="empty-chat"><div className="empty-orbit"><MessageCircle /></div><span className="eyebrow">LINKED DEVICE</span><h2>Companion mirror</h2><p>Choose a conversation mirrored from your primary device.</p></div>}</section>
  </main>;
}

export default function App() {
  const [screen, setScreen] = useState<Screen>("loading");
  const [account, setAccount] = useState<StoredAccount | null>(null);
  const [passphrase, setPassphrase] = useState("");
  useEffect(() => { void vaultExists().then((exists) => setScreen(exists ? "locked" : "welcome")); }, []);
  const blocked = deriveTransportMode(window.location) === null;
  if (blocked) return <main className="blocked"><Lock /><h1>Connection blocked</h1><p>Use a v3 onion origin, HTTPS, or loopback HTTP for development.</p></main>;
  if (screen === "loading") return <main className="loading"><div className="brand-mark large"><MessageCircle /></div><span>Opening Blackspace…</span></main>;
  if (screen === "welcome") return <WelcomeScreen onComplete={(state, password) => { setAccount(state); setPassphrase(password); setScreen("messenger"); }} />;
  if (screen === "locked") return <LockedScreen onUnlock={(state, password) => { setAccount(state); setPassphrase(password); setScreen("messenger"); }} onReset={async () => { if (confirm("Delete the encrypted Blackspace vault from this browser?")) { await deleteVault(); setScreen("welcome"); } }} />;
  if (!account) return null;
  if (account.role === "companion") return <LinkedCompanionMessenger initial={account} passphrase={passphrase} onLock={() => { lockVault(); setAccount(null); setPassphrase(""); setScreen("locked"); }} onReset={() => void (async () => { if (confirm("Delete this encrypted companion mirror from this browser?")) { await deleteVault(); setAccount(null); setPassphrase(""); setScreen("welcome"); } })()} />;
  return <Messenger initial={account} passphrase={passphrase} onLock={() => { lockVault(); setAccount(null); setPassphrase(""); setScreen("locked"); }} onReset={() => void (async () => { if (confirm("Remove this account and its encrypted local data from this device? Export a recovery kit first if this is your only full device.")) { await deleteVault(); setAccount(null); setPassphrase(""); setScreen("welcome"); } })()} />;
}
