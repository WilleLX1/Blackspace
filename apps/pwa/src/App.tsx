import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Archive, ArrowLeft, Check, CheckCheck, CircleAlert, Copy, Download,
  Fingerprint, Hash, Inbox, KeyRound, Lock, LogOut, MessageCircle, Plus,
  RefreshCw, Search, Send, Server, Settings, ShieldCheck, UserPlus, Users, X,
} from "lucide-react";
import QRCode from "qrcode";
import {
  acknowledgeEnvelopes, claimKeyPackage, createDepositCapability, depositEnvelope,
  ownOrigin, provisionMailbox, publishKeyPackages, pullEnvelopes, revokeDepositCapability, serverInfo,
  recoverMailbox, rotateReadCapability,
} from "./api";
import {
  capabilityVerifier, envelopeForPacket,
  formatContactInvitation,
  packetFromEnvelope, parseContactInvitation, parseJoinInvitation, randomCapability,
  type SecureContent,
} from "./crypto";
import { base64Url } from "./crypto";
import { errorMessage } from "./errors";
import { contactFingerprint, decodeSecureContent, encodeSecureContent, mlsCreateMessage, mlsGenerate, mlsGroupHint, mlsJoin, mlsProcessMessage, mlsRecoveryIdentitySnapshot, mlsReplenish, mlsStart } from "./mls";
import type { AccountState, CompanionAccountState, ContactRecord, DepositTarget, KeyPackageWire, MessageRecord, PendingEnvelope, ServerInfo, StoredAccount } from "./model";
import { onboardingError, type OnboardingStage } from "./onboarding";
import { applyDownlinkEvent, buildSnapshot, newMessage, projectContact } from "./companion";
import { classify, openLinkEvent, sealLinkEvent, type DownlinkEvent, type UplinkCommand } from "./link";
import { createCompanionPairingOffer, createPrimaryPairingResponse, openPrimaryPairingResponse, type CompanionPairingOffer, type PairingBundle } from "./pairing";
import { detectTransportMode, deriveTransportMode, modeLabel, validateServerUrl } from "./security";
import { createRecoveryKit, deleteVault, lockVault, openRecoveryKit, saveVault, unlockVault, vaultExists } from "./vault";
import { pairingQrImage, scanQr } from "./qr";
import { createSerialRunner } from "./serial";

type Screen = "loading" | "welcome" | "locked" | "messenger";
type Dialog = "add" | "invite" | "settings" | "security" | "link" | null;

const initials = (name: string) => name.split(/\s+/).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "?";
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
  return <div className="toast" role="alert"><CircleAlert size={18} /><span>{error}</span><button onClick={onClose} aria-label="Dismiss"><X size={16} /></button></div>;
}

function WelcomeScreen({ onComplete }: { onComplete(state: StoredAccount, passphrase: string): void }) {
  const [invitation, setInvitation] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [linking, setLinking] = useState(false);
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
      <button className="text-button" onClick={() => setLinking(true)} disabled={busy}><Users size={15} /> Link to an existing account</button>
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
  const responseImage = useRef<HTMLInputElement>(null);
  useEffect(() => { void createCompanionPairingOffer().then(async (value) => { setOffer(value); setOfferQr(await pairingQrImage(value.qr)); }).catch((cause) => setError(errorMessage(cause, "Could not start pairing."))); }, []);
  const inspect = async () => {
    if (!offer) return;
    try { setOpened(await openPrimaryPairingResponse(offer, response)); setError(""); }
    catch (cause) { setError(errorMessage(cause, "The pairing response is invalid.")); }
  };
  const scanResponse = async (file?: File) => {
    if (!file) return;
    try { setResponse(await scanQr(file)); setError(""); }
    catch (cause) { setError(errorMessage(cause, "Could not scan the pairing response.")); }
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
  return <main className="lock-shell"><section className="lock-card"><span className="eyebrow">LINKED COMPANION</span><h1>Link this device</h1><p>Show this first code to your primary device. It contains only a temporary public key.</p>{offerQr && <img className="pairing-qr" src={offerQr} alt="Companion pairing offer" />}<textarea readOnly rows={4} value={offer?.qr ?? "Preparing…"} />{!opened ? <><label>Response from primary<textarea rows={5} value={response} onChange={(event) => setResponse(event.target.value)} /></label><input ref={responseImage} hidden type="file" accept="image/*" capture="environment" onChange={(event) => void scanResponse(event.target.files?.[0])} /><button className="secondary wide" onClick={() => responseImage.current?.click()}><Hash size={16} /> Scan response QR</button><button className="primary wide" onClick={inspect} disabled={!response.trim()}>Open response</button></> : <><p>Compare this code on both devices before confirming:</p><code>{opened.sas}</code><label>Local vault passphrase<input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label><label>Confirm passphrase<input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label><button className="primary wide" onClick={finish}>Codes match — link device</button></>}{error && <p className="form-error"><CircleAlert size={16} />{error}</p>}<button className="text-button" onClick={onCancel}>Cancel</button></section></main>;
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

interface ModalProps { title: string; children: React.ReactNode; onClose(): void }
function Modal({ title, children, onClose }: ModalProps) {
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className="modal" role="dialog" aria-modal="true"><header><h2>{title}</h2><button className="icon-button" onClick={onClose}><X /></button></header>{children}</section></div>;
}

function Messenger({ initial, passphrase, onLock }: { initial: AccountState; passphrase: string; onLock(): void }) {
  const [account, setAccount] = useState(initial);
  const accountRef = useRef(account);
  const [selectedId, setSelectedId] = useState(initial.contacts.find((contact) => contact.status === "accepted")?.id ?? "");
  const [dialog, setDialog] = useState<Dialog>(null);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [online, setOnline] = useState(navigator.onLine);
  const [mobileList, setMobileList] = useState(true);
  const [inviteValue, setInviteValue] = useState("");
  const [inviteQr, setInviteQr] = useState("");
  const [busy, setBusy] = useState(false);
  const [linkSetup, setLinkSetup] = useState<{ pairingId: string; qr: string; qrImage: string; sas: string; linkSecret: string; downlinkCap: string; downlinkCapId: string; uplinkCapId: string }>();
  const syncing = useRef(false);
  const syncFailures = useRef(0);
  const resumedPendingRotation = useRef(false);
  accountRef.current = account;

  const persist = useCallback(async (next: AccountState) => {
    accountRef.current = next; setAccount(next); await saveVault(next, passphrase);
  }, [passphrase]);

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

  const ownServer = ownOrigin(account.onionOrigin, account.httpsOrigin);
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

  const poll = useCallback(async () => {
    if (!navigator.onLine || syncing.current) return;
    syncing.current = true;
    try {
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
  }, [persist, selectedId, sendReceipt, runExclusive]);

  useEffect(() => { void poll(); const timer = window.setInterval(() => void poll(), 5_000); return () => clearInterval(timer); }, [poll]);

  const selectContact = async (contact: ContactRecord) => {
    setSelectedId(contact.id); setMobileList(false);
    if (contact.unread) await runExclusive(async () => { const next = structuredClone(accountRef.current); const match = next.contacts.find((item) => item.id === contact.id); if (match) match.unread = 0; await persist(next); });
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
    setLinkSetup(undefined); setDialog("settings");
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
      await runExclusive(async () => {
        const base = accountRef.current;
        const invite = parseContactInvitation(value);
        if (base.contacts.some((contact) => contact.identityPublicKey === invite.identityPublicKey)) throw new Error("This contact is already in your Blackspace.");
        const target: DepositTarget = { onion_url: invite.onionOrigin, https_url: invite.httpsOrigin, deposit_capability: invite.capability };
        const claimed = await claimKeyPackage(target);
        validateClaimedPackage(claimed, invite.identityPublicKey);
        const returnCapability = randomCapability();
        const returnGrant = await createDepositCapability(ownServer, base.adminCapability, await capabilityVerifier("deposit", returnCapability));
        const replyInvitation = formatContactInvitation({ onion_url: base.onionOrigin, https_url: base.httpsOrigin, deposit_capability: returnCapability }, base.identityPublicKey, crypto.randomUUID());
        const messageId = crypto.randomUUID();
        const content: SecureContent = { version: 1, type: "profile", messageId, sentAt: Date.now(), senderIdentity: base.identityPublicKey, displayName: base.displayName, replyInvitation, body: firstMessage.trim() || "Hello — I added you on Blackspace." };
        const bootstrap = await mlsStart(accountRef.current.mlsClientState, invite.identityPublicKey, claimed.key_package, await encodeSecureContent(content));
        const contact: ContactRecord = { id: crypto.randomUUID(), identityPublicKey: invite.identityPublicKey, displayName: "New contact", status: "accepted", verified: false, unread: 0, draft: "", target, mlsGroupId: bootstrap.group_id, inboundCapabilityId: returnGrant.capability_id, lastMessageAt: content.sentAt };
        const pendingEnvelope = envelopeForPacket({ kind: "mls_bootstrap", welcome: bootstrap.welcome, firstMessage: bootstrap.first_message });
        const next = structuredClone(accountRef.current); next.mlsClientState = bootstrap.client_state; next.contacts.push(contact); next.messages.push({ id: messageId, contactId: contact.id, direction: "outgoing", body: content.body!, sentAt: content.sentAt, delivery: "queued", pendingEnvelope });
        await persist(next);
        try {
          await depositEnvelope(target, pendingEnvelope);
          const sent = structuredClone(accountRef.current); const message = sent.messages.find((item) => item.id === messageId); if (message) { message.delivery = "server-accepted"; message.pendingEnvelope = undefined; } await persist(sent);
        } catch (cause) {
          const failed = structuredClone(accountRef.current); const message = failed.messages.find((item) => item.id === messageId); if (message) { message.delivery = navigator.onLine ? "failed" : "queued"; message.error = navigator.onLine ? errorMessage(cause, "Send failed") : undefined; } await persist(failed);
        }
        setSelectedId(contact.id); setDialog(null); setMobileList(false);
      });
      await queueMirrorSnapshot();
    } catch (cause) { setError(errorMessage(cause, "Could not add the contact.")); }
    finally { setBusy(false); }
  };

  const sendMessage = async () => {
    if (!selected?.mlsGroupId || !selected.draft.trim()) return;
    const body = selected.draft.trim(); const messageId = crypto.randomUUID(); const sentAt = Date.now(); const contactId = selected.id;
    await runExclusive(async () => {
      let next = structuredClone(accountRef.current); const contact = next.contacts.find((item) => item.id === contactId); if (!contact?.mlsGroupId) return; contact.draft = ""; contact.lastMessageAt = sentAt;
      try {
        const content: SecureContent = { version: 1, type: "text", messageId, sentAt, senderIdentity: next.identityPublicKey, body };
        const encrypted = await mlsCreateMessage(next.mlsClientState, contact.mlsGroupId, await encodeSecureContent(content));
        const pendingEnvelope = envelopeForPacket({ kind: "mls", hint: await mlsGroupHint(contact.mlsGroupId), message: encrypted.message });
        next.mlsClientState = encrypted.client_state; next.messages.push({ id: messageId, contactId: contact.id, direction: "outgoing", body, sentAt, delivery: "queued", pendingEnvelope }); await persist(next);
        await depositEnvelope(contact.target, pendingEnvelope);
        next = structuredClone(accountRef.current); const message = next.messages.find((item) => item.id === messageId); if (message) { message.delivery = "server-accepted"; message.pendingEnvelope = undefined; } await persist(next);
      } catch (cause) {
        next = structuredClone(accountRef.current); const message = next.messages.find((item) => item.id === messageId); if (message) { message.delivery = navigator.onLine ? "failed" : "queued"; message.error = navigator.onLine ? errorMessage(cause, "Send failed") : undefined; } else { next.messages.push({ id: messageId, contactId, direction: "outgoing", body, sentAt, delivery: "failed", error: errorMessage(cause, "Encryption failed") }); } await persist(next);
      }
    });
    await queueMirrorSnapshot();
  };

  const retryMessage = async (message: MessageRecord) => runExclusive(async () => {
    const contact = accountRef.current.contacts.find((item) => item.id === message.contactId);
    // Re-read the outbox record inside the lock — the render-time prop may be
    // stale if a poll already delivered or cleared this message.
    const record = accountRef.current.messages.find((item) => item.id === message.id);
    if (!contact?.mlsGroupId || !record || record.delivery !== "failed") return;
    let next = structuredClone(accountRef.current); const pending = next.messages.find((item) => item.id === message.id); if (pending) { pending.delivery = "queued"; pending.error = undefined; } await persist(next);
    try {
      if (!record.pendingEnvelope) throw new Error("The encrypted outbox record is unavailable.");
      await depositEnvelope(contact.target, record.pendingEnvelope);
      next = structuredClone(accountRef.current); const sent = next.messages.find((item) => item.id === message.id); if (sent) { sent.delivery = "server-accepted"; sent.pendingEnvelope = undefined; } await persist(next);
    } catch (cause) {
      next = structuredClone(accountRef.current); const failed = next.messages.find((item) => item.id === message.id); if (failed) { failed.delivery = "failed"; failed.error = errorMessage(cause, "Send failed"); } await persist(next);
    }
  });

  const updateDraft = (value: string) => {
    const next = structuredClone(account); const contact = next.contacts.find((item) => item.id === selectedId); if (contact) contact.draft = value; setAccount(next);
  };

  const blockContact = async (contactId: string) => {
    const changed = await runExclusive(async () => {
      const next = structuredClone(accountRef.current); const contact = next.contacts.find((item) => item.id === contactId);
      if (!contact) return false;
      if (contact.inboundCapabilityId) await revokeDepositCapability(ownServer, next.adminCapability, contact.inboundCapabilityId);
      contact.status = "blocked"; contact.draft = ""; await persist(next); setSelectedId("");
      return true;
    });
    if (changed) await queueMirrorSnapshot();
  };

  const acceptRequest = async (accepted: boolean) => {
    if (!selected) return;
    if (!accepted) {
      try { await blockContact(selected.id); }
      catch (cause) { setError(errorMessage(cause, "Could not revoke this contact's mailbox access.")); }
      return;
    }
    const contactId = selected.id;
    await runExclusive(async () => {
      let next = structuredClone(accountRef.current); const contact = next.contacts.find((item) => item.id === contactId); if (!contact) return;
      contact.status = "accepted"; await persist(next);
      if (contact.mlsGroupId) {
        try {
          const content: SecureContent = { version: 1, type: "profile", messageId: crypto.randomUUID(), sentAt: Date.now(), senderIdentity: next.identityPublicKey, displayName: next.displayName };
          const encrypted = await mlsCreateMessage(next.mlsClientState, contact.mlsGroupId, await encodeSecureContent(content)); next = structuredClone(accountRef.current); next.mlsClientState = encrypted.client_state; await persist(next);
          await depositEnvelope(contact.target, envelopeForPacket({ kind: "mls", hint: await mlsGroupHint(contact.mlsGroupId), message: encrypted.message }));
        } catch (cause) { setError(errorMessage(cause, "The contact was accepted, but your profile could not be sent.")); }
      }
    });
    await queueMirrorSnapshot();
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
      <span className="rail-spacer" /><button className="avatar small" onClick={() => setDialog("settings")}>{initials(account.displayName)}</button>
    </aside>
    <aside className={`conversation-sidebar ${mobileList ? "mobile-visible" : ""}`}>
      <header className="workspace-header"><div><span className="eyebrow">PRIVATE WORKSPACE</span><h1>{account.instanceName}</h1></div><button className="icon-button" onClick={() => setDialog("settings")}><Settings /></button></header>
      <div className="search-box"><Search /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search conversations" /></div>
      <nav className="primary-nav"><div className="active"><MessageCircle /> Direct messages <span>{conversations.reduce((sum, contact) => sum + contact.unread, 0) || ""}</span></div><div><Inbox /> Message requests <span>{requests.length || ""}</span></div></nav>
      {requests.length > 0 && <ContactSection title="Requests" contacts={requests} selectedId={selectedId} onSelect={selectContact} />}
      <ContactSection title="Direct messages" contacts={conversations} selectedId={selectedId} onSelect={selectContact} />
      {!filtered.length && <div className="sidebar-empty"><Users /><p>No conversations yet.</p></div>}
      <div className="sidebar-actions"><button className="secondary" onClick={() => setDialog("add")}><UserPlus /> Add contact</button><button className="icon-button" onClick={makeInvite} disabled={busy} title="Create invitation"><Plus /></button></div>
      <footer><ModeBadge /><span className={`network-dot ${online ? "online" : ""}`} />{online ? "Connected" : "Offline"}</footer>
    </aside>
    <section className={`chat-panel ${!mobileList ? "mobile-visible" : ""}`}>
      {selected ? <>
        <header className="chat-header"><button className="icon-button mobile-back" onClick={() => setMobileList(true)}><ArrowLeft /></button><div className="avatar">{initials(selected.localName ?? selected.displayName)}</div><div><h2>{selected.localName ?? selected.displayName}</h2><p>{selected.verified ? <><ShieldCheck size={13} /> Identity verified</> : "Identity not verified"}</p></div><span className="chat-spacer" /><button className="icon-button" onClick={() => setDialog("security")}><Fingerprint /></button></header>
        {selected.status === "request" && <div className="request-banner"><div><strong>New message request</strong><span>Review the message and verify this contact before sharing sensitive information.</span></div><button className="secondary" onClick={() => acceptRequest(false)}>Block</button><button className="primary" onClick={() => acceptRequest(true)}>Accept</button></div>}
        <div className="message-scroll">
          <div className="conversation-start"><div className="avatar hero-avatar">{initials(selected.displayName)}</div><h2>{selected.displayName}</h2><p>This is the beginning of your private Blackspace conversation.</p><button className="text-button" onClick={() => setDialog("security")}><Fingerprint /> Verify identity</button></div>
          {messages.map((message, index) => <MessageItem key={message.id} message={message} previous={messages[index - 1]} contact={selected} onRetry={retryMessage} />)}
        </div>
        <div className="composer-wrap"><div className="composer"><textarea value={selected.draft} onChange={(event) => updateDraft(event.target.value)} onBlur={() => void persist(accountRef.current)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void sendMessage(); } }} maxLength={16_384} placeholder={`Message ${selected.localName ?? selected.displayName}`} rows={1} disabled={selected.status === "request"} /><span>{selected.draft.length > 14_000 ? `${selected.draft.length}/16384` : "Enter to send"}</span><button className="send-button" onClick={sendMessage} disabled={!selected.draft.trim() || selected.status === "request"}><Send /></button></div></div>
      </> : <EmptyChat onAdd={() => setDialog("add")} onInvite={makeInvite} />}
    </section>
    {dialog === "add" && <AddContactModal busy={busy} onAdd={addContact} onClose={() => setDialog(null)} />}
    {dialog === "invite" && <InviteModal value={inviteValue} qr={inviteQr} onClose={() => setDialog(null)} />}
    {dialog === "settings" && <SettingsModal account={account} mode={transportMode ? modeLabel(transportMode) : "Blocked"} onExport={exportRecovery} onLink={() => setDialog("link")} onUnlink={() => void unlinkDevice().catch((cause) => setError(errorMessage(cause, "Could not unlink this device.")))} onLock={onLock} onClose={() => setDialog(null)} />}
    {dialog === "link" && <LinkDeviceModal setup={linkSetup} onPrepare={(code) => void prepareDeviceLink(code).catch((cause) => setError(errorMessage(cause, "Could not prepare device pairing.")))} onConfirm={() => void confirmDeviceLink().catch((cause) => setError(errorMessage(cause, "Could not finish device pairing.")))} onClose={() => void cancelDeviceLink()} />}
    {dialog === "security" && selected && <SecurityModal account={account} contact={selected} onNickname={async (nickname) => runExclusive(async () => { const next = structuredClone(accountRef.current); const match = next.contacts.find((item) => item.id === selected.id); if (match) match.localName = nickname.trim() || undefined; await persist(next); })} onBlock={async () => { if (confirm(`Block ${selected.localName ?? selected.displayName} and revoke their mailbox access?`)) { try { await blockContact(selected.id); setDialog(null); } catch (cause) { setError(errorMessage(cause, "Could not block this contact.")); } } }} onVerified={async () => { await runExclusive(async () => { const next = structuredClone(accountRef.current); const match = next.contacts.find((item) => item.id === selected.id); if (match) match.verified = true; await persist(next); }); setDialog(null); }} onClose={() => setDialog(null)} />}
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
    <div className="message-body">{!grouped && <div className="message-meta"><strong>{message.direction === "system" ? "Blackspace" : message.direction === "outgoing" ? "You" : contact.localName ?? contact.displayName}</strong><span>{formatDay(message.sentAt)} at {formatTime(message.sentAt)}</span></div>}<div className="bubble">{message.body}</div>{message.direction === "outgoing" && <span className={`delivery ${message.delivery}`}>{message.delivery === "delivered" ? <CheckCheck /> : message.delivery === "failed" ? <CircleAlert /> : <Check />}{message.delivery.replace("-", " ")}{message.delivery === "failed" && <button className="retry-link" onClick={() => onRetry(message)}>Retry</button>}</span>}</div>
  </div>;
}

function EmptyChat({ onAdd, onInvite }: { onAdd(): void; onInvite(): void }) {
  return <div className="empty-chat"><div className="empty-orbit"><MessageCircle /></div><span className="eyebrow">WELCOME TO BLACKSPACE</span><h2>Start a private conversation</h2><p>Add someone using their contact invitation, or create an invitation for someone you trust.</p><div><button className="primary" onClick={onAdd}><UserPlus /> Add a contact</button><button className="secondary" onClick={onInvite}><Copy /> Create invitation</button></div><small><Lock /> Messages are encrypted before they leave this device.</small></div>;
}

function AddContactModal({ busy, onAdd, onClose }: { busy: boolean; onAdd(value: string, first: string): void; onClose(): void }) {
  const [value, setValue] = useState(""); const [first, setFirst] = useState("");
  const imageInput = useRef<HTMLInputElement>(null);
  const scan = async (file?: File) => {
    if (!file) return;
    try { setValue(await scanQr(file)); } catch (cause) { alert(errorMessage(cause, "Could not scan this QR code.")); }
  };
  return <Modal title="Add a contact" onClose={onClose}><div className="modal-content"><div className="modal-icon"><UserPlus /></div><p>Paste the invitation shared directly by your contact. Blackspace verifies their signed key package before sending.</p><label>Contact invitation<textarea rows={5} value={value} onChange={(event) => setValue(event.target.value)} placeholder="blackspace://contact/v1?onion=…#cap=…" spellCheck={false} /></label><input ref={imageInput} hidden type="file" accept="image/*" capture="environment" onChange={(event) => void scan(event.target.files?.[0])} /><button className="secondary wide" onClick={() => imageInput.current?.click()}><Hash size={16} /> Scan invitation QR</button><label>First message<textarea rows={3} value={first} maxLength={16_384} onChange={(event) => setFirst(event.target.value)} placeholder="Hello…" /></label><div className="modal-actions"><button className="secondary" onClick={onClose}>Cancel</button><button className="primary" onClick={() => onAdd(value, first)} disabled={busy || !value.trim()}>{busy ? "Establishing session…" : "Add and send"}</button></div></div></Modal>;
}

function InviteModal({ value, qr, onClose }: { value: string; qr: string; onClose(): void }) {
  const [copied, setCopied] = useState(false);
  return <Modal title="Your contact invitation" onClose={onClose}><div className="invite-modal"><p>Share this invitation with one person through a trusted channel. It grants write-only access to your mailbox.</p>{qr && <img src={qr} alt="Blackspace contact invitation QR code" />}<textarea readOnly value={value} rows={5} /><button className="primary wide" onClick={async () => { await navigator.clipboard.writeText(value); setCopied(true); }}>{copied ? <><Check /> Copied</> : <><Copy /> Copy invitation</>}</button><small>Revoke this invitation if it is exposed or abused.</small></div></Modal>;
}

function SettingsModal({ account, mode, onExport, onLink, onUnlink, onLock, onClose }: { account: AccountState; mode: string; onExport(): void; onLink(): void; onUnlink(): void; onLock(): void; onClose(): void }) {
  return <Modal title="Settings" onClose={onClose}><div className="settings-profile"><span className="avatar large">{initials(account.displayName)}</span><div><h3>{account.displayName}</h3><p>{account.instanceName}</p></div></div><div className="settings-list"><div><Server /><span><strong>Transport</strong><small>{mode}</small></span></div><div><KeyRound /><span><strong>Identity</strong><small>{account.identityPublicKey.slice(0, 18)}…</small></span></div><div><Archive /><span><strong>Local vault</strong><small>Encrypted browser storage</small></span></div></div><div className="modal-actions stack">{account.companionLink?.active ? <button className="secondary wide danger-action" onClick={onUnlink}><Users /> Unlink companion</button> : <button className="secondary wide" onClick={onLink}><Users /> Link a companion</button>}<button className="secondary wide" onClick={onExport}><Download /> Export encrypted recovery kit</button><button className="secondary wide" onClick={onLock}><LogOut /> Lock Blackspace</button></div><p className="alpha-warning"><CircleAlert /> Private alpha: browser storage cannot guarantee physical erasure of old encrypted pages.</p></Modal>;
}

function LinkDeviceModal({ setup, onPrepare, onConfirm, onClose }: { setup?: { qr: string; qrImage: string; sas: string }; onPrepare(code: string): void; onConfirm(): void; onClose(): void }) {
  const [offer, setOffer] = useState("");
  const offerImage = useRef<HTMLInputElement>(null);
  const [scanError, setScanError] = useState("");
  const scanOffer = async (file?: File) => {
    if (!file) return;
    try { setOffer(await scanQr(file)); setScanError(""); }
    catch (cause) { setScanError(errorMessage(cause, "Could not scan the companion offer.")); }
  };
  return <Modal title="Link a companion" onClose={onClose}><div className="modal-content">{!setup ? <><p>Paste or scan the temporary code shown by the companion. It contains no reusable account secret.</p><label>Companion offer<textarea rows={5} value={offer} onChange={(event) => setOffer(event.target.value)} /></label><input ref={offerImage} hidden type="file" accept="image/*" capture="environment" onChange={(event) => void scanOffer(event.target.files?.[0])} /><button className="secondary wide" onClick={() => offerImage.current?.click()}><Hash size={16} /> Scan companion QR</button>{scanError && <p className="form-error"><CircleAlert size={16} />{scanError}</p>}<button className="primary wide" onClick={() => onPrepare(offer)} disabled={!offer.trim()}>Create encrypted response</button></> : <><p>Show this response to the companion, then compare the six-digit code on both devices.</p><img className="pairing-qr" src={setup.qrImage} alt="Encrypted primary pairing response" /><textarea readOnly rows={5} value={setup.qr} /><code>{setup.sas}</code><button className="primary wide" onClick={onConfirm}>Codes match — finish linking</button></>}<button className="secondary wide" onClick={onClose}>Cancel</button></div></Modal>;
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
      <div className="message-scroll">{messages.map((message) => <div key={message.id} className={`message-row ${message.direction}`}><div className="message-body"><div className="bubble">{message.body}</div>{message.direction === "outgoing" && <span className={`delivery ${message.delivery}`}>{message.delivery.replace("-", " ")}{message.delivery === "failed" && <button className="retry-link" onClick={() => relay({ type: "retry_message", commandId: crypto.randomUUID(), ts: Date.now(), messageId: message.id })}>Retry</button>}</span>}</div></div>)}</div>
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
  return <Messenger initial={account} passphrase={passphrase} onLock={() => { lockVault(); setAccount(null); setPassphrase(""); setScreen("locked"); }} />;
}
