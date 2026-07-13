const SAFE_TAURI_ERRORS = [
  /^Tor is not ready\./,
  /^Tor SOCKS listener is unavailable\.$/,
  /^Tor request timed out\.$/,
  /^Tor request failed\.$/,
  /^Could not connect to the onion service through Tor\.$/,
  /^Could not configure the managed Tor proxy\.$/,
  /^Could not initialize the Tor HTTP client\.$/,
  /^Could not encode the encrypted envelope\.$/,
  /^Mailbox returned an invalid response\.$/,
  /^Mailbox operation failed with status \d{3}\.$/,
  /^Mailbox rejected an invalid request \(status \d{3}\)\.$/,
  /^Mailbox authorization failed \(status \d{3}\)\.$/,
  /^Mailbox delivery is temporarily unavailable \(status \d{3}\)\.$/,
  /^Mailbox could not complete the operation \(status \d{3}\)\.$/,
  /^Capability revocation failed\.$/,
];

export function errorMessage(cause: unknown, fallback: string): string {
  if (cause instanceof Error) return cause.message;
  if (typeof cause === "string" && SAFE_TAURI_ERRORS.some((pattern) => pattern.test(cause))) return cause;
  return fallback;
}

// Plain-language explanation for an error message, framed in Blackspace's own terms
// (capabilities, the self-hosted mailbox, Tor). Returned as extra detail the UI can
// reveal on demand — never leaks server internals, since it is keyed only off the
// status code / known message already shown to the user. Undefined when there is
// nothing useful to add beyond the message itself.
const STATUS_HELP: Record<string, string> = {
  "400": "The server rejected the request as malformed. This usually means a version mismatch between this app and your mailbox — rebuild and redeploy the server, or reload the app to pick up the latest build.",
  "401": "Your device presented a capability the mailbox no longer accepts. Capabilities are rotated or revoked when a device is unlinked, a companion is removed, or the mailbox is recovered — so a linked device can see this after another device changed access. Fixes: lock and unlock this device, and if it persists, re-add (enroll) this device from one that still works.",
  "403": "The mailbox refused this action for the capability presented. The capability is valid but not permitted to do this — check you are using an admin-capable device for device or mailbox management.",
  "404": "The mailbox has no such resource. For enrollment this means the parcel expired or was already claimed — generate a fresh enrollment code on the new device.",
  "409": "The request conflicted with the mailbox's current state — for shared multi-device state this is a normal, self-healing race (another device wrote first) and retries automatically. If you see it surfaced, the retry budget was exhausted; try again.",
  "413": "The message or blob exceeded the server's size limit.",
  "429": "The mailbox is rate-limiting deposits (more than 30 per minute for one capability). Wait a moment and retry.",
  "500": "The mailbox hit an internal error. Check the mailbox container logs on your server.",
  "503": "Delivery is temporarily unavailable — the mailbox is reachable but can't accept this right now (a full queue, an expired deposit capability, or Tor not yet ready). It should clear on its own; retry shortly.",
};

export function explainErrorMessage(message: string): string | undefined {
  const status = message.match(/\((\d{3})\)|status (\d{3})/);
  const code = status?.[1] ?? status?.[2];
  if (code && STATUS_HELP[code]) return STATUS_HELP[code];
  if (/Tor is not ready/i.test(message)) return "Blackspace is waiting for Tor to finish bootstrapping before it will send anything over the network — it refuses to fall back to a direct (deanonymizing) connection. This clears once Tor is connected.";
  if (/empty response|invalid JSON|could not be reached|Failed to fetch/i.test(message)) return "The app could not reach your mailbox. Check that your server is running and reachable at its onion/HTTPS address, and that you are online.";
  return undefined;
}
