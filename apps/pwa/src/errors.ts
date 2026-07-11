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
