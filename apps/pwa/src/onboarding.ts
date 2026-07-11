import { errorMessage } from "./errors";

export type OnboardingStage = "server check" | "mailbox registration" | "encrypted local storage";

export function onboardingError(cause: unknown, stage: OnboardingStage): string {
  const browserError = cause && typeof cause === "object"
    ? cause as { name?: unknown; message?: unknown }
    : undefined;
  const aborted = browserError
    && (browserError.name === "AbortError"
      || (typeof browserError.message === "string" && /operation was aborted/i.test(browserError.message)));
  if (aborted) {
    if (stage === "server check") {
      return "Tor Browser interrupted the server check. Retry signup; the invitation has not been consumed.";
    }
    return `Tor Browser interrupted ${stage}. Retry without changing the invitation or display name; Blackspace will safely resume the same signup attempt.`;
  }
  return errorMessage(cause, "Onboarding failed.");
}
