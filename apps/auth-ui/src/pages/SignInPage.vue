<script setup lang="ts">
import { Alert, AlertDescription, AlertTitle, Badge, Button, Input, Label, ScopeBadge, Skeleton } from "@monaca/ui";
import {
  AlertCircle,
  ArrowLeft,
  Building2,
  Check,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  LockKeyhole,
  Mail,
  ShieldCheck,
} from "lucide-vue-next";
import { computed, nextTick, onMounted, ref, watch } from "vue";

import {
  InteractionError,
  getInteraction,
  getSignInExperience,
  submitSignIn,
  verifyMfa,
  getPasskeySignInOptions,
  verifyPasskeySignIn,
  getMfaPasskeyOptions,
  verifyMfaPasskey,
  submitConsent,
  abortInteraction,
  navigateTo,
  startSignUp,
  verifySignUp,
  requestSignInCode,
  requestSignInLink,
  verifySignInCode,
  requestPasswordReset,
  resetPassword,
  startMfaEnrollment,
  verifyMfaEnrollment,
  type InteractionDetails,
  type MfaEnrollment,
  type SignInExperience,
  type SignInResult,
} from "@/api/interaction";
import { PasskeyError, getPasskeyAssertion, passkeysSupported } from "@/api/webauthn";
import {
  listSocialConnectors,
  socialSignInUrl,
  type SocialConnector,
} from "@/api/social";
import { findSsoConnector, ssoSignInUrl, type SsoConnector } from "@/api/sso";
import { t } from "@/i18n";
import type { MessageKey } from "@/i18n";

/**
 * Hosted sign-in.
 *
 * The one page a person meets before they trust the product, so it follows one rule: never leave the
 * visitor guessing what they are agreeing to. The card states which application is asking, for which
 * organization, and which scopes — before the password field, not after it.
 *
 * Interaction state is fetched once on mount. Two branches matter and both are handled explicitly:
 *
 * - **The interaction is gone** (404 / 410 / 409). This is the expected state in stage 0, because the
 *   server does not exist yet, and it is also what a user sees after a stale bookmark. It is rendered
 *   as an explanation with a way back, never as a stack trace or a bare spinner.
 * - **Credentials are rejected** (401). Rendered inline next to the fields, with the password
 *   cleared and the email kept — retyping an email is pure friction, and the contract returns the
 *   same response for an unknown email and a wrong password, so nothing is disclosed either way.
 */
const interactionId = ref<string | null>(null);
const tenantFromUrl = ref<string | null>(null);

const details = ref<InteractionDetails | null>(null);
const loading = ref(true);
const loadError = ref<InteractionError | Error | null>(null);

const email = ref("");
const password = ref("");
const revealPassword = ref(false);
const submitting = ref(false);
const cancelling = ref(false);
const fieldError = ref<MessageKey | null>(null);
const submitError = ref<InteractionError | null>(null);

/** Set once sign-in succeeds for a flow that still needs approval. */
const consentRequired = ref(false);
const consentSubmitting = ref(false);
const consentError = ref<Error | null>(null);

/** Set once the password (or code) was accepted and the authenticator is still owed. */
const mfaRequired = ref(false);
const mfaCode = ref("");
const mfaSubmitting = ref(false);
const mfaError = ref<InteractionError | null>(null);
const mfaInput = ref<InstanceType<typeof Input> | null>(null);
/** Which factors this challenge accepts; `backup_code` unlocks the recovery-code form. */
const mfaFactors = ref<string[]>([]);
const useBackupCode = ref(false);
/** When checked, the code step also leaves a thirty-day trust for this browser. */
const rememberDevice = ref(false);

/** The recovery-code toggle is offered only when the account actually has unused codes. */
const backupCodeAvailable = computed(() => mfaFactors.value.includes("backup_code"));

/** Passkey support is a browser fact, resolved once; a browser without it never sees the option. */
const passkeyAvailable = ref(passkeysSupported());
const passkeyBusy = ref(false);
const passkeyError = ref<PasskeyError | null>(null);
/** The second-factor answer by passkey, kept apart so it does not overwrite the code form's state. */
const mfaPasskeyBusy = ref(false);
const mfaPasskeyError = ref<PasskeyError | InteractionError | null>(null);

/**
 * Mandatory-policy enrollment.
 *
 * The tenant requires a second factor and this account has none, so the page walks it through
 * scanning an authenticator. The secret is held only for this interaction; proving it finishes the
 * sign-in, and the next visit is challenged normally.
 */
const mfaEnrollmentRequired = ref(false);
const enrollment = ref<MfaEnrollment | null>(null);
const enrollmentLoading = ref(false);
const enrollmentCode = ref("");
const enrollmentSubmitting = ref(false);
const enrollmentError = ref<MessageKey | null>(null);
const enrollmentServerError = ref<InteractionError | null>(null);
const enrollmentInput = ref<InstanceType<typeof Input> | null>(null);

/** Only an account that registered a passkey is offered it, and not while a backup code is in use. */
const mfaPasskeyAvailable = computed(
  () => passkeyAvailable.value && mfaFactors.value.includes("passkey") && !useBackupCode.value,
);

/** A dismissed system prompt is not a failure; nothing is shown for it. */
const passkeyErrorMessage = computed<MessageKey | null>(() => {
  const error = passkeyError.value;
  if (!error || error.reason === "cancelled") return null;
  return error.reason === "unavailable" ? "errors.passkeyUnsupported" : "errors.passkeyFailed";
});

const mfaPasskeyErrorMessage = computed<MessageKey | null>(() => {
  const error = mfaPasskeyError.value;
  if (!error) return null;
  if (error instanceof PasskeyError) {
    if (error.reason === "cancelled") return null;
    return error.reason === "unavailable" ? "errors.passkeyUnsupported" : "errors.passkeyFailed";
  }
  switch (error.code) {
    case "MONACA_TOO_MANY_ATTEMPTS":
      return "errors.mfaTooManyAttempts";
    case "MONACA_INTERACTION_EXPIRED":
      return "errors.interactionExpired";
    case "MONACA_INTERACTION_CONSUMED":
      return "errors.interactionConsumed";
    case "MONACA_INTERACTION_NOT_FOUND":
      return "errors.interactionNotFound";
    case "MONACA_UNREACHABLE":
      return "errors.network";
    default:
      return "errors.passkeyRejected";
  }
});

/**
 * Which authentication flow the page is showing. The interaction is the same in all four; only the
 * proof of identity changes (password, an emailed code, a new account, a password reset).
 */
type Mode = "password" | "code" | "signup" | "reset";
const mode = ref<Mode>("password");
/** `request` collects an address and mails a code; `verify` collects the code (and new secrets). */
const stage = ref<"request" | "verify">("request");
const code = ref("");
const codeRequested = ref(false);
/** The link alternative: one request per visit, with the notice shown until the mode changes. */
const linkSubmitting = ref(false);
const linkSent = ref(false);
const newPassword = ref("");
const displayName = ref("");
/** Optional username chosen at sign-up; the account can also set it later in the account centre. */
const username = ref("");

/** Provider buttons; the tenant's public list is fetched once and never blocks the page. */
const socialConnectors = ref<SocialConnector[]>([]);

/**
 * Enterprise SSO routing.
 *
 * The connector that owns the typed address's domain, if any. A matching address is sent to the
 * provider before the password form can be submitted — the tenant cannot check a password it does
 * not hold. The redirect happens at most once per interaction: the provider round-trip returns to
 * this page on failure, and a page that redirected again on load would loop.
 */
const ssoConnector = ref<SsoConnector | null>(null);
const ssoRedirecting = ref(false);
let ssoLookupToken = 0;

/**
 * The tenant's hosted switches. `null` means "everything is offered": a failed read must not lock
 * a signing-in visitor out, so the flags default to true until the request answers.
 */
const experience = ref<SignInExperience | null>(null);
const passwordAllowed = computed(() => experience.value?.password_sign_in_enabled ?? true);
const emailCodeAllowed = computed(() => experience.value?.email_code_sign_in_enabled ?? true);
const signUpAllowed = computed(() => experience.value?.sign_up_enabled ?? true);
/** The tenant's policy, defaulting to the contract's minimum when the read failed. */
const passwordMinLength = computed(() => experience.value?.password_min_length ?? 8);

const passwordInput = ref<InstanceType<typeof Input> | null>(null);
const emailInput = ref<InstanceType<typeof Input> | null>(null);
const codeInput = ref<InstanceType<typeof Input> | null>(null);

const brandName = computed(
  () => details.value?.client.name || details.value?.tenant || tenantFromUrl.value || t("brand.fallbackTenant"),
);
const organization = computed(() => details.value?.organization ?? null);
const scopes = computed(() => details.value?.scopes ?? []);

/** True while the page collects a code rather than an address. */
const awaitingCode = computed(() => mode.value !== "password" && stage.value === "verify");

const pageTitle = computed<MessageKey>(() => {
  if (consentRequired.value) return "consent.title";
  if (mfaEnrollmentRequired.value) return "mfaEnroll.title";
  if (mfaRequired.value) return "mfa.title";
  switch (mode.value) {
    case "code":
      return "emailCode.title";
    case "signup":
      return "signUp.title";
    case "reset":
      return "reset.title";
    default:
      return "signIn.title";
  }
});

/** The line under the title: what this flow will do. */
const modeNote = computed<MessageKey>(() => {
  if (consentRequired.value) return "consent.request";
  if (mfaEnrollmentRequired.value) return "mfaEnroll.note";
  if (mfaRequired.value) {
    if (useBackupCode.value) return "mfa.backupNote";
    return details.value ? "mfa.note" : "mfa.noteFallback";
  }
  switch (mode.value) {
    case "code":
      return "emailCode.note";
    case "signup":
      return "signUp.note";
    case "reset":
      return "reset.note";
    default:
      return "signIn.request";
  }
});

const newPasswordLabel = computed<MessageKey>(() =>
  mode.value === "reset" ? "reset.password" : "signUp.password",
);
const newPasswordHint = computed<MessageKey>(() =>
  mode.value === "reset" ? "reset.passwordHint" : "signUp.passwordHint",
);
const changeEmailKey = computed<MessageKey>(() => {
  switch (mode.value) {
    case "signup":
      return "signUp.changeEmail";
    case "reset":
      return "reset.changeEmail";
    default:
      return "emailCode.changeEmail";
  }
});

/** The primary button's label, which names the next step rather than a generic "continue". */
const primaryLabel = computed<MessageKey>(() => {
  switch (mode.value) {
    case "password":
      return submitting.value ? "signIn.submitting" : "signIn.submit";
    case "code":
      if (awaitingCode.value) return submitting.value ? "emailCode.verifying" : "emailCode.verify";
      return submitting.value ? "emailCode.sending" : "emailCode.send";
    case "signup":
      if (awaitingCode.value) return submitting.value ? "signUp.submitting" : "signUp.submit";
      return submitting.value ? "signUp.sending" : "signUp.continue";
    case "reset":
      if (awaitingCode.value) return submitting.value ? "reset.submitting" : "reset.submit";
      return submitting.value ? "reset.sending" : "reset.send";
  }
});

/**
 * Explain the failure in the user's terms. The specific messages matter here: "this request expired,
 * start again from the application" is actionable, while "410" is not.
 */
const missingInteractionId = computed(() => !interactionId.value || !tenantFromUrl.value);

const loadErrorTitle = computed<MessageKey>(() =>
  missingInteractionId.value ? "errors.missingInteraction" : "signIn.title",
);

const loadErrorMessage = computed<MessageKey>(() => {
  const error = loadError.value;
  if (error instanceof InteractionError) {
    switch (error.code) {
      case "MONACA_INTERACTION_NOT_FOUND":
        return "errors.interactionNotFound";
      case "MONACA_INTERACTION_EXPIRED":
        return "errors.interactionExpired";
      case "MONACA_INTERACTION_CONSUMED":
        return "errors.interactionConsumed";
      case "MONACA_UNREACHABLE":
        return "errors.network";
      default:
        return "errors.invalidRequest";
    }
  }
  return "errors.generic";
});

const mfaErrorMessage = computed<MessageKey>(() => {
  const error = mfaError.value;
  if (!error) return "errors.generic";
  switch (error.code) {
    case "MONACA_INVALID_VERIFICATION_CODE":
      return useBackupCode.value ? "errors.mfaInvalidBackupCode" : "errors.mfaInvalidCode";
    case "MONACA_TOO_MANY_ATTEMPTS":
      return "errors.mfaTooManyAttempts";
    case "MONACA_INTERACTION_EXPIRED":
      return "errors.interactionExpired";
    case "MONACA_INTERACTION_CONSUMED":
      return "errors.interactionConsumed";
    case "MONACA_INTERACTION_NOT_FOUND":
      return "errors.interactionNotFound";
    case "MONACA_UNREACHABLE":
      return "errors.network";
    default:
      return "errors.generic";
  }
});

/** The enrollment step reuses the second-factor vocabulary: the same six digits, the same failures. */
const enrollmentErrorMessage = computed<MessageKey>(() => {
  const error = enrollmentServerError.value;
  if (!error) return "errors.generic";
  switch (error.code) {
    case "MONACA_INVALID_VERIFICATION_CODE":
      return "errors.mfaInvalidCode";
    case "MONACA_TOO_MANY_ATTEMPTS":
      return "errors.mfaTooManyAttempts";
    case "MONACA_INTERACTION_EXPIRED":
      return "errors.interactionExpired";
    case "MONACA_INTERACTION_CONSUMED":
      return "errors.interactionConsumed";
    case "MONACA_INTERACTION_NOT_FOUND":
      return "errors.interactionNotFound";
    case "MONACA_UNREACHABLE":
      return "errors.network";
    default:
      return "errors.generic";
  }
});

const submitErrorMessage = computed<MessageKey>(() => {
  const error = submitError.value;
  if (!error) return "errors.generic";
  switch (error.code) {
    case "MONACA_INVALID_CREDENTIALS":
      return "errors.invalidCredentials";
    case "MONACA_ACCOUNT_EXISTS":
      return "errors.accountExists";
    case "MONACA_USERNAME_TAKEN":
      return "errors.usernameTaken";
    case "MONACA_WEAK_PASSWORD":
      return "errors.weakPassword";
    case "MONACA_INVALID_VERIFICATION_CODE":
      return "errors.invalidCode";
    case "MONACA_TOO_MANY_ATTEMPTS":
      return "errors.tooManyAttempts";
    case "MONACA_INTERACTION_EXPIRED":
      return "errors.interactionExpired";
    case "MONACA_INTERACTION_CONSUMED":
      return "errors.interactionConsumed";
    case "MONACA_UNREACHABLE":
      return "errors.network";
    default:
      return "errors.generic";
  }
});

onMounted(async () => {
  // The interaction id is read from the query string, where the authorize endpoint put it
  // (`{auth_ui}/sign-in?tenant=…&interaction=int_…`). It also accepts a path form so a future router
  // shape (`/sign-in/{tenant}/{iid}`) needs no change here.
  const params = new URLSearchParams(window.location.search);
  const pathMatch = /\/sign-in\/([^/]+)\/(int_[0-9a-z]+)/.exec(window.location.pathname);

  tenantFromUrl.value = params.get("tenant") ?? pathMatch?.[1] ?? null;
  interactionId.value = params.get("interaction") ?? pathMatch?.[2] ?? null;

  if (!interactionId.value || !tenantFromUrl.value) {
    loading.value = false;
    loadError.value = new InteractionError("MONACA_INVALID_REQUEST", "the request is missing its interaction id", {
      status: 0,
      problem: { title: t("errors.missingInteraction") },
    });
    return;
  }

  try {
    details.value = await getInteraction(tenantFromUrl.value, interactionId.value);
    // A `login_hint` from the authorize request prefills the identifier. It stays editable: it is
    // a hint about who the client expects, not an assertion about who this browser is.
    if (details.value.login_hint) {
      email.value = details.value.login_hint;
    }
    // A valid SSO session already authenticated this interaction; only the consent step remains.
    if (details.value.signed_in && details.value.consent_required) {
      consentRequired.value = true;
    }
    // A page reload after the password was accepted must resume the second-factor step rather than
    // ask for the password again (§6.1 `mfa`).
    if (details.value.mfa_required) {
      mfaRequired.value = true;
      mfaFactors.value = details.value.mfa_factors;
      rememberDevice.value = false;
    }
    // A reload during a mandatory enrollment resumes the setup step instead of the password form.
    if (details.value.mfa_enrollment_required) {
      void beginEnrollment();
    }
    // The switches decide which forms the page offers. A failed read keeps every method so a
    // transient error cannot keep a visitor from signing in.
    try {
      experience.value = await getSignInExperience(tenantFromUrl.value);
      if (!experience.value.password_sign_in_enabled && experience.value.email_code_sign_in_enabled) {
        mode.value = "code";
      }
    } catch {
      experience.value = null;
    }
    socialConnectors.value = await listSocialConnectors(tenantFromUrl.value);
    // A prefilled `login_hint` may already name a federated domain; route it without waiting for a
    // keystroke. The call is fire-and-forget: the ordinary form stays usable until it answers.
    if (email.value.trim().length > 0) void checkSso(email.value.trim());
  } catch (error) {
    loadError.value = error instanceof Error ? error : new Error(String(error));
  } finally {
    loading.value = false;
    await nextTick();
    if (!loadError.value) {
      if (mfaRequired.value) mfaInput.value?.$el?.focus?.();
      else if (mfaEnrollmentRequired.value) enrollmentInput.value?.$el?.focus?.();
      // With a prefilled identifier the password is the only thing left to type.
      else if (details.value?.login_hint && mode.value === "password") passwordInput.value?.$el?.focus?.();
      else emailInput.value?.$el?.focus?.();
    }
  }
});

/** Hand the browser to the provider; the callback returns to this interaction. */
function signInWithProvider(connector: string): void {
  if (!tenantFromUrl.value || !interactionId.value) return;
  window.location.assign(
    socialSignInUrl(tenantFromUrl.value, connector, interactionId.value),
  );
}

/** The sessionStorage marker that limits an automatic SSO redirect to one per interaction. */
function ssoRedirectMarker(): string | null {
  return interactionId.value ? `monaca.sso.redirected.${interactionId.value}` : null;
}

function ssoCanAutoRedirect(): boolean {
  const marker = ssoRedirectMarker();
  if (!marker) return false;
  try {
    if (sessionStorage.getItem(marker) === "1") return false;
    sessionStorage.setItem(marker, "1");
    return true;
  } catch {
    // Storage can be unavailable (private mode, an embedded browser); do not redirect then, and
    // leave the explicit button as the way forward.
    return false;
  }
}

/**
 * Ask the tenant which connector owns this address's domain.
 *
 * Only the flows that accept an email are routed. A code, sign-up or reset form has its own
 * semantics, and a federated address should not be turned into a local account there.
 */
async function checkSso(address: string): Promise<void> {
  ssoConnector.value = null;
  ssoRedirecting.value = false;

  const tenant = tenantFromUrl.value;
  const iid = interactionId.value;
  if (
    !tenant ||
    !iid ||
    !address.includes("@") ||
    mfaRequired.value ||
    consentRequired.value ||
    awaitingCode.value ||
    mode.value === "signup" ||
    mode.value === "reset"
  ) {
    return;
  }

  const token = ++ssoLookupToken;
  const connector = await findSsoConnector(tenant, address);
  // A slower lookup for an address the visitor has already replaced must not hijack the form.
  if (token !== ssoLookupToken) return;
  ssoConnector.value = connector;
  if (connector && ssoCanAutoRedirect()) {
    ssoRedirecting.value = true;
    window.location.assign(ssoSignInUrl(tenant, connector.connector_id, iid));
  }
}

function signInWithSso(): void {
  const connector = ssoConnector.value;
  if (!connector || !tenantFromUrl.value || !interactionId.value) return;
  ssoRedirecting.value = true;
  window.location.assign(
    ssoSignInUrl(tenantFromUrl.value, connector.connector_id, interactionId.value),
  );
}

watch(email, (value) => {
  // A short pause after the keystroke keeps a typed address from costing one lookup per character.
  window.setTimeout(() => void checkSso(value.trim()), 300);
});

/** Leave the form for whichever flow the visitor picked, keeping only what it can reuse. */
function switchMode(next: Mode): void {
  mode.value = next;
  stage.value = "request";
  code.value = "";
  codeRequested.value = false;
  linkSent.value = false;
  password.value = "";
  newPassword.value = "";
  displayName.value = "";
  username.value = "";
  fieldError.value = null;
  submitError.value = null;
  passkeyError.value = null;
  ssoLookupToken += 1;
  ssoConnector.value = null;
  ssoRedirecting.value = false;
  void nextTick(() => {
    if (next === "password") passwordInput.value?.$el?.focus?.();
    else emailInput.value?.$el?.focus?.();
  });
}

/** Return to the address step so a mistyped email can be corrected. */
function changeEmail(): void {
  stage.value = "request";
  code.value = "";
  codeRequested.value = false;
  linkSent.value = false;
  fieldError.value = null;
  submitError.value = null;
  void nextTick(() => emailInput.value?.$el?.focus?.());
}

/** A code was accepted: the flow is done, or it pauses for consent or the second factor. */
function handleResult(result: SignInResult): void {
  if ("consent_required" in result) {
    // The code is withheld until the scopes are approved; the second factor is already satisfied.
    mfaRequired.value = false;
    consentRequired.value = true;
    return;
  }
  if ("mfa_required" in result) {
    mfaRequired.value = true;
    mfaFactors.value = result.factors;
    useBackupCode.value = false;
    rememberDevice.value = false;
    mfaPasskeyError.value = null;
    password.value = "";
    void nextTick(() => mfaInput.value?.$el?.focus?.());
    return;
  }
  if ("mfa_enrollment_required" in result) {
    // The primary factor passed; the tenant requires a second factor this account does not have.
    mfaRequired.value = false;
    password.value = "";
    void beginEnrollment();
    return;
  }
  navigateTo(result.redirect_to);
}

/** Fetch the setup data for the enrollment step. */
async function beginEnrollment(): Promise<void> {
  if (!tenantFromUrl.value || !interactionId.value) return;
  mfaEnrollmentRequired.value = true;
  enrollmentLoading.value = true;
  enrollmentServerError.value = null;
  try {
    enrollment.value = await startMfaEnrollment(tenantFromUrl.value, interactionId.value);
    await nextTick();
    enrollmentInput.value?.$el?.focus?.();
  } catch (error) {
    enrollmentServerError.value = error instanceof InteractionError ? error : null;
    if (!(error instanceof InteractionError)) {
      loadError.value = error instanceof Error ? error : new Error(String(error));
    }
  } finally {
    enrollmentLoading.value = false;
  }
}

/** Prove the freshly scanned authenticator and finish the flow. */
async function submitEnrollment(): Promise<void> {
  enrollmentError.value = null;
  enrollmentServerError.value = null;
  const submitted = enrollmentCode.value.trim();
  if (!/^[0-9]{6}$/.test(submitted)) {
    enrollmentError.value = "errors.mfaCodeRequired";
    return;
  }
  if (!tenantFromUrl.value || !interactionId.value) return;

  enrollmentSubmitting.value = true;
  try {
    handleResult(
      await verifyMfaEnrollment(tenantFromUrl.value, interactionId.value, submitted),
    );
  } catch (error) {
    enrollmentServerError.value = error instanceof InteractionError ? error : null;
    if (!(error instanceof InteractionError)) {
      loadError.value = error instanceof Error ? error : new Error(String(error));
    }
    if (error instanceof InteractionError && error.code === "MONACA_INVALID_VERIFICATION_CODE") {
      enrollmentCode.value = "";
    }
    await nextTick();
    enrollmentInput.value?.$el?.focus?.();
  } finally {
    enrollmentSubmitting.value = false;
  }
}

/** The form's one submit handler: it names the step the current mode is on. */
async function submit(): Promise<void> {
  if (mfaRequired.value) return verifySecondFactor();
  if (mode.value === "password") return signIn();
  if (stage.value === "request") return requestCode();
  return verifyCode();
}

/** The second-factor step: an authenticator code or a saved backup code (§6.1 `mfa`). */
async function verifySecondFactor(): Promise<void> {
  fieldError.value = null;
  mfaError.value = null;
  const submitted = mfaCode.value.trim();
  if (useBackupCode.value) {
    // Case, spaces and the display hyphen are all accepted; the server normalises the same way.
    if (submitted.toLowerCase().replace(/[^a-z0-9]/g, "").length !== 10) {
      fieldError.value = "errors.backupCodeRequired";
      return;
    }
  } else if (!/^[0-9]{6}$/.test(submitted)) {
    fieldError.value = "errors.mfaCodeRequired";
    return;
  }
  if (!tenantFromUrl.value || !interactionId.value) return;

  mfaSubmitting.value = true;
  try {
    handleResult(
      await verifyMfa(
        tenantFromUrl.value,
        interactionId.value,
        submitted,
        useBackupCode.value ? "backup_code" : "totp",
        rememberDevice.value,
      ),
    );
  } catch (error) {
    mfaError.value = error instanceof InteractionError ? error : null;
    if (!(error instanceof InteractionError)) {
      loadError.value = error instanceof Error ? error : new Error(String(error));
    }
    // A rejected code is burned for this attempt; clearing the field makes a retype deliberate.
    if (error instanceof InteractionError && error.code === "MONACA_INVALID_VERIFICATION_CODE") {
      mfaCode.value = "";
    }
    await nextTick();
    mfaInput.value?.$el?.focus?.();
  } finally {
    mfaSubmitting.value = false;
  }
}

/** Swap between the authenticator form and the recovery-code form without leaving the step. */
function toggleBackupCode(): void {
  useBackupCode.value = !useBackupCode.value;
  mfaCode.value = "";
  fieldError.value = null;
  mfaError.value = null;
  mfaPasskeyError.value = null;
  void nextTick(() => mfaInput.value?.$el?.focus?.());
}

/**
 * Sign in without a password: the browser offers the passkeys it holds for this site, the
 * authenticator signs the server's challenge, and the answer is verified like any other primary
 * factor. An enrolled second factor still applies afterwards.
 */
async function signInWithPasskey(): Promise<void> {
  if (!tenantFromUrl.value || !interactionId.value) return;
  fieldError.value = null;
  submitError.value = null;
  passkeyError.value = null;
  passkeyBusy.value = true;
  try {
    const options = await getPasskeySignInOptions(tenantFromUrl.value, interactionId.value);
    const credential = await getPasskeyAssertion(options);
    handleResult(await verifyPasskeySignIn(tenantFromUrl.value, interactionId.value, credential));
  } catch (error) {
    if (error instanceof PasskeyError) passkeyError.value = error;
    else if (error instanceof InteractionError) submitError.value = error;
    else loadError.value = error instanceof Error ? error : new Error(String(error));
  } finally {
    passkeyBusy.value = false;
  }
}

/** Answer the second factor with a registered passkey instead of a typed code. */
async function verifyWithMfaPasskey(): Promise<void> {
  if (!tenantFromUrl.value || !interactionId.value) return;
  fieldError.value = null;
  mfaError.value = null;
  mfaPasskeyError.value = null;
  mfaPasskeyBusy.value = true;
  try {
    const options = await getMfaPasskeyOptions(tenantFromUrl.value, interactionId.value);
    const credential = await getPasskeyAssertion(options);
    handleResult(await verifyMfaPasskey(tenantFromUrl.value, interactionId.value, credential));
  } catch (error) {
    if (error instanceof PasskeyError || error instanceof InteractionError) {
      mfaPasskeyError.value = error;
    } else {
      loadError.value = error instanceof Error ? error : new Error(String(error));
    }
  } finally {
    mfaPasskeyBusy.value = false;
  }
}

async function signIn(): Promise<void> {
  fieldError.value = null;
  submitError.value = null;

  if (email.value.trim().length === 0) {
    fieldError.value = "errors.identifierRequired";
    return;
  }
  if (password.value.length === 0) {
    fieldError.value = "errors.passwordRequired";
    return;
  }
  if (!tenantFromUrl.value || !interactionId.value) return;

  submitting.value = true;
  try {
    const result = await submitSignIn(tenantFromUrl.value, interactionId.value, {
      identifier: email.value.trim(),
      password: password.value,
    });
    handleResult(result);
  } catch (error) {
    submitError.value = error instanceof InteractionError ? error : null;
    // Clear the password but keep the email: the user is about to try again.
    password.value = "";
    if (!(error instanceof InteractionError)) {
      loadError.value = error instanceof Error ? error : new Error(String(error));
    }
    await nextTick();
    passwordInput.value?.$el?.focus?.();
  } finally {
    submitting.value = false;
  }
}

/** Mail a code for the flow the visitor picked. */
async function requestCode(): Promise<void> {
  fieldError.value = null;
  submitError.value = null;
  if (email.value.trim().length === 0) {
    fieldError.value = "errors.emailRequired";
    return;
  }
  if (!tenantFromUrl.value || !interactionId.value) return;

  submitting.value = true;
  try {
    const address = email.value.trim();
    if (mode.value === "signup") {
      await startSignUp(tenantFromUrl.value, interactionId.value, address);
    } else if (mode.value === "code") {
      await requestSignInCode(tenantFromUrl.value, interactionId.value, address);
    } else {
      await requestPasswordReset(tenantFromUrl.value, interactionId.value, address);
    }
    // The server answers the same way whether or not the address exists; a code is mailed either
    // way and the verify step is where an unknown address fails, with the same generic answer.
    stage.value = "verify";
    codeRequested.value = true;
    await nextTick();
    codeInput.value?.$el?.focus?.();
  } catch (error) {
    submitError.value = error instanceof InteractionError ? error : null;
    if (!(error instanceof InteractionError)) {
      loadError.value = error instanceof Error ? error : new Error(String(error));
    }
  } finally {
    submitting.value = false;
  }
}

/** Mail a one-time link instead of a code; the visitor finishes in the mail client. */
async function sendSignInLink(): Promise<void> {
  fieldError.value = null;
  submitError.value = null;
  linkSent.value = false;
  if (email.value.trim().length === 0) {
    fieldError.value = "errors.emailRequired";
    return;
  }
  if (!tenantFromUrl.value || !interactionId.value) return;

  linkSubmitting.value = true;
  try {
    await requestSignInLink(tenantFromUrl.value, interactionId.value, email.value.trim());
    linkSent.value = true;
  } catch (error) {
    submitError.value = error instanceof InteractionError ? error : null;
    if (!(error instanceof InteractionError)) {
      loadError.value = error instanceof Error ? error : new Error(String(error));
    }
  } finally {
    linkSubmitting.value = false;
  }
}

/** Redeem the code and finish the flow the visitor picked. */
async function verifyCode(): Promise<void> {
  fieldError.value = null;
  submitError.value = null;
  if (code.value.trim().length === 0) {
    fieldError.value = "errors.codeRequired";
    return;
  }
  if ((mode.value === "signup" || mode.value === "reset") && [...newPassword.value].length < passwordMinLength.value) {
    fieldError.value = "errors.weakPassword";
    return;
  }
  if (mode.value === "signup" && username.value.trim() !== "" && !/^[A-Za-z0-9_-]{3,32}$/.test(username.value.trim())) {
    fieldError.value = "errors.usernameInvalid";
    return;
  }
  if (!tenantFromUrl.value || !interactionId.value) return;

  submitting.value = true;
  try {
    const address = email.value.trim();
    const submitted = code.value.trim();
    let result: SignInResult;
    if (mode.value === "signup") {
      result = await verifySignUp(tenantFromUrl.value, interactionId.value, {
        email: address,
        code: submitted,
        password: newPassword.value,
        display_name: displayName.value.trim() || undefined,
        username: username.value.trim() || undefined,
      });
    } else if (mode.value === "code") {
      result = await verifySignInCode(tenantFromUrl.value, interactionId.value, {
        email: address,
        code: submitted,
      });
    } else {
      result = await resetPassword(tenantFromUrl.value, interactionId.value, {
        email: address,
        code: submitted,
        password: newPassword.value,
      });
    }
    handleResult(result);
  } catch (error) {
    submitError.value = error instanceof InteractionError ? error : null;
    if (!(error instanceof InteractionError)) {
      loadError.value = error instanceof Error ? error : new Error(String(error));
    }
    // A rejected code is burned for this attempt; clearing the field makes a retype deliberate.
    if (error instanceof InteractionError && error.code === "MONACA_INVALID_VERIFICATION_CODE") {
      code.value = "";
    }
    await nextTick();
    codeInput.value?.$el?.focus?.();
  } finally {
    submitting.value = false;
  }
}

async function decideConsent(decision: "allow" | "deny"): Promise<void> {
  if (!tenantFromUrl.value || !interactionId.value) return;
  consentError.value = null;
  consentSubmitting.value = true;
  try {
    const { redirect_to } = await submitConsent(tenantFromUrl.value, interactionId.value, decision);
    navigateTo(redirect_to);
  } catch (error) {
    consentError.value = error instanceof Error ? error : new Error(String(error));
  } finally {
    consentSubmitting.value = false;
  }
}

async function cancel(): Promise<void> {
  if (!tenantFromUrl.value || !interactionId.value) {
    // Nothing to abort (the interaction was never loaded); there is nowhere to return to either.
    return;
  }
  cancelling.value = true;
  try {
    const { redirect_to } = await abortInteraction(tenantFromUrl.value, interactionId.value);
    navigateTo(redirect_to);
  } catch {
    // An abort that fails leaves the user where they were; a dead-end redirect would be worse.
    cancelling.value = false;
  }
}
</script>

<template>
  <div class="flex min-h-screen flex-col items-center justify-center bg-paper px-4 py-10">
    <div class="w-full max-w-[400px]">
      <!-- Brand: tenant name when the interaction resolved, the product name otherwise. -->
      <div class="mb-5 flex items-center justify-center gap-2">
        <span
          class="grid size-7 place-items-center rounded-[6px] bg-brand text-[13px] font-semibold text-brand-on"
          aria-hidden="true"
        >
          m
        </span>
        <span class="text-[14px] font-semibold tracking-[-0.01em] text-ink">{{ brandName }}</span>
      </div>

      <div class="rounded-xl border border-rule bg-surface p-6 shadow-[var(--shadow-pop)]">
        <!-- Loading: the request is being checked. -->
        <div v-if="loading" class="flex flex-col gap-3" aria-busy="true">
          <Skeleton class="h-6 w-40" />
          <Skeleton class="h-4 w-56" />
          <Skeleton class="mt-2 h-8 w-full" />
          <Skeleton class="h-8 w-full" />
          <p class="text-center text-[12px] text-ink-faint">{{ t("loading.hint") }}</p>
        </div>

        <!-- Failed to load: explain, and give a way out. -->
        <div v-else-if="loadError" class="flex flex-col gap-3">
          <Alert variant="error">
            <AlertCircle />
            <div class="min-w-0">
              <AlertTitle>{{ t(loadErrorTitle) }}</AlertTitle>
              <!-- The hint replaces the generic detail when the request had no id at all, rather
                   than restating it: one explanation per situation. -->
              <AlertDescription>
                {{ missingInteractionId ? t("errors.missingInteractionHint") : t(loadErrorMessage) }}
              </AlertDescription>
            </div>
          </Alert>
        </div>

        <!-- Sign-in, then consent when the client or `prompt=consent` asks for it. -->
        <div v-else class="flex flex-col gap-4">
          <div>
            <h1 class="text-[17px] font-semibold leading-snug tracking-[-0.01em] text-ink">
              {{ t(pageTitle) }}
            </h1>
            <p class="mt-1 text-[12.5px] leading-snug text-ink-muted">
              {{
                details
                  ? t(consentRequired ? "consent.request" : modeNote, { client: details.client.name })
                  : t(mfaRequired ? "mfa.noteFallback" : "signIn.requestFallback")
              }}
            </p>
          </div>

          <!-- What is being granted, stated before the password is typed. -->
          <dl
            v-if="details && (organization || scopes.length > 0)"
            class="flex flex-col gap-2 rounded-lg border border-rule bg-surface-muted px-3 py-2.5"
          >
            <div v-if="organization" class="flex items-center justify-between gap-3">
              <dt class="text-[11.5px] text-ink-faint">{{ t("signIn.organization") }}</dt>
              <dd class="m-0">
                <Badge variant="brand">{{ organization }}</Badge>
              </dd>
            </div>
            <div v-if="scopes.length > 0" class="flex flex-col gap-1.5">
              <dt class="text-[11.5px] text-ink-faint">{{ t("signIn.scopes") }}</dt>
              <dd class="m-0 flex flex-wrap gap-1">
                <ScopeBadge v-for="scope in scopes" :key="scope" :scope="scope" />
              </dd>
            </div>
            <div class="flex items-center justify-between gap-3">
              <dt class="text-[11.5px] text-ink-faint">{{ t("signIn.tenantLabel") }}</dt>
              <dd class="mono-data m-0 text-[11.5px] text-ink-muted">{{ details.tenant }}</dd>
            </div>
          </dl>

          <!-- Consent: signed in, but the code is withheld until the scopes are approved. -->
          <div v-if="consentRequired" class="flex flex-col gap-2">
            <p class="text-[12.5px] leading-snug text-ink-muted">{{ t("consent.note") }}</p>
            <Button
              type="button"
              variant="primary"
              block
              :disabled="consentSubmitting"
              :aria-busy="consentSubmitting"
              @click="decideConsent('allow')"
            >
              <Loader2 v-if="consentSubmitting" class="animate-spin" />
              <Check v-else />
              {{ consentSubmitting ? t("consent.allowSubmitting") : t("consent.allow") }}
            </Button>
            <Button type="button" variant="ghost" block :disabled="consentSubmitting" @click="decideConsent('deny')">
              <ArrowLeft />
              {{ t("consent.deny") }}
            </Button>
            <p
              v-if="consentError"
              role="alert"
              class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
            >
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ t("errors.consentFailed") }}
            </p>
          </div>

          <!-- Second factor: the password was right, the authenticator code is the last step. -->
          <form v-else-if="mfaRequired" class="flex flex-col gap-4" @submit.prevent="submit">
            <div class="flex flex-col gap-1.5">
              <Label for="signin-mfa-code">
                {{ t(useBackupCode ? "mfa.backupCode" : "mfa.code") }}
              </Label>
              <Input
                id="signin-mfa-code"
                ref="mfaInput"
                v-model="mfaCode"
                type="text"
                name="code"
                :inputmode="useBackupCode ? 'text' : 'numeric'"
                :autocomplete="useBackupCode ? 'off' : 'one-time-code'"
                :maxlength="useBackupCode ? 11 : 6"
                :pattern="useBackupCode ? '[A-Za-z0-9-]{10,11}' : '[0-9]{6}'"
                spellcheck="false"
                autocapitalize="none"
                :placeholder="t(useBackupCode ? 'mfa.backupCodePlaceholder' : 'mfa.codePlaceholder')"
                :invalid="fieldError !== null || mfaError !== null"
                :aria-describedby="fieldError || mfaError ? 'signin-error' : undefined"
              />
              <button
                v-if="backupCodeAvailable"
                type="button"
                class="self-start text-[11.5px] font-medium text-brand-strong hover:underline"
                @click="toggleBackupCode"
              >
                {{ t(useBackupCode ? "mfa.useTotp" : "mfa.useBackupCode") }}
              </button>
            </div>

            <!-- Remembering this browser is the one-way choice out of the second factor. -->
            <label class="flex items-start gap-2 text-[12.5px] leading-snug text-ink-muted">
              <input
                v-model="rememberDevice"
                type="checkbox"
                name="remember_device"
                class="mt-0.5 size-3.5 accent-[var(--brand)]"
              />
              <span>{{ t("mfa.rememberDevice") }}</span>
            </label>

            <p
              v-if="fieldError || mfaError"
              id="signin-error"
              role="alert"
              class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
            >
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ t(fieldError ?? mfaErrorMessage) }}
            </p>

            <div class="flex flex-col gap-2">
              <Button type="submit" variant="primary" block :disabled="mfaSubmitting" :aria-busy="mfaSubmitting">
                <Loader2 v-if="mfaSubmitting" class="animate-spin" />
                <ShieldCheck v-else />
                {{ mfaSubmitting ? t("mfa.verifying") : t("mfa.verify") }}
              </Button>
              <Button
                type="button"
                variant="ghost"
                block
                :disabled="cancelling || mfaSubmitting"
                @click="cancel"
              >
                <ArrowLeft />
                {{ cancelling ? t("signIn.cancelling") : t("signIn.cancel") }}
              </Button>
            </div>

            <!-- A passkey can stand in for the six-digit code when the account registered one. -->
            <div v-if="mfaPasskeyAvailable" class="flex flex-col gap-1.5">
              <p class="text-[11.5px] leading-snug text-ink-faint">{{ t("passkey.mfaNote") }}</p>
              <Button
                type="button"
                variant="secondary"
                block
                :disabled="mfaSubmitting || mfaPasskeyBusy"
                :aria-busy="mfaPasskeyBusy"
                @click="verifyWithMfaPasskey"
              >
                <Loader2 v-if="mfaPasskeyBusy" class="animate-spin" />
                <KeyRound v-else />
                {{ mfaPasskeyBusy ? t("passkey.signingIn") : t("mfa.usePasskey") }}
              </Button>
              <p
                v-if="mfaPasskeyErrorMessage"
                role="alert"
                class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
              >
                <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
                {{ t(mfaPasskeyErrorMessage) }}
              </p>
            </div>
          </form>

          <!-- Mandatory enrollment: the tenant requires a factor this account does not have yet. -->
          <form
            v-else-if="mfaEnrollmentRequired"
            class="flex flex-col gap-4"
            @submit.prevent="submitEnrollment"
          >
            <p
              v-if="enrollmentLoading"
              class="flex items-center gap-2 text-[12.5px] leading-snug text-ink-muted"
              aria-busy="true"
            >
              <Loader2 class="animate-spin" />
              {{ t("mfaEnroll.loading") }}
            </p>

            <template v-else-if="enrollment">
              <!-- The secret is shown once: the authenticator app now owns it, this page forgets it. -->
              <div class="flex flex-col gap-1.5">
                <Label for="signin-enrollment-secret">{{ t("mfaEnroll.secret") }}</Label>
                <code
                  id="signin-enrollment-secret"
                  class="mono-data break-all rounded-md border border-rule bg-surface-muted px-2.5 py-1.5 text-[12px] leading-relaxed text-ink"
                >{{ enrollment.secret }}</code>
                <p class="text-[11.5px] leading-snug text-ink-faint">{{ t("mfaEnroll.secretHint") }}</p>
                <a
                  :href="enrollment.otpauth_url"
                  class="self-start text-[11.5px] font-medium text-brand-strong hover:underline"
                >
                  {{ t("mfaEnroll.open") }}
                </a>
              </div>

              <div class="flex flex-col gap-1.5">
                <Label for="signin-enrollment-code">{{ t("mfaEnroll.code") }}</Label>
                <Input
                  id="signin-enrollment-code"
                  ref="enrollmentInput"
                  v-model="enrollmentCode"
                  type="text"
                  name="code"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  maxlength="6"
                  pattern="[0-9]{6}"
                  spellcheck="false"
                  :placeholder="t('mfaEnroll.codePlaceholder')"
                  :invalid="enrollmentError !== null || enrollmentServerError !== null"
                  aria-describedby="signin-enrollment-hint"
                />
                <p id="signin-enrollment-hint" class="text-[11.5px] leading-snug text-ink-faint">
                  {{ t("mfaEnroll.codeHint") }}
                </p>
              </div>

              <p
                v-if="enrollmentError || enrollmentServerError"
                id="signin-error"
                role="alert"
                class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
              >
                <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
                {{ t(enrollmentError ?? enrollmentErrorMessage) }}
              </p>

              <div class="flex flex-col gap-2">
                <Button
                  type="submit"
                  variant="primary"
                  block
                  :disabled="enrollmentSubmitting"
                  :aria-busy="enrollmentSubmitting"
                >
                  <Loader2 v-if="enrollmentSubmitting" class="animate-spin" />
                  <ShieldCheck v-else />
                  {{ enrollmentSubmitting ? t("mfaEnroll.verifying") : t("mfaEnroll.verify") }}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  block
                  :disabled="cancelling || enrollmentSubmitting"
                  @click="cancel"
                >
                  <ArrowLeft />
                  {{ cancelling ? t("signIn.cancelling") : t("signIn.cancel") }}
                </Button>
              </div>
            </template>

            <!-- The setup could not be fetched; reloading is the only way to restart it. -->
            <template v-else>
              <p role="alert" class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny">
                <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
                {{ enrollmentServerError ? t(enrollmentErrorMessage) : t("mfaEnroll.failed") }}
              </p>
              <Button
                type="button"
                variant="ghost"
                block
                :disabled="cancelling"
                @click="cancel"
              >
                <ArrowLeft />
                {{ cancelling ? t("signIn.cancelling") : t("signIn.cancel") }}
              </Button>
            </template>
          </form>

          <form v-else class="flex flex-col gap-4" @submit.prevent="submit">
            <div class="flex flex-col gap-1.5">
              <Label for="signin-email">{{ t(mode === "password" ? "signIn.identifier" : "signIn.email") }}</Label>
              <Input
                id="signin-email"
                ref="emailInput"
                v-model="email"
                :type="mode === 'password' ? 'text' : 'email'"
                name="email"
                autocomplete="username"
                :inputmode="mode === 'password' ? 'text' : 'email'"
                spellcheck="false"
                autocapitalize="none"
                :disabled="awaitingCode"
                :placeholder="t(mode === 'password' ? 'signIn.identifierPlaceholder' : 'signIn.emailPlaceholder')"
                :invalid="fieldError === 'errors.emailRequired' || fieldError === 'errors.identifierRequired'"
                :aria-describedby="fieldError ? 'signin-error' : undefined"
              />
              <!-- The address is locked once a code was mailed, so the code always matches it. -->
              <button
                v-if="awaitingCode"
                type="button"
                class="self-start text-[11.5px] font-medium text-brand-strong hover:underline"
                @click="changeEmail"
              >
                {{ t(changeEmailKey) }}
              </button>
            </div>

            <!-- A federated domain signs in at its provider, not with a password this tenant cannot check. -->
            <div
              v-if="ssoConnector && !awaitingCode && mode !== 'signup' && mode !== 'reset'"
              class="flex flex-col gap-2 rounded-md border border-rule bg-surface-muted px-3 py-2.5"
            >
              <p class="flex items-start gap-1.5 text-[12px] leading-snug text-ink-muted">
                <Building2 class="mt-px size-3.5 shrink-0 text-ink-faint" aria-hidden="true" />
                {{ t("signIn.ssoNote", { name: ssoConnector.display_name }) }}
              </p>
              <Button
                type="button"
                variant="secondary"
                block
                :disabled="ssoRedirecting"
                :aria-busy="ssoRedirecting"
                @click="signInWithSso"
              >
                <Loader2 v-if="ssoRedirecting" class="animate-spin" />
                <Building2 v-else />
                {{
                  ssoRedirecting
                    ? t("signIn.ssoRedirecting", { name: ssoConnector.display_name })
                    : t("signIn.ssoContinue", { name: ssoConnector.display_name })
                }}
              </Button>
            </div>

            <div v-if="awaitingCode" class="flex flex-col gap-1.5">
              <Label for="signin-code">{{ t("emailCode.code") }}</Label>
              <Input
                id="signin-code"
                ref="codeInput"
                v-model="code"
                type="text"
                name="code"
                inputmode="numeric"
                autocomplete="one-time-code"
                maxlength="6"
                pattern="[0-9]{6}"
                spellcheck="false"
                :placeholder="t('emailCode.codePlaceholder')"
                :invalid="fieldError === 'errors.codeRequired' || submitError !== null"
                :aria-describedby="fieldError || submitError ? 'signin-error' : undefined"
              />
              <p v-if="codeRequested" class="text-[11.5px] leading-snug text-ink-faint">
                {{ t("emailCode.sent") }}
              </p>
            </div>

            <div v-if="mode === 'password'" class="flex flex-col gap-1.5">
              <Label for="signin-password">{{ t("signIn.password") }}</Label>
              <div class="relative">
                <Input
                  id="signin-password"
                  ref="passwordInput"
                  v-model="password"
                  :type="revealPassword ? 'text' : 'password'"
                  name="password"
                  autocomplete="current-password"
                  class="pr-9"
                  :invalid="fieldError === 'errors.passwordRequired' || submitError !== null"
                  :aria-describedby="fieldError || submitError ? 'signin-error' : undefined"
                />
                <button
                  type="button"
                  class="absolute right-1 top-1 inline-flex size-6 items-center justify-center rounded-sm text-ink-faint transition-colors hover:bg-surface-muted hover:text-ink"
                  :aria-label="revealPassword ? t('signIn.hidePassword') : t('signIn.showPassword')"
                  :aria-pressed="revealPassword"
                  @click="revealPassword = !revealPassword"
                >
                  <EyeOff v-if="revealPassword" class="size-3.5" aria-hidden="true" />
                  <Eye v-else class="size-3.5" aria-hidden="true" />
                </button>
              </div>
            </div>

            <div v-if="awaitingCode && (mode === 'signup' || mode === 'reset')" class="flex flex-col gap-1.5">
              <Label for="signin-new-password">{{ t(newPasswordLabel) }}</Label>
              <div class="relative">
                <Input
                  id="signin-new-password"
                  v-model="newPassword"
                  :type="revealPassword ? 'text' : 'password'"
                  name="new-password"
                  autocomplete="new-password"
                  class="pr-9"
                  :invalid="fieldError === 'errors.weakPassword'"
                  :aria-describedby="fieldError === 'errors.weakPassword' ? 'signin-error' : undefined"
                />
                <button
                  type="button"
                  class="absolute right-1 top-1 inline-flex size-6 items-center justify-center rounded-sm text-ink-faint transition-colors hover:bg-surface-muted hover:text-ink"
                  :aria-label="revealPassword ? t('signIn.hidePassword') : t('signIn.showPassword')"
                  :aria-pressed="revealPassword"
                  @click="revealPassword = !revealPassword"
                >
                  <EyeOff v-if="revealPassword" class="size-3.5" aria-hidden="true" />
                  <Eye v-else class="size-3.5" aria-hidden="true" />
                </button>
              </div>
              <p class="text-[11.5px] leading-snug text-ink-faint">{{ t(newPasswordHint, { min: passwordMinLength }) }}</p>
            </div>

            <div v-if="awaitingCode && mode === 'signup'" class="flex flex-col gap-1.5">
              <Label for="signin-display-name">{{ t("signUp.displayName") }}</Label>
              <Input
                id="signin-display-name"
                v-model="displayName"
                type="text"
                name="name"
                autocomplete="name"
                :placeholder="t('signUp.displayNamePlaceholder')"
              />
            </div>

            <!-- A username is a second sign-in identifier; optional at sign-up, changeable later. -->
            <div v-if="awaitingCode && mode === 'signup'" class="flex flex-col gap-1.5">
              <Label for="signin-username">{{ t("signUp.username") }}</Label>
              <Input
                id="signin-username"
                v-model="username"
                type="text"
                name="username"
                autocomplete="username"
                spellcheck="false"
                autocapitalize="none"
                :placeholder="t('signUp.usernamePlaceholder')"
                :invalid="fieldError === 'errors.usernameInvalid'"
              />
              <p class="text-[11.5px] leading-snug text-ink-faint">{{ t("signUp.usernameHint") }}</p>
            </div>

            <!-- Field-level or submission error, in one place, wired through aria-describedby. -->
            <p
              v-if="fieldError || submitError"
              id="signin-error"
              role="alert"
              class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
            >
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ t(fieldError ?? submitErrorMessage) }}
            </p>

            <div class="flex flex-col gap-2">
              <Button type="submit" variant="primary" block :disabled="submitting" :aria-busy="submitting">
                <Loader2 v-if="submitting" class="animate-spin" />
                <Mail v-else-if="mode !== 'password' && !awaitingCode" />
                <LockKeyhole v-else />
                {{ t(primaryLabel) }}
              </Button>
              <!-- The same address, but the sign-in happens from the inbox instead of this form. -->
              <Button
                v-if="mode === 'code' && !awaitingCode"
                type="button"
                variant="ghost"
                block
                :disabled="linkSubmitting || submitting"
                :aria-busy="linkSubmitting"
                @click="sendSignInLink"
              >
                <Loader2 v-if="linkSubmitting" class="animate-spin" />
                <Mail v-else />
                {{ linkSubmitting ? t("emailCode.linking") : t("emailCode.link") }}
              </Button>
              <p
                v-if="mode === 'code' && linkSent"
                role="status"
                class="text-center text-[11.5px] leading-snug text-ink-muted"
              >
                {{ t("emailCode.linkSent") }}
              </p>
              <Button
                type="button"
                variant="ghost"
                block
                :disabled="cancelling || submitting"
                @click="cancel"
              >
                <ArrowLeft />
                {{ cancelling ? t("signIn.cancelling") : t("signIn.cancel") }}
              </Button>
            </div>

            <!-- A passkey replaces the typed secret; hidden when the browser cannot run a ceremony. -->
            <div v-if="!awaitingCode && (mode === 'password' || mode === 'code') && passkeyAvailable" class="flex flex-col gap-2">
              <div class="flex items-center gap-2 text-[11px] text-ink-faint">
                <span class="h-px flex-1 bg-rule" aria-hidden="true" />
                {{ t("passkey.or") }}
                <span class="h-px flex-1 bg-rule" aria-hidden="true" />
              </div>
              <Button
                type="button"
                variant="secondary"
                block
                :disabled="passkeyBusy || submitting"
                :aria-busy="passkeyBusy"
                @click="signInWithPasskey"
              >
                <Loader2 v-if="passkeyBusy" class="animate-spin" />
                <KeyRound v-else />
                {{ passkeyBusy ? t("passkey.signingIn") : t("passkey.signIn") }}
              </Button>
              <p
                v-if="passkeyErrorMessage"
                role="alert"
                class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
              >
                <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
                {{ t(passkeyErrorMessage) }}
              </p>
            </div>

            <!-- Provider accounts: a full-page navigation to the provider and back to this interaction. -->
            <div
              v-if="!awaitingCode && (mode === 'password' || mode === 'code') && socialConnectors.length > 0"
              class="flex flex-col gap-2"
            >
              <div class="flex items-center gap-2 text-[11px] text-ink-faint">
                <span class="h-px flex-1 bg-rule" aria-hidden="true" />
                {{ t("signIn.or") }}
                <span class="h-px flex-1 bg-rule" aria-hidden="true" />
              </div>
              <Button
                v-for="connector in socialConnectors"
                :key="connector.connector_id"
                type="button"
                variant="secondary"
                block
                :disabled="submitting || passkeyBusy"
                @click="signInWithProvider(connector.connector_id)"
              >
                {{ t("signIn.continueWith", { name: connector.display_name }) }}
              </Button>
            </div>

            <!-- Four ways in, one interaction; the links only appear once no code is in flight. -->
            <div
              v-if="!awaitingCode"
              class="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-[11.5px]"
            >
              <button
                v-if="mode !== 'password' && passwordAllowed"
                type="button"
                class="font-medium text-brand-strong hover:underline"
                :disabled="submitting"
                @click="switchMode('password')"
              >
                {{ t("modes.password") }}
              </button>
              <button
                v-if="mode !== 'code' && emailCodeAllowed"
                type="button"
                class="font-medium text-brand-strong hover:underline"
                :disabled="submitting"
                @click="switchMode('code')"
              >
                {{ t("modes.code") }}
              </button>
              <button
                v-if="mode !== 'signup' && signUpAllowed"
                type="button"
                class="font-medium text-brand-strong hover:underline"
                :disabled="submitting"
                @click="switchMode('signup')"
              >
                {{ t("modes.signUp") }}
              </button>
              <button
                v-if="mode !== 'reset' && passwordAllowed"
                type="button"
                class="font-medium text-brand-strong hover:underline"
                :disabled="submitting"
                @click="switchMode('reset')"
              >
                {{ t("modes.reset") }}
              </button>
            </div>

            <p
              v-if="mode === 'password'"
              class="text-center text-[11.5px] leading-relaxed text-ink-faint"
            >
              {{ t("signIn.footnote") }}
            </p>
          </form>
        </div>
      </div>

      <p class="mt-4 text-center text-[11.5px] text-ink-faint">
        {{ details?.client.client_id ? `${details.client.client_id} · ` : "" }}{{ t("brand.poweredBy") }}
      </p>
    </div>
  </div>
</template>
