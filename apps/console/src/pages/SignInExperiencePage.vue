<script setup lang="ts">
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Checkbox,
  Input,
  Label,
  NativeSelect,
  Separator,
  Textarea,
  toast,
} from "@monaca/ui";
import { CircleAlert, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-vue-next";
import { computed, ref, watch } from "vue";
import { RouterLink } from "vue-router";

import { describeError } from "@/api/contract";
import type { Branding, SignInExperience, UpdateSignInExperienceRequest } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import { useConnectors, useSignInExperience, useUpdateSignInExperience } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Sign-in experience — the tenant's hosted sign-in switches (§6.2).
 *
 * Three booleans decide what every application's sign-in page offers, so the page is a form and
 * nothing else. Two rules shape it:
 *
 * - **The save sends only what changed.** The server's patch is partial, and sending one field
 *   means a concurrent change to another is not silently overwritten by this page's stale copy.
 * - **The one invalid state is shown, not just rejected.** Password sign-in and email codes cannot
 *   both be off, so the page disables the save and says why instead of letting the server answer 400.
 *
 * The preview on the right is built from the same local values, so toggling a switch shows the
 * hosted page changing before anything is saved — the reader can see the consequence, not infer it.
 */
const ui = useUiStore();

const experience = useSignInExperience();
const connectors = useConnectors();
const update = useUpdateSignInExperience();

const signUp = ref(false);
const password = ref(true);
const emailCode = ref(true);
const passkey = ref(true);
const sso = ref(true);
const mfaEnabled = ref(true);
const mfaPolicy = ref<"user_controlled" | "mandatory">("user_controlled");
const trustedDevices = ref(true);
const trustedDeviceDays = ref(30);
const TRUSTED_MIN_DAYS = 1;
const TRUSTED_MAX_DAYS = 365;
const passwordMinLength = ref(8);
const passwordMinTypes = ref(1);
const rejectUserInfo = ref(true);
const rejectRepetition = ref(true);
/** The word list is edited as text, one word per line or comma-separated. */
const rejectedWordsText = ref("");
/** Session and refresh-token lifetimes are stored in seconds but edited in whole days. */
const sessionDays = ref(30);
const refreshDays = ref(30);
const SESSION_MIN_DAYS = 1;
const SESSION_MAX_DAYS = 90;
const REFRESH_MIN_DAYS = 1;
const REFRESH_MAX_DAYS = 365;
/** Branding is edited as six strings; empty means "use the built-in look". */
const brandName = ref("");
const logoUrl = ref("");
const darkLogoUrl = ref("");
const faviconUrl = ref("");
const primaryColor = ref("");
const termsUrl = ref("");
const privacyUrl = ref("");
const supportEmail = ref("");
const websiteUrl = ref("");
const customCss = ref("");
const signUpUsername = ref(false);
const signUpEmailVerification = ref(true);
const usernameCaseSensitive = ref(false);
const usernameMinLength = ref(3);
const usernameMaxLength = ref(32);
const signUpProfileName = ref(true);
const signUpProfileAvatar = ref(false);
/** CAPTCHA settings; the secret is write-only, so "stored" is the only state the page can read. */
const captchaEnabled = ref(false);
const captchaProvider = ref<"turnstile" | "recaptcha">("turnstile");
const captchaSiteKey = ref("");
const captchaSecret = ref("");
const clearCaptchaSecret = ref(false);
const captchaSecretSet = ref(false);
const captchaOnSignIn = ref(true);
const captchaOnSignUp = ref(true);
const captchaOnPasswordReset = ref(true);
/** The lockout is edited in minutes; stored durations are rounded to the nearest one. */
const lockoutThreshold = ref(0);
const lockoutMinutes = ref(15);
const LOCKOUT_MIN_THRESHOLD = 0;
const LOCKOUT_MAX_THRESHOLD = 100;
const LOCKOUT_MIN_MINUTES = 1;
const LOCKOUT_MAX_MINUTES = 1_440;
const formError = ref<string | null>(null);

function signUpIdentifiers(): ("email" | "username")[] {
  return signUpUsername.value ? ["email", "username"] : ["email"];
}

function signUpProfileFields(): ("name" | "avatar")[] {
  const fields: ("name" | "avatar")[] = [];
  if (signUpProfileName.value) fields.push("name");
  if (signUpProfileAvatar.value) fields.push("avatar");
  return fields;
}

/** The last server values the form was synchronised with; the save diffs against it. */
const baseline = ref<SignInExperience | null>(null);

function sameBranding(a: Branding, b: Branding): boolean {
  return (
    a.display_name === b.display_name &&
    a.logo_url === b.logo_url &&
    a.dark_logo_url === b.dark_logo_url &&
    a.favicon_url === b.favicon_url &&
    a.primary_color === b.primary_color &&
    a.terms_url === b.terms_url &&
    a.privacy_url === b.privacy_url &&
    a.support_email === b.support_email &&
    a.website_url === b.website_url &&
    a.custom_css === b.custom_css
  );
}

/** The branding the form would write, in the stored shape (`null` for an empty field). */
function brandingValues(): Branding {
  const value = (raw: string) => raw.trim() === "" ? null : raw.trim();
  return {
    display_name: value(brandName.value),
    logo_url: value(logoUrl.value),
    dark_logo_url: value(darkLogoUrl.value),
    favicon_url: value(faviconUrl.value),
    primary_color: value(primaryColor.value),
    terms_url: value(termsUrl.value),
    privacy_url: value(privacyUrl.value),
    support_email: value(supportEmail.value),
    website_url: value(websiteUrl.value),
    custom_css: value(customCss.value),
  };
}

/** The day count the form shows for a stored duration, clamped to the editable range. */
function storedDays(secs: number, maxDays: number): number {
  return Math.min(maxDays, Math.max(SESSION_MIN_DAYS, Math.round(secs / 86_400)));
}

/** The minute count the form shows for a stored lockout duration. */
function storedMinutes(secs: number): number {
  return Math.min(LOCKOUT_MAX_MINUTES, Math.max(LOCKOUT_MIN_MINUTES, Math.round(secs / 60)));
}

/** The word list as the server stores it: trimmed, lowercased and de-duplicated. */
function rejectedWordsValues(): string[] {
  const words = rejectedWordsText.value
    .split(/[\n,]+/)
    .map((word) => word.trim().toLowerCase())
    .filter((word) => word !== "");
  return [...new Set(words)];
}

function sameWords(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const left = [...a].sort();
  const right = [...b].sort();
  return left.every((word, index) => word === right[index]);
}

/** Every value the form can change, so the comparison and the save read one object. */
interface SwitchForm {
  signUp: boolean;
  password: boolean;
  emailCode: boolean;
  passkey: boolean;
  sso: boolean;
  mfaEnabled: boolean;
  mfaPolicy: "user_controlled" | "mandatory";
  trustedDevices: boolean;
  trustedDeviceDays: number;
  passwordMinLength: number;
  passwordMinTypes: number;
  rejectUserInfo: boolean;
  rejectRepetition: boolean;
  rejectedWords: string[];
  sessionDays: number;
  refreshDays: number;
  signUpIdentifiers: ("email" | "username")[];
  signUpEmailVerification: boolean;
  usernameCaseSensitive: boolean;
  usernameMinLength: number;
  usernameMaxLength: number;
  signUpProfileFields: ("name" | "avatar")[];
  branding: Branding;
  captchaEnabled: boolean;
  captchaProvider: "turnstile" | "recaptcha";
  captchaSiteKey: string;
  captchaSecret: string;
  clearCaptchaSecret: boolean;
  captchaOnSignIn: boolean;
  captchaOnSignUp: boolean;
  captchaOnPasswordReset: boolean;
  lockoutThreshold: number;
  lockoutMinutes: number;
}

function formValues(): SwitchForm {
  return {
    signUp: signUp.value,
    password: password.value,
    emailCode: emailCode.value,
    passkey: passkey.value,
    sso: sso.value,
    mfaEnabled: mfaEnabled.value,
    mfaPolicy: mfaPolicy.value,
    trustedDevices: trustedDevices.value,
    trustedDeviceDays: trustedDeviceDays.value,
    passwordMinLength: passwordMinLength.value,
    passwordMinTypes: passwordMinTypes.value,
    rejectUserInfo: rejectUserInfo.value,
    rejectRepetition: rejectRepetition.value,
    rejectedWords: rejectedWordsValues(),
    sessionDays: sessionDays.value,
    refreshDays: refreshDays.value,
    signUpIdentifiers: signUpIdentifiers(),
    signUpEmailVerification: signUpEmailVerification.value,
    usernameCaseSensitive: usernameCaseSensitive.value,
    usernameMinLength: usernameMinLength.value,
    usernameMaxLength: usernameMaxLength.value,
    signUpProfileFields: signUpProfileFields(),
    branding: brandingValues(),
    captchaEnabled: captchaEnabled.value,
    captchaProvider: captchaProvider.value,
    captchaSiteKey: captchaSiteKey.value.trim(),
    captchaSecret: captchaSecret.value.trim(),
    clearCaptchaSecret: clearCaptchaSecret.value,
    captchaOnSignIn: captchaOnSignIn.value,
    captchaOnSignUp: captchaOnSignUp.value,
    captchaOnPasswordReset: captchaOnPasswordReset.value,
    lockoutThreshold: lockoutThreshold.value,
    lockoutMinutes: lockoutMinutes.value,
  };
}

function sameSwitches(value: SignInExperience, form: SwitchForm): boolean {
  return (
    value.sign_up_enabled === form.signUp &&
    value.password_sign_in_enabled === form.password &&
    value.email_code_sign_in_enabled === form.emailCode &&
    value.passkey_sign_in_enabled === form.passkey &&
    value.single_sign_on_enabled === form.sso &&
    value.mfa_enabled === form.mfaEnabled &&
    value.mfa_policy === form.mfaPolicy &&
    value.mfa_trusted_devices_enabled === form.trustedDevices &&
    value.mfa_trusted_device_ttl_days === form.trustedDeviceDays &&
    value.password_min_length === form.passwordMinLength &&
    value.password_min_character_types === form.passwordMinTypes &&
    value.password_reject_user_info === form.rejectUserInfo &&
    value.password_reject_repetition_and_sequence === form.rejectRepetition &&
    sameWords(value.password_rejected_words, form.rejectedWords) &&
    storedDays(value.session_ttl_secs, SESSION_MAX_DAYS) === form.sessionDays &&
    storedDays(value.refresh_token_ttl_secs, REFRESH_MAX_DAYS) === form.refreshDays &&
    sameWords(value.sign_up_identifiers, form.signUpIdentifiers) &&
    value.sign_up_email_verification_required === form.signUpEmailVerification &&
    value.username_case_sensitive === form.usernameCaseSensitive &&
    value.username_min_length === form.usernameMinLength &&
    value.username_max_length === form.usernameMaxLength &&
    sameWords(value.sign_up_profile_fields, form.signUpProfileFields) &&
    sameBranding(value.branding, form.branding) &&
    value.captcha.enabled === form.captchaEnabled &&
    value.captcha.provider === form.captchaProvider &&
    (value.captcha.site_key ?? "") === form.captchaSiteKey &&
    form.captchaSecret === "" &&
    !form.clearCaptchaSecret &&
    value.captcha.on_sign_in === form.captchaOnSignIn &&
    value.captcha.on_sign_up === form.captchaOnSignUp &&
    value.captcha.on_password_reset === form.captchaOnPasswordReset &&
    value.login_lockout_threshold === form.lockoutThreshold &&
    storedMinutes(value.login_lockout_duration_secs) === form.lockoutMinutes
  );
}

function adopt(value: SignInExperience): void {
  baseline.value = value;
  signUp.value = value.sign_up_enabled;
  password.value = value.password_sign_in_enabled;
  emailCode.value = value.email_code_sign_in_enabled;
  passkey.value = value.passkey_sign_in_enabled;
  sso.value = value.single_sign_on_enabled;
  mfaEnabled.value = value.mfa_enabled;
  mfaPolicy.value = value.mfa_policy;
  trustedDevices.value = value.mfa_trusted_devices_enabled;
  trustedDeviceDays.value = value.mfa_trusted_device_ttl_days;
  passwordMinLength.value = value.password_min_length;
  passwordMinTypes.value = value.password_min_character_types;
  rejectUserInfo.value = value.password_reject_user_info;
  rejectRepetition.value = value.password_reject_repetition_and_sequence;
  rejectedWordsText.value = value.password_rejected_words.join("\n");
  sessionDays.value = storedDays(value.session_ttl_secs, SESSION_MAX_DAYS);
  refreshDays.value = storedDays(value.refresh_token_ttl_secs, REFRESH_MAX_DAYS);
  signUpUsername.value = value.sign_up_identifiers.includes("username");
  signUpEmailVerification.value = value.sign_up_email_verification_required;
  usernameCaseSensitive.value = value.username_case_sensitive;
  usernameMinLength.value = value.username_min_length;
  usernameMaxLength.value = value.username_max_length;
  signUpProfileName.value = value.sign_up_profile_fields.includes("name");
  signUpProfileAvatar.value = value.sign_up_profile_fields.includes("avatar");
  brandName.value = value.branding.display_name ?? "";
  logoUrl.value = value.branding.logo_url ?? "";
  darkLogoUrl.value = value.branding.dark_logo_url ?? "";
  faviconUrl.value = value.branding.favicon_url ?? "";
  primaryColor.value = value.branding.primary_color ?? "";
  termsUrl.value = value.branding.terms_url ?? "";
  privacyUrl.value = value.branding.privacy_url ?? "";
  supportEmail.value = value.branding.support_email ?? "";
  websiteUrl.value = value.branding.website_url ?? "";
  customCss.value = value.branding.custom_css ?? "";
  captchaEnabled.value = value.captcha.enabled;
  captchaProvider.value = value.captcha.provider;
  captchaSiteKey.value = value.captcha.site_key ?? "";
  captchaSecret.value = "";
  clearCaptchaSecret.value = false;
  captchaSecretSet.value = value.captcha.secret_set;
  captchaOnSignIn.value = value.captcha.on_sign_in;
  captchaOnSignUp.value = value.captcha.on_sign_up;
  captchaOnPasswordReset.value = value.captcha.on_password_reset;
  lockoutThreshold.value = value.login_lockout_threshold;
  lockoutMinutes.value = storedMinutes(value.login_lockout_duration_secs);
}

/**
 * A background refetch must not discard edits in progress.
 *
 * Adopt the incoming values when the form still shows the previous server state, or when it already
 * matches the new one (the usual case right after a save). Only a real unsaved edit is preserved.
 */
watch(
  () => experience.data.value,
  (next, previous) => {
    if (!next) return;
    const base = previous ?? null;
    const form = formValues();
    const matchesNext = sameSwitches(next, form);
    const matchesBase = base !== null && sameSwitches(base, form);
    if (matchesNext || !matchesBase) adopt(next);
  },
  { immediate: true },
);

const dirty = computed(() => {
  const base = baseline.value;
  if (!base) return false;
  return !sameSwitches(base, formValues());
});

watch(
  [
    brandName,
    logoUrl,
    darkLogoUrl,
    faviconUrl,
    primaryColor,
    termsUrl,
    privacyUrl,
    supportEmail,
    websiteUrl,
    customCss,
    rejectedWordsText,
    signUpUsername,
    signUpEmailVerification,
    usernameCaseSensitive,
    usernameMinLength,
    usernameMaxLength,
    signUpProfileName,
    signUpProfileAvatar,
    captchaEnabled,
    captchaProvider,
    captchaSiteKey,
    captchaSecret,
    clearCaptchaSecret,
    captchaOnSignIn,
    captchaOnSignUp,
    captchaOnPasswordReset,
    lockoutThreshold,
    lockoutMinutes,
  ],
  () => (formError.value = null),
);

const rejectedWordsIssue = computed<"count" | "length" | null>(() => {
  const words = rejectedWordsValues();
  if (words.length > 100) return "count";
  if (words.some((word) => [...word].length < 3 || [...word].length > 64)) return "length";
  return null;
});

const noFirstFactor = computed(() => !password.value && !emailCode.value);

/**
 * The CAPTCHA state the server would refuse: an enabled challenge with nothing to verify against, or
 * a key longer than the endpoint accepts. A stored secret satisfies the requirement without the page
 * ever reading it.
 */
const captchaIssue = computed<"siteKey" | "siteKeyLength" | "secret" | null>(() => {
  if ([...captchaSiteKey.value.trim()].length > 200) return "siteKeyLength";
  if ([...captchaSecret.value.trim()].length > 500) return "secret";
  if (captchaEnabled.value) {
    if (captchaSiteKey.value.trim() === "") return "siteKey";
    const usesStoredSecret = captchaSecretSet.value && !clearCaptchaSecret.value;
    if (captchaSecret.value.trim() === "" && !usesStoredSecret) return "secret";
  }
  return null;
});

const lockoutIssue = computed<"threshold" | "minutes" | null>(() => {
  if (
    lockoutThreshold.value < LOCKOUT_MIN_THRESHOLD ||
    lockoutThreshold.value > LOCKOUT_MAX_THRESHOLD
  ) {
    return "threshold";
  }
  if (lockoutMinutes.value < LOCKOUT_MIN_MINUTES || lockoutMinutes.value > LOCKOUT_MAX_MINUTES) {
    return "minutes";
  }
  return null;
});

const saveDisabled = computed(
  () => !dirty.value || noFirstFactor.value || update.isPending.value || baseline.value === null,
);

const stats = computed(() => {
  const items: string[] = [];
  const value = experience.data.value;
  if (value) items.push(t("signInExperience.updated", { date: formatStamp(value.updated_at) }));
  if (dirty.value) items.push(t("signInExperience.unsaved"));
  return items;
});

const socials = computed(() => connectors.data.value?.items ?? []);

function setSwitch(field: "signUp" | "password" | "emailCode" | "passkey" | "sso", value: boolean | "indeterminate"): void {
  const next = value === true;
  if (field === "signUp") signUp.value = next;
  if (field === "password") password.value = next;
  if (field === "emailCode") emailCode.value = next;
  if (field === "passkey") passkey.value = next;
  if (field === "sso") sso.value = next;
  formError.value = null;
}

/**
 * Turning MFA off makes the mandatory policy impossible, so the policy follows the switch instead
 * of leaving the form in a state the server would reject.
 */
function setMfa(value: boolean | "indeterminate"): void {
  mfaEnabled.value = value === true;
  if (!mfaEnabled.value) mfaPolicy.value = "user_controlled";
  formError.value = null;
}

function setMfaPolicy(value: string): void {
  mfaPolicy.value = value === "mandatory" ? "mandatory" : "user_controlled";
  formError.value = null;
}

function setTrustedDevices(value: boolean | "indeterminate"): void {
  trustedDevices.value = value === true;
  formError.value = null;
}

function setTrustedDays(value: string | number): void {
  const parsed = Number.parseInt(String(value), 10);
  trustedDeviceDays.value = Number.isNaN(parsed) ? 0 : parsed;
  formError.value = null;
}

function setPasswordMinLength(value: string | number): void {
  const parsed = Number.parseInt(String(value), 10);
  passwordMinLength.value = Number.isNaN(parsed) ? 0 : parsed;
  formError.value = null;
}

function setPasswordMinTypes(value: string): void {
  passwordMinTypes.value = Number.parseInt(value, 10) || 0;
  formError.value = null;
}

function setRejection(field: "userInfo" | "repetition", value: boolean | "indeterminate"): void {
  const next = value === true;
  if (field === "userInfo") rejectUserInfo.value = next;
  else rejectRepetition.value = next;
  formError.value = null;
}

function setDays(field: "session" | "refresh", value: string | number): void {
  const parsed = Number.parseInt(String(value), 10);
  const next = Number.isNaN(parsed) ? 0 : parsed;
  if (field === "session") sessionDays.value = next;
  else refreshDays.value = next;
  formError.value = null;
}

function setLockout(field: "threshold" | "minutes", value: string | number): void {
  const parsed = Number.parseInt(String(value), 10);
  const next = Number.isNaN(parsed) ? 0 : parsed;
  if (field === "threshold") lockoutThreshold.value = next;
  else lockoutMinutes.value = next;
  formError.value = null;
}

function discard(): void {
  const current = experience.data.value;
  if (current) adopt(current);
  formError.value = null;
}

async function save(): Promise<void> {
  const base = baseline.value;
  if (!base) return;
  if (noFirstFactor.value) {
    formError.value = t("signInExperience.invalidMethods");
    return;
  }
  if (passwordMinLength.value < 8 || passwordMinLength.value > 64) {
    formError.value = t("signInExperience.invalidPasswordMinLength");
    return;
  }
  if (passwordMinTypes.value < 1 || passwordMinTypes.value > 4) {
    formError.value = t("signInExperience.invalidPasswordMinTypes");
    return;
  }
  if (
    trustedDeviceDays.value < TRUSTED_MIN_DAYS ||
    trustedDeviceDays.value > TRUSTED_MAX_DAYS
  ) {
    formError.value = t("signInExperience.invalidTrustedDays");
    return;
  }
  if (rejectedWordsIssue.value !== null) {
    formError.value = t("signInExperience.invalidRejectedWords");
    return;
  }
  if (
    usernameMinLength.value < 3 ||
    usernameMaxLength.value > 32 ||
    usernameMinLength.value > usernameMaxLength.value
  ) {
    formError.value = t("signInExperience.invalidUsernameLength");
    return;
  }
  if (sessionDays.value < SESSION_MIN_DAYS || sessionDays.value > SESSION_MAX_DAYS) {
    formError.value = t("signInExperience.invalidSessionTtl");
    return;
  }
  if (refreshDays.value < REFRESH_MIN_DAYS || refreshDays.value > REFRESH_MAX_DAYS) {
    formError.value = t("signInExperience.invalidRefreshTtl");
    return;
  }
  if (brandName.value.trim().length > 64) {
    formError.value = t("signInExperience.invalidBrandingName");
    return;
  }
  if (
    [logoUrl.value, darkLogoUrl.value, faviconUrl.value, termsUrl.value, privacyUrl.value, websiteUrl.value].some(
      (url) => url.trim() !== "" && !/^https?:\/\/[^\s]+$/.test(url.trim()),
    )
  ) {
    formError.value = t("signInExperience.invalidBrandingUrl");
    return;
  }
  if (supportEmail.value.trim() !== "" && !/^[^\s@]+@[^\s@]+$/.test(supportEmail.value.trim())) {
    formError.value = t("signInExperience.invalidBrandingEmail");
    return;
  }
  if (primaryColor.value.trim() !== "" && !/^#[0-9a-fA-F]{6}$/.test(primaryColor.value.trim())) {
    formError.value = t("signInExperience.invalidBrandingColor");
    return;
  }
  if ([...customCss.value.trim()].length > 20_000) {
    formError.value = t("signInExperience.invalidBrandingCss");
    return;
  }
  if (captchaIssue.value !== null) {
    formError.value =
      captchaIssue.value === "siteKeyLength"
        ? t("signInExperience.invalidCaptchaSiteKey")
        : captchaIssue.value === "secret"
          ? t("signInExperience.invalidCaptchaSecret")
          : t("signInExperience.invalidCaptcha");
    return;
  }
  if (lockoutIssue.value !== null) {
    formError.value =
      lockoutIssue.value === "threshold"
        ? t("signInExperience.invalidLockoutThreshold")
        : t("signInExperience.invalidLockoutMinutes");
    return;
  }

  const body: UpdateSignInExperienceRequest = {};
  if (signUp.value !== base.sign_up_enabled) body.sign_up_enabled = signUp.value;
  if (password.value !== base.password_sign_in_enabled) body.password_sign_in_enabled = password.value;
  if (emailCode.value !== base.email_code_sign_in_enabled) body.email_code_sign_in_enabled = emailCode.value;
  if (passkey.value !== base.passkey_sign_in_enabled) body.passkey_sign_in_enabled = passkey.value;
  if (sso.value !== base.single_sign_on_enabled) body.single_sign_on_enabled = sso.value;
  if (mfaEnabled.value !== base.mfa_enabled) body.mfa_enabled = mfaEnabled.value;
  if (mfaPolicy.value !== base.mfa_policy) body.mfa_policy = mfaPolicy.value;
  if (trustedDevices.value !== base.mfa_trusted_devices_enabled) {
    body.mfa_trusted_devices_enabled = trustedDevices.value;
  }
  if (trustedDeviceDays.value !== base.mfa_trusted_device_ttl_days) {
    body.mfa_trusted_device_ttl_days = trustedDeviceDays.value;
  }
  if (passwordMinLength.value !== base.password_min_length) body.password_min_length = passwordMinLength.value;
  if (passwordMinTypes.value !== base.password_min_character_types) {
    body.password_min_character_types = passwordMinTypes.value;
  }
  if (rejectUserInfo.value !== base.password_reject_user_info) {
    body.password_reject_user_info = rejectUserInfo.value;
  }
  if (rejectRepetition.value !== base.password_reject_repetition_and_sequence) {
    body.password_reject_repetition_and_sequence = rejectRepetition.value;
  }
  if (!sameWords(base.password_rejected_words, rejectedWordsValues())) {
    body.password_rejected_words = rejectedWordsValues();
  }
  if (storedDays(base.session_ttl_secs, SESSION_MAX_DAYS) !== sessionDays.value) {
    body.session_ttl_secs = sessionDays.value * 86_400;
  }
  if (storedDays(base.refresh_token_ttl_secs, REFRESH_MAX_DAYS) !== refreshDays.value) {
    body.refresh_token_ttl_secs = refreshDays.value * 86_400;
  }
  if (!sameWords(base.sign_up_identifiers, signUpIdentifiers())) {
    body.sign_up_identifiers = signUpIdentifiers();
  }
  if (signUpEmailVerification.value !== base.sign_up_email_verification_required) {
    body.sign_up_email_verification_required = signUpEmailVerification.value;
  }
  if (usernameCaseSensitive.value !== base.username_case_sensitive) {
    body.username_case_sensitive = usernameCaseSensitive.value;
  }
  if (usernameMinLength.value !== base.username_min_length) {
    body.username_min_length = usernameMinLength.value;
  }
  if (usernameMaxLength.value !== base.username_max_length) {
    body.username_max_length = usernameMaxLength.value;
  }
  if (!sameWords(base.sign_up_profile_fields, signUpProfileFields())) {
    body.sign_up_profile_fields = signUpProfileFields();
  }
  if (!sameBranding(base.branding, brandingValues())) {
    body.branding = {
      display_name: brandName.value.trim(),
      logo_url: logoUrl.value.trim(),
      dark_logo_url: darkLogoUrl.value.trim(),
      favicon_url: faviconUrl.value.trim(),
      primary_color: primaryColor.value.trim(),
      terms_url: termsUrl.value.trim(),
      privacy_url: privacyUrl.value.trim(),
      support_email: supportEmail.value.trim(),
      website_url: websiteUrl.value.trim(),
      custom_css: customCss.value.trim(),
    };
  }
  const captchaChanged =
    captchaEnabled.value !== base.captcha.enabled ||
    captchaProvider.value !== base.captcha.provider ||
    captchaSiteKey.value.trim() !== (base.captcha.site_key ?? "") ||
    captchaSecret.value.trim() !== "" ||
    clearCaptchaSecret.value ||
    captchaOnSignIn.value !== base.captcha.on_sign_in ||
    captchaOnSignUp.value !== base.captcha.on_sign_up ||
    captchaOnPasswordReset.value !== base.captcha.on_password_reset;
  if (captchaChanged) {
    body.captcha = {
      enabled: captchaEnabled.value,
      provider: captchaProvider.value,
      site_key: captchaSiteKey.value.trim(),
      on_sign_in: captchaOnSignIn.value,
      on_sign_up: captchaOnSignUp.value,
      on_password_reset: captchaOnPasswordReset.value,
    };
    // The secret is write-only: omitted keeps it, an empty string clears it.
    if (clearCaptchaSecret.value) body.captcha.secret = "";
    else if (captchaSecret.value.trim() !== "") body.captcha.secret = captchaSecret.value.trim();
  }
  if (lockoutThreshold.value !== base.login_lockout_threshold) {
    body.login_lockout_threshold = lockoutThreshold.value;
  }
  if (storedMinutes(base.login_lockout_duration_secs) !== lockoutMinutes.value) {
    body.login_lockout_duration_secs = lockoutMinutes.value * 60;
  }
  if (Object.keys(body).length === 0) return;

  formError.value = null;
  try {
    const updated = await update.mutateAsync(body);
    adopt(updated);
    toast({
      title: t("signInExperience.savedToast"),
      description: t("signInExperience.savedDescription", { tenant: ui.tenant }),
      variant: "success",
    });
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

function setUsernameLength(which: "min" | "max", value: string | number): void {
  const parsed = typeof value === "number" ? value : Number.parseInt(value, 10);
  const next = Number.isNaN(parsed) ? 0 : parsed;
  if (which === "min") usernameMinLength.value = next;
  else usernameMaxLength.value = next;
}

function formatStamp(at: string): string {
  const parsed = new Date(at);
  return Number.isNaN(parsed.getTime()) ? at : `${parsed.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('signInExperience.title')"
      :subtitle="t('signInExperience.subtitle', { tenant: ui.tenant })"
      :stats="stats"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="experience.refetch()">
          <RefreshCw :class="experience.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button v-if="dirty" variant="secondary" size="sm" @click="discard">
          {{ t('signInExperience.discard') }}
        </Button>
        <Button
          variant="primary"
          size="sm"
          :disabled="saveDisabled"
          @click="save"
        >
          {{ update.isPending.value ? t('signInExperience.saving') : t('signInExperience.save') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="experience.isPending.value"
      :error="experience.error.value"
      :on-retry="() => experience.refetch()"
    >
      <Alert v-if="formError" variant="error">
        <CircleAlert />
        <div class="min-w-0">
          <AlertTitle>{{ t('signInExperience.saveFailed') }}</AlertTitle>
          <AlertDescription>{{ formError }}</AlertDescription>
        </div>
      </Alert>

      <div class="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div class="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>{{ t('signInExperience.signUp') }}</CardTitle>
              <CardDescription>{{ t('signInExperience.signUpHint') }}</CardDescription>
            </CardHeader>
            <CardContent>
              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="sign-up-enabled"
                  :model-value="signUp"
                  :disabled="update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => setSwitch('signUp', value)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="sign-up-enabled">{{ t('signInExperience.signUpField') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.signUpFieldHint') }}
                  </p>
                </div>
              </div>

              <div v-if="signUp" class="mt-4 flex flex-col gap-3 border-t border-rule pt-4">
                <p class="text-[11.5px] leading-snug text-ink-faint">
                  {{ t('signInExperience.signUpPolicyHint') }}
                </p>

                <label class="flex items-start gap-2.5">
                  <Checkbox
                    id="sign-up-username"
                    :model-value="signUpUsername"
                    :disabled="update.isPending.value"
                    @update:model-value="(value: boolean | 'indeterminate') => (signUpUsername = value === true)"
                  />
                  <span class="min-w-0 -mt-0.5">
                    <Label for="sign-up-username">{{ t('signInExperience.signUpUsername') }}</Label>
                    <span class="mt-0.5 block text-[11.5px] leading-snug text-ink-faint">
                      {{ t('signInExperience.signUpUsernameHint') }}
                    </span>
                  </span>
                </label>

                <label class="flex items-start gap-2.5">
                  <Checkbox
                    id="sign-up-verify-email"
                    :model-value="signUpEmailVerification"
                    :disabled="update.isPending.value"
                    @update:model-value="(value: boolean | 'indeterminate') => (signUpEmailVerification = value === true)"
                  />
                  <span class="min-w-0 -mt-0.5">
                    <Label for="sign-up-verify-email">{{ t('signInExperience.signUpVerifyEmail') }}</Label>
                    <span class="mt-0.5 block text-[11.5px] leading-snug text-ink-faint">
                      {{ t('signInExperience.signUpVerifyEmailHint') }}
                    </span>
                  </span>
                </label>

                <div class="grid grid-cols-2 gap-3">
                  <div class="flex flex-col gap-1.5">
                    <Label for="username-min-length">{{ t('signInExperience.usernameMin') }}</Label>
                    <Input
                      id="username-min-length"
                      type="number"
                      min="3"
                      max="32"
                      :model-value="usernameMinLength"
                      :invalid="usernameMinLength < 3 || usernameMinLength > 32"
                      :disabled="update.isPending.value"
                      class="w-[120px]"
                      @update:model-value="(value: string | number) => setUsernameLength('min', value)"
                    />
                  </div>
                  <div class="flex flex-col gap-1.5">
                    <Label for="username-max-length">{{ t('signInExperience.usernameMax') }}</Label>
                    <Input
                      id="username-max-length"
                      type="number"
                      min="3"
                      max="32"
                      :model-value="usernameMaxLength"
                      :invalid="usernameMaxLength > 32 || usernameMaxLength < usernameMinLength"
                      :disabled="update.isPending.value"
                      class="w-[120px]"
                      @update:model-value="(value: string | number) => setUsernameLength('max', value)"
                    />
                  </div>
                </div>

                <label class="flex items-start gap-2.5">
                  <Checkbox
                    id="username-case-sensitive"
                    :model-value="usernameCaseSensitive"
                    :disabled="update.isPending.value"
                    @update:model-value="(value: boolean | 'indeterminate') => (usernameCaseSensitive = value === true)"
                  />
                  <span class="min-w-0 -mt-0.5">
                    <Label for="username-case-sensitive">{{ t('signInExperience.usernameCase') }}</Label>
                    <span class="mt-0.5 block text-[11.5px] leading-snug text-ink-faint">
                      {{ t('signInExperience.usernameCaseHint') }}
                    </span>
                  </span>
                </label>

                <div class="flex flex-col gap-2">
                  <Label>{{ t('signInExperience.signUpProfileFields') }}</Label>
                  <div class="flex flex-wrap items-center gap-4">
                    <label class="flex items-center gap-2">
                      <Checkbox
                        id="sign-up-profile-name"
                        :model-value="signUpProfileName"
                        :disabled="update.isPending.value"
                        @update:model-value="(value: boolean | 'indeterminate') => (signUpProfileName = value === true)"
                      />
                      <span class="text-[12px]">{{ t('signInExperience.profileName') }}</span>
                    </label>
                    <label class="flex items-center gap-2">
                      <Checkbox
                        id="sign-up-profile-avatar"
                        :model-value="signUpProfileAvatar"
                        :disabled="update.isPending.value"
                        @update:model-value="(value: boolean | 'indeterminate') => (signUpProfileAvatar = value === true)"
                      />
                      <span class="text-[12px]">{{ t('signInExperience.profileAvatar') }}</span>
                    </label>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{{ t('signInExperience.branding') }}</CardTitle>
              <CardDescription>{{ t('signInExperience.brandingHint') }}</CardDescription>
            </CardHeader>
            <CardContent class="flex flex-col gap-3">
              <div class="grid grid-cols-2 gap-3">
                <div class="flex flex-col gap-1.5">
                  <Label for="brand-display-name">{{ t('signInExperience.brandName') }}</Label>
                  <Input
                    id="brand-display-name"
                    v-model="brandName"
                    :invalid="brandName.trim().length > 64"
                    :disabled="update.isPending.value"
                    :placeholder="ui.tenant"
                    autocomplete="off"
                  />
                </div>
                <div class="flex flex-col gap-1.5">
                  <Label for="brand-primary-color">{{ t('signInExperience.brandColor') }}</Label>
                  <div class="flex items-center gap-2">
                    <Input
                      id="brand-primary-color"
                      v-model="primaryColor"
                      :invalid="primaryColor.trim() !== '' && !/^#[0-9a-fA-F]{6}$/.test(primaryColor.trim())"
                      :disabled="update.isPending.value"
                      placeholder="#0f6cbd"
                      autocomplete="off"
                      spellcheck="false"
                      class="mono-data"
                    />
                    <span
                      v-if="/^#[0-9a-fA-F]{6}$/.test(primaryColor.trim())"
                      class="size-7 shrink-0 rounded-md border border-rule"
                      :style="{ backgroundColor: primaryColor.trim() }"
                      aria-hidden="true"
                    />
                  </div>
                </div>
              </div>

              <div class="grid grid-cols-2 gap-3">
                <div class="flex flex-col gap-1.5">
                  <Label for="brand-logo">{{ t('signInExperience.brandLogo') }}</Label>
                  <Input
                    id="brand-logo"
                    v-model="logoUrl"
                    :invalid="logoUrl.trim() !== '' && !/^https?:\/\/[^\s]+$/.test(logoUrl.trim())"
                    :disabled="update.isPending.value"
                    placeholder="https://cdn.example/logo.png"
                    autocomplete="off"
                    spellcheck="false"
                    class="mono-data text-[12.5px]"
                  />
                </div>
                <div class="flex flex-col gap-1.5">
                  <Label for="brand-dark-logo">{{ t('signInExperience.brandDarkLogo') }}</Label>
                  <Input
                    id="brand-dark-logo"
                    v-model="darkLogoUrl"
                    :invalid="darkLogoUrl.trim() !== '' && !/^https?:\/\/[^\s]+$/.test(darkLogoUrl.trim())"
                    :disabled="update.isPending.value"
                    placeholder="https://cdn.example/logo-dark.png"
                    autocomplete="off"
                    spellcheck="false"
                    class="mono-data text-[12.5px]"
                  />
                </div>
              </div>

              <div class="flex flex-col gap-1.5">
                <Label for="brand-favicon">{{ t('signInExperience.brandFavicon') }}</Label>
                <Input
                  id="brand-favicon"
                  v-model="faviconUrl"
                  :invalid="faviconUrl.trim() !== '' && !/^https?:\/\/[^\s]+$/.test(faviconUrl.trim())"
                  :disabled="update.isPending.value"
                  placeholder="https://cdn.example/favicon.ico"
                  autocomplete="off"
                  spellcheck="false"
                  class="mono-data text-[12.5px]"
                />
              </div>

              <div class="grid grid-cols-2 gap-3">
                <div class="flex flex-col gap-1.5">
                  <Label for="brand-support-email">{{ t('signInExperience.brandSupportEmail') }}</Label>
                  <Input
                    id="brand-support-email"
                    v-model="supportEmail"
                    :invalid="supportEmail.trim() !== '' && !/^[^\s@]+@[^\s@]+$/.test(supportEmail.trim())"
                    :disabled="update.isPending.value"
                    placeholder="help@example.com"
                    autocomplete="off"
                    spellcheck="false"
                    class="mono-data text-[12.5px]"
                  />
                </div>
                <div class="flex flex-col gap-1.5">
                  <Label for="brand-website">{{ t('signInExperience.brandWebsite') }}</Label>
                  <Input
                    id="brand-website"
                    v-model="websiteUrl"
                    :invalid="websiteUrl.trim() !== '' && !/^https?:\/\/[^\s]+$/.test(websiteUrl.trim())"
                    :disabled="update.isPending.value"
                    placeholder="https://example.com"
                    autocomplete="off"
                    spellcheck="false"
                    class="mono-data text-[12.5px]"
                  />
                </div>
              </div>
              <p v-if="supportEmail.trim() !== '' && !/^[^\s@]+@[^\s@]+$/.test(supportEmail.trim())" class="text-[11.5px] leading-snug text-deny">
                {{ t('signInExperience.invalidBrandingEmail') }}
              </p>

              <div class="grid grid-cols-2 gap-3">
                <div class="flex flex-col gap-1.5">
                  <Label for="brand-terms">{{ t('signInExperience.brandTerms') }}</Label>
                  <Input
                    id="brand-terms"
                    v-model="termsUrl"
                    :invalid="termsUrl.trim() !== '' && !/^https?:\/\/[^\s]+$/.test(termsUrl.trim())"
                    :disabled="update.isPending.value"
                    placeholder="https://example.com/terms"
                    autocomplete="off"
                    spellcheck="false"
                    class="mono-data text-[12.5px]"
                  />
                </div>
                <div class="flex flex-col gap-1.5">
                  <Label for="brand-privacy">{{ t('signInExperience.brandPrivacy') }}</Label>
                  <Input
                    id="brand-privacy"
                    v-model="privacyUrl"
                    :invalid="privacyUrl.trim() !== '' && !/^https?:\/\/[^\s]+$/.test(privacyUrl.trim())"
                    :disabled="update.isPending.value"
                    placeholder="https://example.com/privacy"
                    autocomplete="off"
                    spellcheck="false"
                    class="mono-data text-[12.5px]"
                  />
                </div>
              </div>
              <p class="text-[11.5px] leading-snug text-ink-faint">
                {{ t('signInExperience.brandingFieldsHint') }}
              </p>

              <Separator />

              <div class="flex flex-col gap-1.5">
                <Label for="brand-custom-css">{{ t('signInExperience.brandCustomCss') }}</Label>
                <Textarea
                  id="brand-custom-css"
                  v-model="customCss"
                  rows="6"
                  :invalid="[...customCss.trim()].length > 20_000"
                  :disabled="update.isPending.value"
                  placeholder=".mono-card { border-radius: 12px; }"
                  spellcheck="false"
                />
                <p class="text-[11.5px] leading-snug text-ink-faint">
                  {{ t('signInExperience.brandCustomCssHint') }}
                </p>
                <p v-if="[...customCss.trim()].length > 20_000" class="text-[11.5px] leading-snug text-deny">
                  {{ t('signInExperience.invalidBrandingCss') }}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{{ t('signInExperience.methods') }}</CardTitle>
              <CardDescription>{{ t('signInExperience.methodsHint') }}</CardDescription>
            </CardHeader>
            <CardContent class="flex flex-col gap-3">
              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="password-sign-in-enabled"
                  :model-value="password"
                  :disabled="update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => setSwitch('password', value)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="password-sign-in-enabled">{{ t('signInExperience.passwordField') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.passwordFieldHint') }}
                  </p>
                </div>
              </div>

              <Separator />

              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="email-code-sign-in-enabled"
                  :model-value="emailCode"
                  :disabled="update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => setSwitch('emailCode', value)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="email-code-sign-in-enabled">{{ t('signInExperience.emailCodeField') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.emailCodeFieldHint') }}
                  </p>
                </div>
              </div>

              <Separator />

              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="passkey-sign-in-enabled"
                  :model-value="passkey"
                  :disabled="update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => setSwitch('passkey', value)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="passkey-sign-in-enabled">{{ t('signInExperience.passkeyField') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.passkeyFieldHint') }}
                  </p>
                </div>
              </div>

              <Separator />

              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="sso-sign-in-enabled"
                  :model-value="sso"
                  :disabled="update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => setSwitch('sso', value)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="sso-sign-in-enabled">{{ t('signInExperience.ssoField') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.ssoFieldHint') }}
                  </p>
                </div>
              </div>

              <Alert v-if="noFirstFactor" variant="warn">
                <TriangleAlert />
                <AlertDescription>{{ t('signInExperience.invalidMethods') }}</AlertDescription>
              </Alert>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{{ t('signInExperience.passwordPolicy') }}</CardTitle>
              <CardDescription>{{ t('signInExperience.passwordPolicyHint') }}</CardDescription>
            </CardHeader>
            <CardContent class="flex flex-col gap-3">
              <Label for="password-min-length">{{ t('signInExperience.passwordMinLength') }}</Label>
              <Input
                id="password-min-length"
                type="number"
                min="8"
                max="64"
                :model-value="passwordMinLength"
                :invalid="passwordMinLength < 8 || passwordMinLength > 64"
                :disabled="update.isPending.value"
                class="w-[120px]"
                @update:model-value="(value: string | number) => setPasswordMinLength(value)"
              />
              <p class="text-[11.5px] leading-snug text-ink-faint">
                {{ t('signInExperience.passwordMinLengthHint') }}
              </p>
              <p v-if="passwordMinLength < 8 || passwordMinLength > 64" class="text-[11.5px] leading-snug text-deny">
                {{ t('signInExperience.invalidPasswordMinLength') }}
              </p>

              <Separator />

              <div class="flex flex-col gap-1.5">
                <Label for="password-min-types">{{ t('signInExperience.passwordMinTypes') }}</Label>
                <NativeSelect
                  id="password-min-types"
                  :model-value="String(passwordMinTypes)"
                  :disabled="update.isPending.value"
                  class="w-[220px]"
                  @update:model-value="(value: string) => setPasswordMinTypes(value)"
                >
                  <option value="1">{{ t('signInExperience.passwordMinTypesAny') }}</option>
                  <option value="2">{{ t('signInExperience.passwordMinTypesTwo') }}</option>
                  <option value="3">{{ t('signInExperience.passwordMinTypesThree') }}</option>
                  <option value="4">{{ t('signInExperience.passwordMinTypesFour') }}</option>
                </NativeSelect>
                <p class="text-[11.5px] leading-snug text-ink-faint">
                  {{ t('signInExperience.passwordMinTypesHint') }}
                </p>
                <p v-if="passwordMinTypes < 1 || passwordMinTypes > 4" class="text-[11.5px] leading-snug text-deny">
                  {{ t('signInExperience.invalidPasswordMinTypes') }}
                </p>
              </div>

              <Separator />

              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="password-reject-user-info"
                  :model-value="rejectUserInfo"
                  :disabled="update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => setRejection('userInfo', value)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="password-reject-user-info">{{ t('signInExperience.rejectUserInfo') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.rejectUserInfoHint') }}
                  </p>
                </div>
              </div>

              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="password-reject-repetition"
                  :model-value="rejectRepetition"
                  :disabled="update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => setRejection('repetition', value)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="password-reject-repetition">{{ t('signInExperience.rejectRepetition') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.rejectRepetitionHint') }}
                  </p>
                </div>
              </div>

              <Separator />

              <div class="flex flex-col gap-1.5">
                <Label for="password-rejected-words">{{ t('signInExperience.rejectedWords') }}</Label>
                <Textarea
                  id="password-rejected-words"
                  v-model="rejectedWordsText"
                  rows="3"
                  :invalid="rejectedWordsIssue !== null"
                  :disabled="update.isPending.value"
                  placeholder="monaca&#10;qwerty"
                  spellcheck="false"
                />
                <p class="text-[11.5px] leading-snug text-ink-faint">
                  {{ t('signInExperience.rejectedWordsHint') }}
                </p>
                <p v-if="rejectedWordsIssue !== null" class="text-[11.5px] leading-snug text-deny">
                  {{ t('signInExperience.invalidRejectedWords') }}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{{ t('signInExperience.sessions') }}</CardTitle>
              <CardDescription>{{ t('signInExperience.sessionsHint') }}</CardDescription>
            </CardHeader>
            <CardContent class="grid grid-cols-2 gap-3">
              <div class="flex flex-col gap-1.5">
                <Label for="session-ttl">{{ t('signInExperience.sessionTtl') }}</Label>
                <Input
                  id="session-ttl"
                  type="number"
                  :min="SESSION_MIN_DAYS"
                  :max="SESSION_MAX_DAYS"
                  :model-value="sessionDays"
                  :invalid="sessionDays < SESSION_MIN_DAYS || sessionDays > SESSION_MAX_DAYS"
                  :disabled="update.isPending.value"
                  class="w-[120px]"
                  @update:model-value="(value: string | number) => setDays('session', value)"
                />
                <p class="text-[11.5px] leading-snug text-ink-faint">
                  {{ t('signInExperience.sessionTtlHint') }}
                </p>
                <p
                  v-if="sessionDays < SESSION_MIN_DAYS || sessionDays > SESSION_MAX_DAYS"
                  class="text-[11.5px] leading-snug text-deny"
                >
                  {{ t('signInExperience.invalidSessionTtl') }}
                </p>
              </div>
              <div class="flex flex-col gap-1.5">
                <Label for="refresh-ttl">{{ t('signInExperience.refreshTtl') }}</Label>
                <Input
                  id="refresh-ttl"
                  type="number"
                  :min="REFRESH_MIN_DAYS"
                  :max="REFRESH_MAX_DAYS"
                  :model-value="refreshDays"
                  :invalid="refreshDays < REFRESH_MIN_DAYS || refreshDays > REFRESH_MAX_DAYS"
                  :disabled="update.isPending.value"
                  class="w-[120px]"
                  @update:model-value="(value: string | number) => setDays('refresh', value)"
                />
                <p class="text-[11.5px] leading-snug text-ink-faint">
                  {{ t('signInExperience.refreshTtlHint') }}
                </p>
                <p
                  v-if="refreshDays < REFRESH_MIN_DAYS || refreshDays > REFRESH_MAX_DAYS"
                  class="text-[11.5px] leading-snug text-deny"
                >
                  {{ t('signInExperience.invalidRefreshTtl') }}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{{ t('signInExperience.security') }}</CardTitle>
              <CardDescription>{{ t('signInExperience.securityHint') }}</CardDescription>
            </CardHeader>
            <CardContent class="flex flex-col gap-3">
              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="captcha-enabled"
                  :model-value="captchaEnabled"
                  :disabled="update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => (captchaEnabled = value === true)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="captcha-enabled">{{ t('signInExperience.captchaField') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.captchaFieldHint') }}
                  </p>
                </div>
              </div>

              <div
                v-if="captchaEnabled || captchaSecretSet"
                class="flex flex-col gap-3 border-t border-rule pt-4"
              >
                <div class="grid grid-cols-2 gap-3">
                  <div class="flex flex-col gap-1.5">
                    <Label for="captcha-provider">{{ t('signInExperience.captchaProvider') }}</Label>
                    <NativeSelect
                      id="captcha-provider"
                      :model-value="captchaProvider"
                      :disabled="update.isPending.value"
                      @update:model-value="(value: string) => (captchaProvider = value === 'recaptcha' ? 'recaptcha' : 'turnstile')"
                    >
                      <option value="turnstile">{{ t('signInExperience.captchaProviderTurnstile') }}</option>
                      <option value="recaptcha">{{ t('signInExperience.captchaProviderRecaptcha') }}</option>
                    </NativeSelect>
                  </div>
                  <div class="flex flex-col gap-1.5">
                    <Label for="captcha-site-key">{{ t('signInExperience.captchaSiteKey') }}</Label>
                    <Input
                      id="captcha-site-key"
                      v-model="captchaSiteKey"
                      :invalid="captchaIssue === 'siteKey' || captchaIssue === 'siteKeyLength'"
                      :disabled="update.isPending.value"
                      autocomplete="off"
                      spellcheck="false"
                      class="mono-data text-[12.5px]"
                    />
                  </div>
                </div>

                <div class="flex flex-col gap-1.5">
                  <Label for="captcha-secret">{{ t('signInExperience.captchaSecret') }}</Label>
                  <Input
                    id="captcha-secret"
                    v-model="captchaSecret"
                    type="password"
                    :invalid="captchaIssue === 'secret'"
                    :disabled="update.isPending.value || clearCaptchaSecret"
                    :placeholder="captchaSecretSet ? t('signInExperience.captchaSecretStored') : t('signInExperience.captchaSecretEmpty')"
                    autocomplete="new-password"
                    spellcheck="false"
                    class="mono-data text-[12.5px]"
                  />
                  <p class="text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.captchaSecretHint') }}
                  </p>
                  <label v-if="captchaSecretSet" class="flex items-center gap-2">
                    <Checkbox
                      id="captcha-clear-secret"
                      :model-value="clearCaptchaSecret"
                      :disabled="update.isPending.value"
                      @update:model-value="(value: boolean | 'indeterminate') => (clearCaptchaSecret = value === true)"
                    />
                    <span class="text-[12px]">{{ t('signInExperience.captchaClearSecret') }}</span>
                  </label>
                </div>

                <div class="flex flex-col gap-2">
                  <Label>{{ t('signInExperience.captchaFlows') }}</Label>
                  <div class="flex flex-wrap items-center gap-4">
                    <label class="flex items-center gap-2">
                      <Checkbox
                        id="captcha-on-sign-in"
                        :model-value="captchaOnSignIn"
                        :disabled="update.isPending.value"
                        @update:model-value="(value: boolean | 'indeterminate') => (captchaOnSignIn = value === true)"
                      />
                      <span class="text-[12px]">{{ t('signInExperience.captchaFlowSignIn') }}</span>
                    </label>
                    <label class="flex items-center gap-2">
                      <Checkbox
                        id="captcha-on-sign-up"
                        :model-value="captchaOnSignUp"
                        :disabled="update.isPending.value"
                        @update:model-value="(value: boolean | 'indeterminate') => (captchaOnSignUp = value === true)"
                      />
                      <span class="text-[12px]">{{ t('signInExperience.captchaFlowSignUp') }}</span>
                    </label>
                    <label class="flex items-center gap-2">
                      <Checkbox
                        id="captcha-on-password-reset"
                        :model-value="captchaOnPasswordReset"
                        :disabled="update.isPending.value"
                        @update:model-value="(value: boolean | 'indeterminate') => (captchaOnPasswordReset = value === true)"
                      />
                      <span class="text-[12px]">{{ t('signInExperience.captchaFlowPasswordReset') }}</span>
                    </label>
                  </div>
                  <p class="text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.captchaFlowsHint') }}
                  </p>
                </div>

                <p v-if="captchaIssue !== null" class="text-[11.5px] leading-snug text-deny">
                  {{
                    captchaIssue === 'siteKeyLength'
                      ? t('signInExperience.invalidCaptchaSiteKey')
                      : captchaIssue === 'secret'
                        ? t('signInExperience.invalidCaptchaSecret')
                        : t('signInExperience.invalidCaptcha')
                  }}
                </p>
              </div>

              <Separator />

              <div class="grid grid-cols-2 gap-3">
                <div class="flex flex-col gap-1.5">
                  <Label for="lockout-threshold">{{ t('signInExperience.lockoutThreshold') }}</Label>
                  <Input
                    id="lockout-threshold"
                    type="number"
                    :min="LOCKOUT_MIN_THRESHOLD"
                    :max="LOCKOUT_MAX_THRESHOLD"
                    :model-value="lockoutThreshold"
                    :invalid="lockoutIssue === 'threshold'"
                    :disabled="update.isPending.value"
                    class="w-[120px]"
                    @update:model-value="(value: string | number) => setLockout('threshold', value)"
                  />
                  <p class="text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.lockoutThresholdHint') }}
                  </p>
                  <p v-if="lockoutIssue === 'threshold'" class="text-[11.5px] leading-snug text-deny">
                    {{ t('signInExperience.invalidLockoutThreshold') }}
                  </p>
                </div>
                <div class="flex flex-col gap-1.5">
                  <Label for="lockout-minutes">{{ t('signInExperience.lockoutMinutes') }}</Label>
                  <Input
                    id="lockout-minutes"
                    type="number"
                    :min="LOCKOUT_MIN_MINUTES"
                    :max="LOCKOUT_MAX_MINUTES"
                    :model-value="lockoutMinutes"
                    :invalid="lockoutIssue === 'minutes'"
                    :disabled="lockoutThreshold === 0 || update.isPending.value"
                    class="w-[120px]"
                    @update:model-value="(value: string | number) => setLockout('minutes', value)"
                  />
                  <p class="text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.lockoutMinutesHint') }}
                  </p>
                  <p v-if="lockoutIssue === 'minutes'" class="text-[11.5px] leading-snug text-deny">
                    {{ t('signInExperience.invalidLockoutMinutes') }}
                  </p>
                </div>
              </div>
              <p class="text-[11.5px] leading-snug text-ink-faint">
                {{ t('signInExperience.lockoutHint') }}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{{ t('signInExperience.mfa') }}</CardTitle>
              <CardDescription>{{ t('signInExperience.mfaHint') }}</CardDescription>
            </CardHeader>
            <CardContent class="flex flex-col gap-3">
              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="mfa-enabled"
                  :model-value="mfaEnabled"
                  :disabled="update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => setMfa(value)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="mfa-enabled">{{ t('signInExperience.mfaField') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.mfaFieldHint') }}
                  </p>
                </div>
              </div>

              <Separator />

              <div class="flex flex-col gap-1.5">
                <Label for="mfa-policy">{{ t('signInExperience.mfaPolicy') }}</Label>
                <NativeSelect
                  id="mfa-policy"
                  :model-value="mfaPolicy"
                  :disabled="!mfaEnabled || update.isPending.value"
                  @update:model-value="(value: string) => setMfaPolicy(value)"
                >
                  <option value="user_controlled">{{ t('signInExperience.mfaPolicyUser') }}</option>
                  <option value="mandatory">{{ t('signInExperience.mfaPolicyMandatory') }}</option>
                </NativeSelect>
                <p class="text-[11.5px] leading-snug text-ink-faint">
                  {{ t('signInExperience.mfaPolicyHint') }}
                </p>
              </div>

              <Separator />

              <div class="flex items-start gap-2.5">
                <Checkbox
                  id="mfa-trusted-devices"
                  :model-value="trustedDevices"
                  :disabled="!mfaEnabled || update.isPending.value"
                  @update:model-value="(value: boolean | 'indeterminate') => setTrustedDevices(value)"
                />
                <div class="min-w-0 -mt-0.5">
                  <Label for="mfa-trusted-devices">{{ t('signInExperience.trustedDevicesField') }}</Label>
                  <p class="mt-0.5 text-[11.5px] leading-snug text-ink-faint">
                    {{ t('signInExperience.trustedDevicesHint') }}
                  </p>
                </div>
              </div>

              <div class="flex flex-col gap-1.5">
                <Label for="mfa-trusted-days">{{ t('signInExperience.trustedDays') }}</Label>
                <Input
                  id="mfa-trusted-days"
                  type="number"
                  :min="TRUSTED_MIN_DAYS"
                  :max="TRUSTED_MAX_DAYS"
                  :model-value="trustedDeviceDays"
                  :invalid="trustedDeviceDays < TRUSTED_MIN_DAYS || trustedDeviceDays > TRUSTED_MAX_DAYS"
                  :disabled="!mfaEnabled || !trustedDevices || update.isPending.value"
                  class="w-[120px]"
                  @update:model-value="(value: string | number) => setTrustedDays(value)"
                />
                <p class="text-[11.5px] leading-snug text-ink-faint">
                  {{ t('signInExperience.trustedDaysHint') }}
                </p>
                <p
                  v-if="trustedDeviceDays < TRUSTED_MIN_DAYS || trustedDeviceDays > TRUSTED_MAX_DAYS"
                  class="text-[11.5px] leading-snug text-deny"
                >
                  {{ t('signInExperience.invalidTrustedDays') }}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>

        <Card class="lg:sticky lg:top-[72px]">
          <CardHeader>
            <CardTitle>{{ t('signInExperience.preview') }}</CardTitle>
            <CardDescription>{{ t('signInExperience.previewHint') }}</CardDescription>
          </CardHeader>
          <CardContent>
            <div class="rounded-md border border-rule bg-paper p-4">
              <p class="text-[13.5px] font-semibold tracking-[-0.01em] text-ink">
                {{ t('signInExperience.previewHeading', { tenant: ui.tenant }) }}
              </p>

              <div
                v-if="captchaEnabled"
                class="mt-3 flex items-center gap-2 rounded-md border border-rule bg-paper px-2.5 py-2"
              >
                <ShieldCheck class="size-3.5 shrink-0 text-ink-faint" />
                <span class="text-[11px] leading-snug text-ink-faint">
                  {{ t('signInExperience.previewCaptcha') }}
                </span>
              </div>

              <div v-if="password" class="mt-3.5 flex flex-col gap-2">
                <Input
                  :model-value="''"
                  disabled
                  readonly
                  tabindex="-1"
                  :placeholder="t('signInExperience.previewEmail')"
                  :aria-label="t('signInExperience.previewEmail')"
                />
                <Input
                  :model-value="''"
                  type="password"
                  disabled
                  readonly
                  tabindex="-1"
                  :placeholder="t('signInExperience.previewPassword')"
                  :aria-label="t('signInExperience.previewPassword')"
                />
                <Button variant="primary" size="sm" type="button" disabled class="w-full">
                  {{ t('signInExperience.previewSubmit') }}
                </Button>
              </div>

              <Button
                v-if="emailCode"
                variant="secondary"
                size="sm"
                type="button"
                disabled
                class="w-full"
                :class="password ? 'mt-2' : 'mt-3.5'"
              >
                {{ t('signInExperience.previewEmailCode') }}
              </Button>

              <Button
                v-if="passkey"
                variant="secondary"
                size="sm"
                type="button"
                disabled
                class="w-full"
                :class="password || emailCode ? 'mt-2' : 'mt-3.5'"
              >
                {{ t('signInExperience.previewPasskey') }}
              </Button>

              <p v-if="noFirstFactor" class="mt-3.5 text-[11.5px] leading-snug text-deny">
                {{ t('signInExperience.previewNoMethods') }}
              </p>

              <div v-if="socials.length > 0" class="mt-3.5 flex items-center gap-2.5">
                <span class="h-px flex-1 bg-rule" aria-hidden="true" />
                <span class="text-[10.5px] uppercase tracking-[0.04em] text-ink-faint">
                  {{ t('signInExperience.previewDivider') }}
                </span>
                <span class="h-px flex-1 bg-rule" aria-hidden="true" />
              </div>

              <div v-if="socials.length > 0" class="mt-2 flex flex-col gap-1.5">
                <Button
                  v-for="connector in socials"
                  :key="connector.connector_id"
                  variant="secondary"
                  size="sm"
                  type="button"
                  disabled
                  class="w-full justify-center"
                >
                  {{ connector.display_name }}
                </Button>
              </div>

              <p v-else-if="connectors.isPending.value" class="mt-3.5 text-[11.5px] leading-snug text-ink-faint">
                {{ t('common.loading') }}
              </p>
              <p v-else-if="connectors.error.value" class="mt-3.5 text-[11.5px] leading-snug text-deny">
                {{ t('signInExperience.previewSocialUnavailable') }}
              </p>
              <p v-else class="mt-3.5 text-[11.5px] leading-snug text-ink-faint">
                {{ t('signInExperience.previewNoSocial') }}
              </p>

              <p v-if="signUp" class="mt-3.5 text-center text-[11.5px] text-ink-muted">
                {{ t('signInExperience.previewSignUp') }}
              </p>
            </div>

            <div class="mt-2.5 flex flex-wrap items-center justify-between gap-2">
              <p class="max-w-[220px] text-[11px] leading-snug text-ink-faint">
                {{ t('signInExperience.previewFooter') }}
              </p>
              <RouterLink
                :to="{ name: 'connectors' }"
                class="text-[11.5px] text-brand-ink underline decoration-brand/40 underline-offset-4 hover:decoration-brand"
              >
                {{ t('signInExperience.manageConnectors') }}
              </RouterLink>
            </div>
          </CardContent>
        </Card>
      </div>
    </QueryBoundary>
  </div>
</template>
