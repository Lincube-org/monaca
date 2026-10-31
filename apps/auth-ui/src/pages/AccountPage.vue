<script setup lang="ts">
import { Alert, AlertDescription, AlertTitle, Badge, Button, Input, Label, Skeleton } from "@monaca/ui";
import { AlertCircle, KeyRound, Loader2, Mail, ShieldCheck, ShieldOff, User } from "lucide-vue-next";
import { computed, nextTick, onMounted, ref } from "vue";
import { useRoute } from "vue-router";

import {
  AccountError,
  beginPasskeyRegistration,
  beginTotp,
  changePassword,
  deletePasskey,
  disableBackupCodes,
  disableTotp,
  generateBackupCodes,
  getAccount,
  listPasskeys,
  listSessions,
  registerPasskey,
  renamePasskey,
  requestEmailChange,
  revokeOtherSessions,
  revokeSession,
  updateProfile,
  verifyEmailChange,
  verifyTotp,
  type AccountPasskey,
  type AccountProfile,
  type AccountSession,
  type TotpEnrollment,
} from "@/api/account";
import { PasskeyError, createPasskey, passkeysSupported } from "@/api/webauthn";
import { t } from "@/i18n";
import type { MessageKey } from "@/i18n";

/**
 * Account centre, reached at `/account/{tenant}`.
 *
 * This page is where a signed-in account manages itself: its display name, its password, the
 * browsers that are signed in, and the authenticator app. It is deliberately a separate route from
 * the sign-in page: everything here happens while already signed in, and the SSO cookie is the
 * only credential it needs.
 */
const route = useRoute();
const tenant = computed(() => String(route.params.tenant ?? ""));

const loading = ref(true);
const loadError = ref<AccountError | null>(null);
const account = ref<AccountProfile | null>(null);

const displayName = ref("");
const username = ref("");
const profileBusy = ref(false);
const profileError = ref<MessageKey | null>(null);
const profileSubmitError = ref<string | null>(null);
const profileNotice = ref<MessageKey | null>(null);

/**
 * Email change: the pending address and the code mailed to it. The account keeps its old email
 * until the code is confirmed, so `emailPending` is what switches the card to the confirm step.
 */
const newEmail = ref("");
const emailCode = ref("");
const emailPending = ref(false);
const emailBusy = ref<"send" | "verify" | null>(null);
const emailFieldError = ref<MessageKey | null>(null);
const emailSubmitError = ref<string | null>(null);
const emailNotice = ref<MessageKey | null>(null);

const currentPassword = ref("");
const newPassword = ref("");
const passwordBusy = ref(false);
const passwordFieldError = ref<MessageKey | null>(null);
const passwordSubmitError = ref<string | null>(null);
const passwordNotice = ref<MessageKey | null>(null);

const sessions = ref<AccountSession[] | null>(null);
const sessionsBusy = ref(false);
const sessionsError = ref<string | null>(null);
const sessionBusyId = ref<string | null>(null);
const revokingOthers = ref(false);
const sessionsNotice = ref<MessageKey | null>(null);

const enrollment = ref<TotpEnrollment | null>(null);
const code = ref("");
const fieldError = ref<MessageKey | null>(null);
const submitError = ref<string | null>(null);
const busy = ref<"begin" | "verify" | "disable" | null>(null);
const mfaNotice = ref<MessageKey | null>(null);

/** The plaintext sheet from the last generation; `null` once it has been dismissed or replaced. */
const backupCodes = ref<string[] | null>(null);
const backupBusy = ref<"generate" | "disable" | null>(null);
const backupNotice = ref<MessageKey | null>(null);
const backupError = ref<string | null>(null);

/** Passkeys, like the authenticator app: listed, added, renamed and removed from here. */
const passkeys = ref<AccountPasskey[] | null>(null);
const passkeysSupportedHere = ref(passkeysSupported());
const passkeyBusy = ref<"add" | "rename" | "delete" | null>(null);
const passkeyError = ref<string | null>(null);
const passkeyNotice = ref<MessageKey | null>(null);
const passkeyName = ref("");
/** The `pky_…` id being relabelled, if a row is in edit mode. */
const renaming = ref<string | null>(null);
const renameValue = ref("");
const renameBusyId = ref<string | null>(null);

const codeInput = ref<InstanceType<typeof Input> | null>(null);

const totpEnabled = computed(() => account.value?.mfa.totp === true);
const hasPassword = computed(() => account.value?.has_password === true);
const otherSessions = computed(() => sessions.value?.filter((row) => !row.current) ?? []);
const backupRemaining = computed(() => account.value?.mfa.backup_codes ?? 0);
const passkeyCount = computed(() => passkeys.value?.length ?? 0);
const passkeyLimitReached = computed(() => passkeyCount.value >= 10);

const loadErrorMessage = computed<MessageKey>(() =>
  loadError.value?.status === 401 ? "account.sessionRequired" : "account.loadFailed",
);

function messageOf(error: unknown): string {
  return error instanceof AccountError ? error.message : String(error);
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

async function loadSessions(): Promise<void> {
  sessionsBusy.value = true;
  try {
    sessions.value = (await listSessions(tenant.value)).items;
    sessionsError.value = null;
  } catch (error) {
    sessions.value = null;
    sessionsError.value = messageOf(error);
  } finally {
    sessionsBusy.value = false;
  }
}

async function loadPasskeys(): Promise<void> {
  try {
    passkeys.value = (await listPasskeys(tenant.value)).items;
    passkeyError.value = null;
  } catch (error) {
    passkeys.value = null;
    passkeyError.value = messageOf(error);
  }
}

async function load(): Promise<void> {
  loading.value = true;
  try {
    const profile = await getAccount(tenant.value);
    account.value = profile;
    displayName.value = profile.display_name;
    username.value = profile.username ?? "";
    loadError.value = null;
    await loadSessions();
    await loadPasskeys();
  } catch (error) {
    account.value = null;
    loadError.value = error instanceof AccountError ? error : new AccountError(0, String(error));
  } finally {
    loading.value = false;
  }
}

onMounted(load);

async function saveProfile(): Promise<void> {
  profileError.value = null;
  profileSubmitError.value = null;
  profileNotice.value = null;

  const name = displayName.value.trim();
  if (name === "") {
    profileError.value = "errors.displayNameRequired";
    return;
  }
  if ([...name].length > 80) {
    profileError.value = "errors.displayNameTooLong";
    return;
  }
  // An empty field means "leave the username unchanged"; a non-empty one must be a valid claim.
  const chosen = username.value.trim();
  if (chosen !== "" && !/^[A-Za-z0-9_-]{3,32}$/.test(chosen)) {
    profileError.value = "errors.usernameInvalid";
    return;
  }

  profileBusy.value = true;
  try {
    const profile = await updateProfile(tenant.value, {
      displayName: name,
      ...(chosen === "" ? {} : { username: chosen }),
    });
    account.value = profile;
    displayName.value = profile.display_name;
    username.value = profile.username ?? "";
    profileNotice.value = "account.profileSaved";
  } catch (error) {
    // 409 is the taken username; every other failure is shown as the server described it.
    profileSubmitError.value =
      error instanceof AccountError && error.status === 409
        ? t("account.usernameTaken")
        : messageOf(error);
  } finally {
    profileBusy.value = false;
  }
}

async function sendEmailCode(): Promise<void> {
  emailFieldError.value = null;
  emailSubmitError.value = null;
  emailNotice.value = null;

  const address = newEmail.value.trim();
  if (address === "") {
    emailFieldError.value = "errors.emailRequired";
    return;
  }
  // A plain shape check; the server validates the address again before mailing anything.
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
    emailFieldError.value = "errors.emailInvalid";
    return;
  }
  if (address.toLowerCase() === (account.value?.email ?? "").toLowerCase()) {
    emailSubmitError.value = t("account.emailSame");
    return;
  }

  emailBusy.value = "send";
  try {
    await requestEmailChange(tenant.value, address);
    emailPending.value = true;
    emailCode.value = "";
    emailNotice.value = "account.emailCodeSent";
  } catch (error) {
    // 409 is another account holding the address; everything else carries the server's detail.
    emailSubmitError.value =
      error instanceof AccountError && error.status === 409
        ? t("account.emailTaken")
        : messageOf(error);
  } finally {
    emailBusy.value = null;
  }
}

async function confirmEmail(): Promise<void> {
  emailFieldError.value = null;
  emailSubmitError.value = null;
  emailNotice.value = null;

  const address = newEmail.value.trim();
  if (!/^[0-9]{6}$/.test(emailCode.value.trim())) {
    emailFieldError.value = "errors.codeRequired";
    return;
  }

  emailBusy.value = "verify";
  try {
    const profile = await verifyEmailChange(tenant.value, address, emailCode.value.trim());
    account.value = profile;
    displayName.value = profile.display_name;
    username.value = profile.username ?? "";
    emailPending.value = false;
    newEmail.value = "";
    emailCode.value = "";
    emailNotice.value = "account.emailChanged";
  } catch (error) {
    emailSubmitError.value = messageOf(error);
    emailCode.value = "";
  } finally {
    emailBusy.value = null;
  }
}

/** Abandon the pending change and let the visitor type another address. */
function resetEmail(): void {
  emailPending.value = false;
  emailCode.value = "";
  emailFieldError.value = null;
  emailSubmitError.value = null;
  emailNotice.value = null;
  newEmail.value = "";
}

async function submitPassword(): Promise<void> {
  passwordFieldError.value = null;
  passwordSubmitError.value = null;
  passwordNotice.value = null;

  if (currentPassword.value === "") {
    passwordFieldError.value = "errors.currentPasswordRequired";
    return;
  }
  if (newPassword.value === "") {
    passwordFieldError.value = "errors.newPasswordRequired";
    return;
  }
  if ([...newPassword.value].length < 8) {
    passwordFieldError.value = "errors.weakPassword";
    return;
  }

  passwordBusy.value = true;
  try {
    await changePassword(tenant.value, currentPassword.value, newPassword.value);
    currentPassword.value = "";
    newPassword.value = "";
    passwordNotice.value = "account.passwordChanged";
    // Every other browser was signed out by the change; the list must show that.
    await loadSessions();
  } catch (error) {
    if (error instanceof AccountError && error.status === 401) {
      passwordSubmitError.value = t("errors.currentPasswordInvalid");
    } else {
      passwordSubmitError.value = messageOf(error);
    }
  } finally {
    passwordBusy.value = false;
  }
}

async function revokeOne(sessionId: string): Promise<void> {
  sessionsNotice.value = null;
  sessionBusyId.value = sessionId;
  try {
    await revokeSession(tenant.value, sessionId);
    await loadSessions();
    sessionsNotice.value = "account.sessionRevoked";
  } catch (error) {
    sessionsError.value = messageOf(error);
  } finally {
    sessionBusyId.value = null;
  }
}

async function revokeOthers(): Promise<void> {
  sessionsNotice.value = null;
  revokingOthers.value = true;
  try {
    await revokeOtherSessions(tenant.value);
    await loadSessions();
    sessionsNotice.value = "account.otherSessionsRevoked";
  } catch (error) {
    sessionsError.value = messageOf(error);
  } finally {
    revokingOthers.value = false;
  }
}

async function enable(): Promise<void> {
  fieldError.value = null;
  submitError.value = null;
  mfaNotice.value = null;
  busy.value = "begin";
  try {
    enrollment.value = await beginTotp(tenant.value);
    code.value = "";
    await nextTick();
    codeInput.value?.$el?.focus?.();
  } catch (error) {
    submitError.value = messageOf(error);
  } finally {
    busy.value = null;
  }
}

async function verify(): Promise<void> {
  fieldError.value = null;
  submitError.value = null;
  if (!/^[0-9]{6}$/.test(code.value.trim())) {
    fieldError.value = "errors.mfaCodeRequired";
    return;
  }
  busy.value = "verify";
  try {
    await verifyTotp(tenant.value, code.value.trim());
    enrollment.value = null;
    code.value = "";
    await load();
    mfaNotice.value = "account.enabled";
  } catch (error) {
    submitError.value = messageOf(error);
    code.value = "";
    await nextTick();
    codeInput.value?.$el?.focus?.();
  } finally {
    busy.value = null;
  }
}

async function disable(): Promise<void> {
  submitError.value = null;
  mfaNotice.value = null;
  busy.value = "disable";
  try {
    await disableTotp(tenant.value);
    // Removing the authenticator also removes the recovery codes it stood behind.
    backupCodes.value = null;
    backupNotice.value = null;
    await load();
    mfaNotice.value = "account.disabled";
  } catch (error) {
    submitError.value = messageOf(error);
  } finally {
    busy.value = null;
  }
}

async function generateBackup(): Promise<void> {
  backupBusy.value = "generate";
  backupError.value = null;
  backupNotice.value = null;
  try {
    const sheet = await generateBackupCodes(tenant.value);
    backupCodes.value = sheet.codes;
    if (account.value) {
      account.value = {
        ...account.value,
        mfa: { ...account.value.mfa, backup_codes: sheet.remaining },
      };
    }
    backupNotice.value = "account.backupGenerated";
  } catch (error) {
    backupError.value = messageOf(error);
  } finally {
    backupBusy.value = null;
  }
}

async function removeBackup(): Promise<void> {
  backupBusy.value = "disable";
  backupError.value = null;
  backupNotice.value = null;
  try {
    await disableBackupCodes(tenant.value);
    backupCodes.value = null;
    if (account.value) {
      account.value = {
        ...account.value,
        mfa: { ...account.value.mfa, backup_codes: 0 },
      };
    }
    backupNotice.value = "account.backupRemoved";
  } catch (error) {
    backupError.value = messageOf(error);
  } finally {
    backupBusy.value = null;
  }
}

function cancelEnrollment(): void {
  enrollment.value = null;
  code.value = "";
  fieldError.value = null;
  submitError.value = null;
}

/** Add a passkey: mint the options, run the browser ceremony, then store the verified result. */
async function addPasskey(): Promise<void> {
  passkeyError.value = null;
  passkeyNotice.value = null;
  passkeyBusy.value = "add";
  try {
    const options = await beginPasskeyRegistration(tenant.value);
    const credential = await createPasskey(options, passkeyName.value.trim() || undefined);
    const created = await registerPasskey(tenant.value, credential);
    passkeys.value = [created, ...(passkeys.value ?? [])];
    passkeyName.value = "";
    passkeyNotice.value = "account.passkeyCreated";
    if (account.value) {
      account.value = {
        ...account.value,
        mfa: { ...account.value.mfa, passkeys: passkeyCount.value },
      };
    }
  } catch (error) {
    if (error instanceof PasskeyError) {
      // A dismissed prompt is not a failure; only a real refusal gets an explanation.
      passkeyError.value = error.reason === "cancelled" ? null : t("errors.passkeyFailed");
    } else {
      passkeyError.value = messageOf(error);
    }
  } finally {
    passkeyBusy.value = null;
  }
}

function startRename(passkey: AccountPasskey): void {
  renaming.value = passkey.id;
  renameValue.value = passkey.name ?? "";
  passkeyError.value = null;
  passkeyNotice.value = null;
}

function cancelRename(): void {
  renaming.value = null;
  renameValue.value = "";
}

async function saveRename(passkey: AccountPasskey): Promise<void> {
  const name = renameValue.value.trim();
  if (name === "") {
    passkeyError.value = t("errors.passkeyNameRequired");
    return;
  }
  renameBusyId.value = passkey.id;
  passkeyError.value = null;
  passkeyNotice.value = null;
  try {
    const updated = await renamePasskey(tenant.value, passkey.id, name);
    passkeys.value = (passkeys.value ?? []).map((row) => (row.id === updated.id ? updated : row));
    renaming.value = null;
    renameValue.value = "";
    passkeyNotice.value = "account.passkeyRenamed";
  } catch (error) {
    passkeyError.value = messageOf(error);
  } finally {
    renameBusyId.value = null;
  }
}

async function removePasskey(passkey: AccountPasskey): Promise<void> {
  if (renaming.value === passkey.id) cancelRename();
  passkeyBusy.value = "delete";
  passkeyError.value = null;
  passkeyNotice.value = null;
  try {
    await deletePasskey(tenant.value, passkey.id);
    passkeys.value = (passkeys.value ?? []).filter((row) => row.id !== passkey.id);
    passkeyNotice.value = "account.passkeyDeleted";
    if (account.value) {
      account.value = {
        ...account.value,
        mfa: { ...account.value.mfa, passkeys: passkeyCount.value },
      };
    }
  } catch (error) {
    passkeyError.value = messageOf(error);
  } finally {
    passkeyBusy.value = null;
  }
}
</script>

<template>
  <div class="flex min-h-screen flex-col items-center justify-center bg-paper px-4 py-10">
    <div class="w-full max-w-[440px]">
      <div class="mb-5 flex items-center justify-center gap-2">
        <span
          class="grid size-7 place-items-center rounded-[6px] bg-brand text-[13px] font-semibold text-brand-on"
          aria-hidden="true"
        >
          m
        </span>
        <span class="text-[14px] font-semibold tracking-[-0.01em] text-ink">{{ t("brand.poweredBy") }}</span>
      </div>

      <div class="rounded-xl border border-rule bg-surface p-6 shadow-[var(--shadow-pop)]">
        <div v-if="loading" class="flex flex-col gap-3" aria-busy="true">
          <Skeleton class="h-6 w-40" />
          <Skeleton class="h-4 w-56" />
          <Skeleton class="mt-2 h-8 w-full" />
          <p class="text-center text-[12px] text-ink-faint">{{ t("loading.hint") }}</p>
        </div>

        <div v-else-if="loadError" class="flex flex-col gap-3">
          <Alert variant="error">
            <AlertCircle />
            <div class="min-w-0">
              <AlertTitle>{{ t("account.title") }}</AlertTitle>
              <AlertDescription>{{ t(loadErrorMessage) }}</AlertDescription>
            </div>
          </Alert>
          <Button type="button" variant="ghost" block @click="load">{{ t("account.refresh") }}</Button>
        </div>

        <div v-else-if="account" class="flex flex-col gap-4">
          <div class="flex flex-col gap-1">
            <h1 class="text-[17px] font-semibold leading-snug tracking-[-0.01em] text-ink">
              {{ t("account.title") }}
            </h1>
            <p class="text-[12.5px] leading-snug text-ink-muted">
              {{ t("account.signedInAs") }}
              <span class="mono-data text-ink">{{ account.email }}</span>
            </p>
          </div>

          <!-- Profile: the name applications display. -->
          <div class="flex flex-col gap-2 rounded-lg border border-rule bg-surface-muted px-3 py-3">
            <div class="flex items-center gap-1.5">
              <User class="size-3.5 text-ink-faint" aria-hidden="true" />
              <h2 class="text-[13px] font-semibold text-ink">{{ t("account.profileTitle") }}</h2>
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="account-display-name">{{ t("account.displayNameLabel") }}</Label>
              <Input
                id="account-display-name"
                v-model="displayName"
                type="text"
                name="display_name"
                autocomplete="name"
                maxlength="80"
                :placeholder="t('account.displayNamePlaceholder')"
                :invalid="profileError === 'errors.displayNameRequired' || profileError === 'errors.displayNameTooLong'"
              />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="account-username">{{ t("account.usernameLabel") }}</Label>
              <Input
                id="account-username"
                v-model="username"
                type="text"
                name="username"
                autocomplete="username"
                maxlength="32"
                spellcheck="false"
                autocapitalize="none"
                :placeholder="t('account.usernamePlaceholder')"
                :invalid="profileError === 'errors.usernameInvalid'"
              />
              <span class="text-[11.5px] text-ink-faint">{{ t("account.usernameHint") }}</span>
            </div>
            <p
              v-if="profileError || profileSubmitError"
              role="alert"
              class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
            >
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ profileError ? t(profileError) : profileSubmitError }}
            </p>
            <p v-else-if="profileNotice" role="status" class="text-[12.5px] leading-snug text-ink-muted">
              {{ t(profileNotice) }}
            </p>
            <Button type="button" variant="secondary" block :disabled="profileBusy" :aria-busy="profileBusy" @click="saveProfile">
              <Loader2 v-if="profileBusy" class="animate-spin" />
              <User v-else />
              {{ profileBusy ? t("account.savingProfile") : t("account.saveProfile") }}
            </Button>
          </div>

          <!-- Email: the address that signs in and receives codes, confirmed before it takes effect. -->
          <div class="flex flex-col gap-2 rounded-lg border border-rule bg-surface-muted px-3 py-3">
            <div class="flex items-center gap-1.5">
              <Mail class="size-3.5 text-ink-faint" aria-hidden="true" />
              <h2 class="text-[13px] font-semibold text-ink">{{ t("account.emailTitle") }}</h2>
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="account-new-email">{{ t("account.emailLabel") }}</Label>
              <Input
                id="account-new-email"
                v-model="newEmail"
                type="email"
                name="email"
                autocomplete="email"
                autocapitalize="none"
                spellcheck="false"
                :placeholder="t('account.emailPlaceholder')"
                :disabled="emailBusy !== null || emailPending"
                :invalid="emailFieldError === 'errors.emailRequired' || emailFieldError === 'errors.emailInvalid'"
              />
              <span class="text-[11.5px] text-ink-faint">{{ t("account.emailNote") }}</span>
            </div>
            <div v-if="emailPending" class="flex flex-col gap-1.5">
              <Label for="account-email-code">{{ t("account.emailCodeLabel") }}</Label>
              <Input
                id="account-email-code"
                v-model="emailCode"
                type="text"
                name="email_code"
                inputmode="numeric"
                autocomplete="one-time-code"
                maxlength="6"
                :placeholder="t('account.emailCodePlaceholder')"
                :invalid="emailFieldError === 'errors.codeRequired'"
              />
            </div>
            <p
              v-if="emailFieldError || emailSubmitError"
              role="alert"
              class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
            >
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ emailFieldError ? t(emailFieldError) : emailSubmitError }}
            </p>
            <p v-else-if="emailNotice" role="status" class="text-[12.5px] leading-snug text-ink-muted">
              {{ t(emailNotice) }}
            </p>
            <Button
              v-if="emailPending"
              type="button"
              variant="secondary"
              block
              :disabled="emailBusy !== null"
              :aria-busy="emailBusy === 'verify'"
              @click="confirmEmail"
            >
              <Loader2 v-if="emailBusy === 'verify'" class="animate-spin" />
              <Mail v-else />
              {{ emailBusy === "verify" ? t("account.emailVerifying") : t("account.emailVerify") }}
            </Button>
            <Button
              v-else
              type="button"
              variant="secondary"
              block
              :disabled="emailBusy !== null"
              :aria-busy="emailBusy === 'send'"
              @click="sendEmailCode"
            >
              <Loader2 v-if="emailBusy === 'send'" class="animate-spin" />
              <Mail v-else />
              {{ emailBusy === "send" ? t("account.emailSending") : t("account.emailSend") }}
            </Button>
            <Button
              v-if="emailPending"
              type="button"
              variant="ghost"
              block
              :disabled="emailBusy !== null"
              @click="resetEmail"
            >
              {{ t("account.emailDifferent") }}
            </Button>
          </div>

          <!-- Password: proving the current one means a stolen cookie cannot lock the owner out. -->
          <div v-if="hasPassword" class="flex flex-col gap-2 rounded-lg border border-rule bg-surface-muted px-3 py-3">
            <div class="flex items-center gap-1.5">
              <KeyRound class="size-3.5 text-ink-faint" aria-hidden="true" />
              <h2 class="text-[13px] font-semibold text-ink">{{ t("account.passwordTitle") }}</h2>
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="account-current-password">{{ t("account.currentPassword") }}</Label>
              <Input
                id="account-current-password"
                v-model="currentPassword"
                type="password"
                name="current_password"
                autocomplete="current-password"
              />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="account-new-password">{{ t("account.newPassword") }}</Label>
              <Input
                id="account-new-password"
                v-model="newPassword"
                type="password"
                name="new_password"
                autocomplete="new-password"
                :invalid="passwordFieldError === 'errors.newPasswordRequired' || passwordFieldError === 'errors.weakPassword'"
              />
              <span class="text-[11.5px] text-ink-faint">{{ t("account.passwordHint") }}</span>
            </div>
            <p
              v-if="passwordFieldError || passwordSubmitError"
              role="alert"
              class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
            >
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ passwordFieldError ? t(passwordFieldError) : passwordSubmitError }}
            </p>
            <p v-else-if="passwordNotice" role="status" class="text-[12.5px] leading-snug text-ink-muted">
              {{ t(passwordNotice) }}
            </p>
            <Button type="button" variant="secondary" block :disabled="passwordBusy" :aria-busy="passwordBusy" @click="submitPassword">
              <Loader2 v-if="passwordBusy" class="animate-spin" />
              <KeyRound v-else />
              {{ passwordBusy ? t("account.changingPassword") : t("account.changePassword") }}
            </Button>
          </div>
          <p v-else class="rounded-lg border border-rule bg-surface-muted px-3 py-3 text-[12.5px] leading-snug text-ink-muted">
            {{ t("account.noPassword") }}
          </p>

          <!-- Two-step verification. -->
          <div class="flex flex-col gap-2 rounded-lg border border-rule bg-surface-muted px-3 py-3">
            <div class="flex items-center justify-between gap-3">
              <h2 class="text-[13px] font-semibold text-ink">{{ t("account.mfaTitle") }}</h2>
              <Badge :variant="totpEnabled ? 'brand' : 'muted'">
                <ShieldCheck v-if="totpEnabled" class="size-3.5" aria-hidden="true" />
                <ShieldOff v-else class="size-3.5" aria-hidden="true" />
                {{ totpEnabled ? "TOTP" : "—" }}
              </Badge>
            </div>
            <p class="text-[12.5px] leading-snug text-ink-muted">
              {{ t(totpEnabled ? "account.mfaOn" : "account.mfaOff") }}
            </p>
          </div>

          <!-- Not enrolled and not mid-setup: offer the one action there is. -->
          <Button
            v-if="!totpEnabled && !enrollment"
            type="button"
            variant="primary"
            block
            :disabled="busy !== null"
            :aria-busy="busy === 'begin'"
            @click="enable"
          >
            <Loader2 v-if="busy === 'begin'" class="animate-spin" />
            <ShieldCheck v-else />
            {{ busy === "begin" ? t("account.enabling") : t("account.enable") }}
          </Button>

          <!-- Setup: the secret is shown once, the app must prove it before it is stored. -->
          <div v-else-if="enrollment" class="flex flex-col gap-3">
            <p class="text-[12.5px] leading-snug text-ink-muted">{{ t("account.scan") }}</p>
            <div class="flex flex-col gap-1">
              <span class="text-[11.5px] text-ink-faint">{{ t("account.secret") }}</span>
              <span class="mono-data select-all break-all rounded-md border border-rule bg-surface px-2 py-1.5 text-[12px] text-ink">
                {{ enrollment.secret }}
              </span>
              <a
                class="self-start text-[11.5px] font-medium text-brand-strong hover:underline"
                :href="enrollment.otpauth_url"
              >
                {{ enrollment.otpauth_url }}
              </a>
            </div>

            <div class="flex flex-col gap-1.5">
              <Label for="account-totp-code">{{ t("account.code") }}</Label>
              <Input
                id="account-totp-code"
                ref="codeInput"
                v-model="code"
                type="text"
                name="code"
                inputmode="numeric"
                autocomplete="one-time-code"
                maxlength="6"
                pattern="[0-9]{6}"
                spellcheck="false"
                :placeholder="t('mfa.codePlaceholder')"
                :invalid="fieldError === 'errors.mfaCodeRequired'"
              />
            </div>

            <p
              v-if="fieldError || submitError"
              role="alert"
              class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
            >
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ fieldError ? t(fieldError) : submitError }}
            </p>

            <div class="flex flex-col gap-2">
              <Button
                type="button"
                variant="primary"
                block
                :disabled="busy !== null"
                :aria-busy="busy === 'verify'"
                @click="verify"
              >
                <Loader2 v-if="busy === 'verify'" class="animate-spin" />
                <ShieldCheck v-else />
                {{ busy === "verify" ? t("account.verifying") : t("account.verify") }}
              </Button>
              <Button type="button" variant="ghost" block :disabled="busy !== null" @click="cancelEnrollment">
                {{ t("signIn.cancel") }}
              </Button>
            </div>
          </div>

          <!-- Enrolled: removal is the only change; re-enrolling starts from a fresh secret. -->
          <div v-else class="flex flex-col gap-2">
            <Button
              type="button"
              variant="ghost"
              block
              :disabled="busy !== null"
              :aria-busy="busy === 'disable'"
              @click="disable"
            >
              <Loader2 v-if="busy === 'disable'" class="animate-spin" />
              <ShieldOff v-else />
              {{ busy === "disable" ? t("account.disabling") : t("account.disable") }}
            </Button>
          </div>

          <p v-if="mfaNotice" class="text-[12.5px] leading-snug text-ink-muted" role="status">
            {{ t(mfaNotice) }}
          </p>

          <!-- Recovery codes: a way back in when the authenticator app is lost. -->
          <div
            v-if="totpEnabled"
            class="flex flex-col gap-2 rounded-lg border border-rule bg-surface-muted px-3 py-3"
          >
            <div class="flex items-center justify-between gap-3">
              <h2 class="text-[13px] font-semibold text-ink">{{ t("account.backupTitle") }}</h2>
              <Badge variant="muted">
                {{ t("account.backupRemaining", { remaining: backupRemaining }) }}
              </Badge>
            </div>
            <p class="text-[12.5px] leading-snug text-ink-muted">{{ t("account.backupNote") }}</p>

            <!-- The plaintext sheet exists only in the response to a generation. -->
            <div v-if="backupCodes" class="flex flex-col gap-1.5">
              <p class="text-[12.5px] leading-snug text-ink-muted">{{ t("account.backupShownOnce") }}</p>
              <div class="grid grid-cols-2 gap-x-3 gap-y-1 rounded-md border border-rule bg-surface px-3 py-2">
                <span
                  v-for="backupCode in backupCodes"
                  :key="backupCode"
                  class="mono-data select-all text-[12px] text-ink"
                >
                  {{ backupCode }}
                </span>
              </div>
            </div>

            <p
              v-if="backupError"
              role="alert"
              class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny"
            >
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ backupError }}
            </p>
            <p v-else-if="backupNotice" role="status" class="text-[12.5px] leading-snug text-ink-muted">
              {{ t(backupNotice) }}
            </p>

            <div class="flex flex-col gap-2">
              <Button
                type="button"
                variant="secondary"
                block
                :disabled="backupBusy !== null"
                :aria-busy="backupBusy === 'generate'"
                @click="generateBackup"
              >
                <Loader2 v-if="backupBusy === 'generate'" class="animate-spin" />
                <KeyRound v-else />
                {{ backupBusy === "generate" ? t("account.backupGenerating") : t("account.backupGenerate") }}
              </Button>
              <Button
                v-if="backupRemaining > 0"
                type="button"
                variant="ghost"
                block
                :disabled="backupBusy !== null"
                :aria-busy="backupBusy === 'disable'"
                @click="removeBackup"
              >
                <Loader2 v-if="backupBusy === 'disable'" class="animate-spin" />
                <ShieldOff v-else />
                {{ backupBusy === "disable" ? t("account.backupDisabling") : t("account.backupDisable") }}
              </Button>
            </div>
          </div>

          <!-- Passkeys: passwordless credentials the account can sign in with. -->
          <div class="flex flex-col gap-2 rounded-lg border border-rule bg-surface-muted px-3 py-3">
            <div class="flex items-center justify-between gap-3">
              <div class="flex items-center gap-1.5">
                <KeyRound class="size-3.5 text-ink-faint" aria-hidden="true" />
                <h2 class="text-[13px] font-semibold text-ink">{{ t("account.passkeysTitle") }}</h2>
              </div>
              <Badge variant="muted">{{ passkeyCount }}</Badge>
            </div>
            <p class="text-[12.5px] leading-snug text-ink-muted">{{ t("account.passkeysNote") }}</p>

            <p v-if="passkeys && passkeys.length === 0" class="text-[12.5px] leading-snug text-ink-muted">
              {{ t("account.passkeyEmpty") }}
            </p>

            <div v-else-if="passkeys" class="flex flex-col divide-y divide-rule">
              <div v-for="passkey in passkeys" :key="passkey.id" class="flex flex-col gap-1.5 py-2">
                <div v-if="renaming === passkey.id" class="flex items-end gap-2">
                  <div class="flex min-w-0 flex-1 flex-col gap-1">
                    <Label :for="`passkey-name-${passkey.id}`">{{ t("account.passkeyNameLabel") }}</Label>
                    <Input
                      :id="`passkey-name-${passkey.id}`"
                      v-model="renameValue"
                      type="text"
                      maxlength="80"
                      :placeholder="t('account.passkeyNamePlaceholder')"
                    />
                  </div>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    :disabled="renameBusyId !== null"
                    :aria-busy="renameBusyId === passkey.id"
                    @click="saveRename(passkey)"
                  >
                    <Loader2 v-if="renameBusyId === passkey.id" class="animate-spin" />
                    {{ t("account.passkeySaving") }}
                  </Button>
                  <Button type="button" variant="ghost" size="sm" :disabled="renameBusyId !== null" @click="cancelRename">
                    {{ t("signIn.cancel") }}
                  </Button>
                </div>
                <div v-else class="flex items-center justify-between gap-3">
                  <div class="min-w-0">
                    <p class="truncate text-[12.5px] text-ink">
                      {{ passkey.name ?? t("account.passkeyNoName") }}
                    </p>
                    <p class="text-[11.5px] leading-snug text-ink-faint">
                      {{
                        passkey.last_used_at
                          ? t("account.passkeyLastUsed", { when: formatDate(passkey.last_used_at) })
                          : t("account.passkeyNeverUsed")
                      }}
                    </p>
                  </div>
                  <div class="flex items-center gap-1">
                    <Button
                      type="button"
                      variant="ghost"
                      size="xs"
                      :disabled="passkeyBusy !== null"
                      @click="startRename(passkey)"
                    >
                      {{ t("account.passkeyRename") }}
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="xs"
                      :disabled="passkeyBusy !== null"
                      :aria-busy="passkeyBusy === 'delete'"
                      @click="removePasskey(passkey)"
                    >
                      <Loader2 v-if="passkeyBusy === 'delete'" class="animate-spin" />
                      {{ t("account.passkeyDelete") }}
                    </Button>
                  </div>
                </div>
              </div>
            </div>

            <p v-if="passkeyError" role="alert" class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny">
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ passkeyError }}
            </p>
            <p v-else-if="passkeyNotice" role="status" class="text-[12.5px] leading-snug text-ink-muted">
              {{ t(passkeyNotice) }}
            </p>

            <div v-if="passkeysSupportedHere" class="flex flex-col gap-1.5">
              <div class="flex flex-col gap-1.5">
                <Label for="account-passkey-name">{{ t("account.passkeyNameLabel") }}</Label>
                <Input
                  id="account-passkey-name"
                  v-model="passkeyName"
                  type="text"
                  maxlength="80"
                  :placeholder="t('account.passkeyNamePlaceholder')"
                  :disabled="passkeyBusy !== null || passkeyLimitReached"
                />
              </div>
              <Button
                type="button"
                variant="secondary"
                block
                :disabled="passkeyBusy !== null || passkeyLimitReached"
                :aria-busy="passkeyBusy === 'add'"
                @click="addPasskey"
              >
                <Loader2 v-if="passkeyBusy === 'add'" class="animate-spin" />
                <KeyRound v-else />
                {{ passkeyBusy === "add" ? t("account.passkeyAdding") : t("account.passkeyAdd") }}
              </Button>
              <p v-if="passkeyLimitReached" class="text-[11.5px] leading-snug text-ink-faint">
                {{ t("account.passkeyLimit") }}
              </p>
            </div>
            <p v-else class="text-[11.5px] leading-snug text-ink-faint">
              {{ t("errors.passkeyUnsupported") }}
            </p>
          </div>

          <!-- Sessions: every browser that can currently act as this account. -->
          <div class="flex flex-col gap-2 rounded-lg border border-rule bg-surface-muted px-3 py-3">
            <h2 class="text-[13px] font-semibold text-ink">{{ t("account.sessionsTitle") }}</h2>
            <p class="text-[12.5px] leading-snug text-ink-muted">{{ t("account.sessionsNote") }}</p>

            <div v-if="sessionsBusy" class="flex flex-col gap-2" aria-busy="true">
              <Skeleton class="h-8 w-full" />
              <Skeleton class="h-8 w-full" />
            </div>
            <p v-else-if="sessionsError" role="alert" class="flex items-start gap-1.5 text-[12.5px] leading-snug text-deny">
              <AlertCircle class="mt-px size-3.5 shrink-0" aria-hidden="true" />
              {{ sessionsError }}
            </p>
            <p v-else-if="sessions && sessions.length === 0" class="text-[12.5px] leading-snug text-ink-muted">
              {{ t("account.sessionsEmpty") }}
            </p>
            <div v-else-if="sessions" class="flex flex-col divide-y divide-rule">
              <div
                v-for="session in sessions"
                :key="session.id"
                class="flex items-center justify-between gap-3 py-2"
              >
                <div class="min-w-0">
                  <div class="flex items-center gap-1.5">
                    <span class="truncate text-[12.5px] text-ink">
                      {{ session.user_agent ?? session.client_id ?? session.id }}
                    </span>
                    <Badge v-if="session.current" variant="brand">{{ t("account.currentSession") }}</Badge>
                  </div>
                  <p class="text-[11.5px] leading-snug text-ink-faint">
                    {{ t("account.lastSeen") }} {{ formatDate(session.last_seen_at) }} ·
                    {{ t("account.sessionStarted") }} {{ formatDate(session.issued_at) }}
                  </p>
                </div>
                <Button
                  v-if="!session.current"
                  type="button"
                  variant="ghost"
                  size="xs"
                  :disabled="sessionBusyId !== null || revokingOthers"
                  :aria-busy="sessionBusyId === session.id"
                  @click="revokeOne(session.id)"
                >
                  <Loader2 v-if="sessionBusyId === session.id" class="animate-spin" />
                  {{ sessionBusyId === session.id ? t("account.revoking") : t("account.revoke") }}
                </Button>
              </div>
            </div>

            <Button
              type="button"
              variant="ghost"
              block
              :disabled="sessionsBusy || revokingOthers || otherSessions.length === 0"
              :aria-busy="revokingOthers"
              @click="revokeOthers"
            >
              <Loader2 v-if="revokingOthers" class="animate-spin" />
              {{ revokingOthers ? t("account.revokingOthers") : t("account.revokeOthers") }}
            </Button>
            <p v-if="sessionsNotice" role="status" class="text-[12.5px] leading-snug text-ink-muted">
              {{ t(sessionsNotice) }}
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
