<script setup lang="ts">
import { Alert, AlertDescription, AlertTitle, Badge, Button, Input, Label, Skeleton } from "@monaca/ui";
import { AlertCircle, Loader2, ShieldCheck, ShieldOff } from "lucide-vue-next";
import { computed, nextTick, onMounted, ref } from "vue";
import { useRoute } from "vue-router";

import {
  AccountError,
  beginTotp,
  disableTotp,
  getAccount,
  verifyTotp,
  type AccountProfile,
  type TotpEnrollment,
} from "@/api/account";
import { t } from "@/i18n";
import type { MessageKey } from "@/i18n";

/**
 * Account security, reached at `/account/{tenant}`.
 *
 * This page is where an account enrolls the second factor. It is deliberately a separate route
 * from the sign-in page: enrolling happens while already signed in, and the SSO cookie is the only
 * credential it needs. The secret is shown once, in base32, so it can be typed into an
 * authenticator app; nothing is persisted until the app proves it works.
 */
const route = useRoute();
const tenant = computed(() => String(route.params.tenant ?? ""));

const loading = ref(true);
const loadError = ref<AccountError | null>(null);
const account = ref<AccountProfile | null>(null);

const enrollment = ref<TotpEnrollment | null>(null);
const code = ref("");
const fieldError = ref<MessageKey | null>(null);
const submitError = ref<string | null>(null);
const busy = ref<"begin" | "verify" | "disable" | null>(null);
const notice = ref<MessageKey | null>(null);

const codeInput = ref<InstanceType<typeof Input> | null>(null);

const totpEnabled = computed(() => account.value?.mfa.totp === true);

const loadErrorMessage = computed<MessageKey>(() =>
  loadError.value?.status === 401 ? "account.sessionRequired" : "account.loadFailed",
);

const noticeText = computed(() => (notice.value ? t(notice.value) : ""));

async function load(): Promise<void> {
  loading.value = true;
  try {
    account.value = await getAccount(tenant.value);
    loadError.value = null;
  } catch (error) {
    account.value = null;
    loadError.value = error instanceof AccountError ? error : new AccountError(0, String(error));
  } finally {
    loading.value = false;
  }
}

onMounted(load);

async function enable(): Promise<void> {
  fieldError.value = null;
  submitError.value = null;
  notice.value = null;
  busy.value = "begin";
  try {
    enrollment.value = await beginTotp(tenant.value);
    code.value = "";
    await nextTick();
    codeInput.value?.$el?.focus?.();
  } catch (error) {
    submitError.value = error instanceof AccountError ? error.message : String(error);
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
    notice.value = "account.enabled";
  } catch (error) {
    submitError.value = error instanceof AccountError ? error.message : String(error);
    code.value = "";
    await nextTick();
    codeInput.value?.$el?.focus?.();
  } finally {
    busy.value = null;
  }
}

async function disable(): Promise<void> {
  submitError.value = null;
  notice.value = null;
  busy.value = "disable";
  try {
    await disableTotp(tenant.value);
    await load();
    notice.value = "account.disabled";
  } catch (error) {
    submitError.value = error instanceof AccountError ? error.message : String(error);
  } finally {
    busy.value = null;
  }
}

function cancelEnrollment(): void {
  enrollment.value = null;
  code.value = "";
  fieldError.value = null;
  submitError.value = null;
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

          <p v-if="notice" class="text-[12.5px] leading-snug text-ink-muted" role="status">
            {{ noticeText }}
          </p>
        </div>
      </div>
    </div>
  </div>
</template>
