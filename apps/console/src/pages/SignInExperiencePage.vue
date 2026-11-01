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
  toast,
} from "@monaca/ui";
import { CircleAlert, RefreshCw, TriangleAlert } from "lucide-vue-next";
import { computed, ref, watch } from "vue";
import { RouterLink } from "vue-router";

import { describeError } from "@/api/contract";
import type { SignInExperience, UpdateSignInExperienceRequest } from "@/api/types";
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
const mfaEnabled = ref(true);
const mfaPolicy = ref<"user_controlled" | "mandatory">("user_controlled");
const formError = ref<string | null>(null);

/** The last server values the form was synchronised with; the save diffs against it. */
const baseline = ref<SignInExperience | null>(null);

function sameSwitches(
  value: SignInExperience,
  a: boolean,
  b: boolean,
  c: boolean,
  mfa: boolean,
  policy: "user_controlled" | "mandatory",
): boolean {
  return (
    value.sign_up_enabled === a &&
    value.password_sign_in_enabled === b &&
    value.email_code_sign_in_enabled === c &&
    value.mfa_enabled === mfa &&
    value.mfa_policy === policy
  );
}

function adopt(value: SignInExperience): void {
  baseline.value = value;
  signUp.value = value.sign_up_enabled;
  password.value = value.password_sign_in_enabled;
  emailCode.value = value.email_code_sign_in_enabled;
  mfaEnabled.value = value.mfa_enabled;
  mfaPolicy.value = value.mfa_policy;
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
    const matchesNext = sameSwitches(next, signUp.value, password.value, emailCode.value, mfaEnabled.value, mfaPolicy.value);
    const matchesBase = base !== null && sameSwitches(base, signUp.value, password.value, emailCode.value, mfaEnabled.value, mfaPolicy.value);
    if (matchesNext || !matchesBase) adopt(next);
  },
  { immediate: true },
);

const dirty = computed(() => {
  const base = baseline.value;
  if (!base) return false;
  return !sameSwitches(base, signUp.value, password.value, emailCode.value, mfaEnabled.value, mfaPolicy.value);
});

const noFirstFactor = computed(() => !password.value && !emailCode.value);

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

function setSwitch(field: "signUp" | "password" | "emailCode", value: boolean | "indeterminate"): void {
  const next = value === true;
  if (field === "signUp") signUp.value = next;
  if (field === "password") password.value = next;
  if (field === "emailCode") emailCode.value = next;
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

  const body: UpdateSignInExperienceRequest = {};
  if (signUp.value !== base.sign_up_enabled) body.sign_up_enabled = signUp.value;
  if (password.value !== base.password_sign_in_enabled) body.password_sign_in_enabled = password.value;
  if (emailCode.value !== base.email_code_sign_in_enabled) body.email_code_sign_in_enabled = emailCode.value;
  if (mfaEnabled.value !== base.mfa_enabled) body.mfa_enabled = mfaEnabled.value;
  if (mfaPolicy.value !== base.mfa_policy) body.mfa_policy = mfaPolicy.value;
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

              <Alert v-if="noFirstFactor" variant="warn">
                <TriangleAlert />
                <AlertDescription>{{ t('signInExperience.invalidMethods') }}</AlertDescription>
              </Alert>
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
