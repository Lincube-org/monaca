<script setup lang="ts">
import { Alert, AlertDescription, AlertTitle, Badge, Button, Input, Label, ScopeBadge, Skeleton } from "@monaca/ui";
import { AlertCircle, ArrowLeft, Check, Eye, EyeOff, Loader2, LockKeyhole } from "lucide-vue-next";
import { computed, nextTick, onMounted, ref } from "vue";

import { InteractionError, getInteraction, submitSignIn, submitConsent, abortInteraction, navigateTo, type InteractionDetails } from "@/api/interaction";
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

const passwordInput = ref<InstanceType<typeof Input> | null>(null);
const emailInput = ref<InstanceType<typeof Input> | null>(null);

const brandName = computed(
  () => details.value?.client.name || details.value?.tenant || tenantFromUrl.value || t("brand.fallbackTenant"),
);
const organization = computed(() => details.value?.organization ?? null);
const scopes = computed(() => details.value?.scopes ?? []);

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

const submitErrorMessage = computed<MessageKey>(() => {
  const error = submitError.value;
  if (!error) return "errors.generic";
  switch (error.code) {
    case "MONACA_INVALID_CREDENTIALS":
      return "errors.invalidCredentials";
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
  } catch (error) {
    loadError.value = error instanceof Error ? error : new Error(String(error));
  } finally {
    loading.value = false;
    await nextTick();
    if (!loadError.value) emailInput.value?.$el?.focus?.();
  }
});

async function signIn(): Promise<void> {
  fieldError.value = null;
  submitError.value = null;

  if (email.value.trim().length === 0) {
    fieldError.value = "errors.emailRequired";
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
      email: email.value.trim(),
      password: password.value,
    });
    if ("consent_required" in result) {
      // Authenticated, but the code is withheld until the user approves the scopes.
      consentRequired.value = true;
      return;
    }
    navigateTo(result.redirect_to);
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
              {{ consentRequired ? t("consent.title") : t("signIn.title") }}
            </h1>
            <p class="mt-1 text-[12.5px] leading-snug text-ink-muted">
              {{
                details
                  ? t(consentRequired ? "consent.request" : "signIn.request", { client: details.client.name })
                  : t("signIn.requestFallback")
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

          <form v-else class="flex flex-col gap-4" @submit.prevent="signIn">
            <div class="flex flex-col gap-1.5">
              <Label for="signin-email">{{ t("signIn.email") }}</Label>
              <Input
                id="signin-email"
                ref="emailInput"
                v-model="email"
                type="email"
                name="email"
                autocomplete="username"
                inputmode="email"
                spellcheck="false"
                autocapitalize="none"
                :placeholder="t('signIn.emailPlaceholder')"
                :invalid="fieldError === 'errors.emailRequired'"
                :aria-describedby="fieldError ? 'signin-error' : undefined"
              />
            </div>

            <div class="flex flex-col gap-1.5">
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
                <LockKeyhole v-else />
                {{ submitting ? t("signIn.submitting") : t("signIn.submit") }}
              </Button>
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

            <p class="text-center text-[11.5px] leading-relaxed text-ink-faint">{{ t("signIn.footnote") }}</p>
          </form>
        </div>
      </div>

      <p class="mt-4 text-center text-[11.5px] text-ink-faint">
        {{ details?.client.client_id ? `${details.client.client_id} · ` : "" }}{{ t("brand.poweredBy") }}
      </p>
    </div>
  </div>
</template>
