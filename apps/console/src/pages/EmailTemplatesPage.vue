<script setup lang="ts">
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
  Separator,
  Textarea,
  toast,
} from "@monaca/ui";
import { CircleAlert, RefreshCw } from "lucide-vue-next";
import { computed, ref, watch } from "vue";

import { describeError } from "@/api/contract";
import type { EmailTemplate } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t, type MessageKey } from "@/i18n";
import { unknownPlaceholder } from "@/lib/placeholders";
import { useEmailTemplates, useResetEmailTemplate, useUpdateEmailTemplate } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Email templates — the tenant's mail copy per purpose (§6.3).
 *
 * The server sends either the tenant's row or its built-in default for every message it mails, so
 * this page edits words, not delivery. Two rules shape it:
 *
 * - **Placeholders are a contract, not decoration.** The list of names is shown next to the editor,
 *   and an unknown or unclosed one disables the save: mailed literally it would reach the recipient
 *   as `{{cod}}`, and the user would never get in.
 * - **Reset is a first-class action.** A customised purpose can always return to the built-in copy;
 *   the page says which state the selected purpose is in rather than leaving the reader to diff.
 */
const ui = useUiStore();

const templates = useEmailTemplates();
const update = useUpdateEmailTemplate();
const reset = useResetEmailTemplate();

const rows = computed(() => templates.data.value?.items ?? []);

const PURPOSE_LABELS: Record<string, MessageKey> = {
  sign_up: "emailTemplates.purposes.sign_up",
  sign_in: "emailTemplates.purposes.sign_in",
  password_reset: "emailTemplates.purposes.password_reset",
  email_change: "emailTemplates.purposes.email_change",
  delete_account: "emailTemplates.purposes.delete_account",
  sign_in_link: "emailTemplates.purposes.sign_in_link",
  email_changed: "emailTemplates.purposes.email_changed",
  password_changed: "emailTemplates.purposes.password_changed",
  account_deleted: "emailTemplates.purposes.account_deleted",
};

function labelFor(purpose: string): string {
  const key = PURPOSE_LABELS[purpose];
  return key ? t(key) : purpose;
}

const selectedPurpose = ref<string | null>(null);
const selected = computed(
  () => rows.value.find((row) => row.purpose === selectedPurpose.value) ?? null,
);

const subject = ref("");
const body = ref("");
/** The server state the form was last synchronised with; the save diffs against it. */
const baseline = ref<EmailTemplate | null>(null);
const formError = ref<string | null>(null);

function adopt(template: EmailTemplate): void {
  baseline.value = template;
  subject.value = template.subject;
  body.value = template.body;
  formError.value = null;
}

/**
 * A background refetch must not discard an edit in progress.
 *
 * Adopt the incoming row when the form still shows the previous server state, or when it already
 * matches the new one (the usual case right after a save or reset). Only a real unsaved edit stays.
 */
watch(
  rows,
  (items) => {
    if (items.length === 0) return;
    const current = items.find((row) => row.purpose === selectedPurpose.value);
    if (!current) {
      const first = items[0];
      if (!first) return;
      selectedPurpose.value = first.purpose;
      adopt(first);
      return;
    }
    const base = baseline.value;
    const matchesIncoming =
      subject.value.trim() === current.subject && body.value.trim() === current.body;
    const matchesBase =
      base !== null && current.subject === base.subject && current.body === base.body;
    if (matchesIncoming || !matchesBase) adopt(current);
  },
  { immediate: true },
);

const dirty = computed(() => {
  const base = baseline.value;
  if (!base) return false;
  return subject.value.trim() !== base.subject || body.value.trim() !== base.body;
});

const subjectLength = computed(() => [...subject.value.trim()].length);
const bodyLength = computed(() => [...body.value.trim()].length);
const invalidSubject = computed(() => subjectLength.value < 1 || subjectLength.value > 200);
const invalidBody = computed(() => bodyLength.value < 1 || bodyLength.value > 10_000);

const placeholderIssue = computed(() => {
  const template = selected.value;
  if (!template) return null;
  return (
    unknownPlaceholder(subject.value, template.variables) ??
    unknownPlaceholder(body.value, template.variables) ??
    null
  );
});

const allowedVariables = computed(() =>
  (selected.value?.variables ?? []).map((name) => `{{${name}}}`).join(", "),
);

/** A placeholder as copy spells it. Building the braces in script keeps a stray `}}` out of the template. */
function braced(name: string): string {
  return `{{${name}}}`;
}

const saveDisabled = computed(
  () =>
    !dirty.value ||
    invalidSubject.value ||
    invalidBody.value ||
    placeholderIssue.value !== null ||
    update.isPending.value,
);

const stats = computed(() => {
  const items = rows.value;
  return [
    t("emailTemplates.count", { count: items.length }),
    t("emailTemplates.customizedCount", {
      count: items.filter((template) => template.customized).length,
    }),
  ];
});

const updatedLabel = computed(() => {
  const value = selected.value;
  if (!value || !value.customized || value.updated_at === null) {
    return t("emailTemplates.defaultBadge");
  }
  return t("emailTemplates.updated", { date: formatStamp(value.updated_at) });
});

function select(purpose: string): void {
  const template = rows.value.find((row) => row.purpose === purpose);
  selectedPurpose.value = purpose;
  if (template) adopt(template);
}

/** Switching purpose is not a save, so returning to it shows the stored copy again. */
function discard(): void {
  const current = selected.value;
  if (current) adopt(current);
  formError.value = null;
}

async function save(): Promise<void> {
  const template = selected.value;
  if (!template) return;
  if (invalidSubject.value) {
    formError.value = t("emailTemplates.invalidSubject");
    return;
  }
  if (invalidBody.value) {
    formError.value = t("emailTemplates.invalidBody");
    return;
  }
  if (placeholderIssue.value !== null) {
    formError.value = t("emailTemplates.unknownPlaceholder", {
      name: `{{${placeholderIssue.value}}}`,
      allowed: allowedVariables.value,
    });
    return;
  }

  formError.value = null;
  try {
    const saved = await update.mutateAsync({
      purpose: template.purpose,
      body: { subject: subject.value.trim(), body: body.value.trim() },
    });
    adopt(saved);
    toast({
      title: t("emailTemplates.savedToast"),
      description: t("emailTemplates.savedDescription", { purpose: labelFor(saved.purpose) }),
      variant: "success",
    });
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

async function restore(): Promise<void> {
  const template = selected.value;
  if (!template) return;
  formError.value = null;
  try {
    await reset.mutateAsync(template.purpose);
    toast({
      title: t("emailTemplates.resetToast"),
      description: t("emailTemplates.resetDescription", { purpose: labelFor(template.purpose) }),
      variant: "success",
    });
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

function formatStamp(at: string): string {
  const parsed = new Date(at);
  return Number.isNaN(parsed.getTime())
    ? at
    : `${parsed.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('emailTemplates.title')"
      :subtitle="t('emailTemplates.subtitle', { tenant: ui.tenant })"
      :stats="stats"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="templates.refetch()">
          <RefreshCw :class="templates.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="templates.isPending.value"
      :error="templates.error.value"
      :on-retry="() => templates.refetch()"
    >
      <div class="grid items-start gap-5 lg:grid-cols-[280px_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>{{ t('emailTemplates.title') }}</CardTitle>
            <CardDescription>{{ t('emailTemplates.listHint') }}</CardDescription>
          </CardHeader>
          <CardContent class="flex flex-col gap-1">
            <button
              v-for="row in rows"
              :key="row.purpose"
              type="button"
              class="flex w-full items-center justify-between gap-2 rounded-md border px-2.5 py-2 text-left"
              :class="
                row.purpose === selected?.purpose
                  ? 'border-rule bg-paper'
                  : 'border-transparent hover:bg-paper'
              "
              :aria-pressed="row.purpose === selected?.purpose"
              @click="select(row.purpose)"
            >
              <span class="min-w-0">
                <span class="block truncate text-[12.5px] font-medium text-ink">
                  {{ labelFor(row.purpose) }}
                </span>
                <span class="mono-data block truncate text-[11px] text-ink-faint">
                  {{ row.purpose }}
                </span>
              </span>
              <Badge :variant="row.customized ? 'brand' : 'muted'" class="shrink-0">
                {{ row.customized ? t('emailTemplates.customizedBadge') : t('emailTemplates.defaultBadge') }}
              </Badge>
            </button>
          </CardContent>
        </Card>

        <Card v-if="selected">
          <CardHeader>
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0">
                <CardTitle>{{ labelFor(selected.purpose) }}</CardTitle>
                <CardDescription>{{ t('emailTemplates.editorHint') }}</CardDescription>
              </div>
              <Badge :variant="selected.customized ? 'brand' : 'muted'">
                {{ selected.customized ? t('emailTemplates.customizedBadge') : t('emailTemplates.defaultBadge') }}
              </Badge>
            </div>
          </CardHeader>
          <CardContent class="flex flex-col gap-4">
            <Alert v-if="formError" variant="error">
              <CircleAlert />
              <div class="min-w-0">
                <AlertTitle>{{ t('emailTemplates.saveFailed') }}</AlertTitle>
                <AlertDescription>{{ formError }}</AlertDescription>
              </div>
            </Alert>

            <div class="flex flex-col gap-1.5">
              <Label for="mail-template-subject">{{ t('emailTemplates.subject') }}</Label>
              <Input
                id="mail-template-subject"
                v-model="subject"
                :invalid="invalidSubject"
                :disabled="update.isPending.value"
                autocomplete="off"
                spellcheck="false"
              />
              <p v-if="invalidSubject" class="text-[11.5px] leading-snug text-deny">
                {{ t('emailTemplates.invalidSubject') }}
              </p>
            </div>

            <div class="flex flex-col gap-1.5">
              <Label for="mail-template-body">{{ t('emailTemplates.body') }}</Label>
              <Textarea
                id="mail-template-body"
                v-model="body"
                rows="9"
                :invalid="invalidBody"
                :disabled="update.isPending.value"
                spellcheck="false"
              />
              <p v-if="invalidBody" class="text-[11.5px] leading-snug text-deny">
                {{ t('emailTemplates.invalidBody') }}
              </p>
            </div>

            <div class="flex flex-col gap-1.5">
              <span class="text-[11.5px] font-medium text-ink-muted">
                {{ t('emailTemplates.variables') }}
              </span>
              <div class="flex flex-wrap items-center gap-1.5">
                <Badge
                  v-for="name in selected.variables"
                  :key="name"
                  variant="outline"
                  class="mono-data"
                >
                  {{ braced(name) }}
                </Badge>
              </div>
              <p class="text-[11.5px] leading-snug text-ink-faint">
                {{ t('emailTemplates.variablesHint') }}
              </p>
              <p v-if="placeholderIssue !== null" class="text-[11.5px] leading-snug text-deny">
                {{
                  t('emailTemplates.unknownPlaceholder', {
                    name: braced(placeholderIssue),
                    allowed: allowedVariables,
                  })
                }}
              </p>
            </div>

            <Separator />

            <div class="flex flex-wrap items-center justify-between gap-3">
              <p class="text-[11.5px] leading-snug text-ink-faint">{{ updatedLabel }}</p>
              <div class="flex flex-wrap items-center gap-2">
                <Button v-if="dirty" variant="secondary" size="sm" @click="discard">
                  {{ t('emailTemplates.discard') }}
                </Button>
                <Button
                  v-if="selected.customized"
                  variant="secondary"
                  size="sm"
                  :disabled="reset.isPending.value || update.isPending.value"
                  @click="restore"
                >
                  {{ reset.isPending.value ? t('emailTemplates.resetting') : t('emailTemplates.reset') }}
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  :disabled="saveDisabled"
                  @click="save"
                >
                  {{ update.isPending.value ? t('emailTemplates.saving') : t('emailTemplates.save') }}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </QueryBoundary>
  </div>
</template>
