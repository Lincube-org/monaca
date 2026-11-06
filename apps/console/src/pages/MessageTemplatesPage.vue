<script setup lang="ts">
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
  NativeSelect,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
  toast,
} from "@monaca/ui";
import { RefreshCw } from "lucide-vue-next";
import { computed, ref, watch } from "vue";

import { describeError } from "@/api/contract";
import type { MessageTemplate } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import {
  useDeleteMessageTemplate,
  useMessageTemplates,
  useRestoreMessageTemplate,
  useSession,
  useUpdateMessageTemplate,
} from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Message templates — every purpose and locale with its effective email/SMS copy (§6.3/§6.5).
 *
 * The variables list is a contract: the save is disabled when the body names a placeholder the
 * purpose cannot render, because the recipient would otherwise read `{{cod}}` literally.
 */
const ui = useUiStore();
const session = useSession();
const canWrite = computed(() => {
  const tier = session.data.value?.management ?? "none";
  return tier === "write" || tier === "full";
});

const channel = ref<"all" | "email" | "sms">("all");
const templates = useMessageTemplates(
  computed(() => (channel.value === "all" ? undefined : channel.value)),
);
const update = useUpdateMessageTemplate();
const remove = useDeleteMessageTemplate();
const restore = useRestoreMessageTemplate();

const rows = computed(() => templates.data.value?.items ?? []);
const selectedKey = ref<string | null>(null);
const selected = computed(() => {
  if (selectedKey.value === null) return null;
  return rows.value.find((row) => `${row.purpose}|${row.locale}` === selectedKey.value) ?? null;
});

const subject = ref("");
const body = ref("");
const formError = ref<string | null>(null);
let baseline: MessageTemplate | null = null;

function adopt(template: MessageTemplate): void {
  baseline = template;
  subject.value = template.subject ?? "";
  body.value = template.body;
  formError.value = null;
}

watch(
  rows,
  (items) => {
    if (items.length === 0) return;
    const current = items.find((row) => `${row.purpose}|${row.locale}` === selectedKey.value);
    if (!current) {
      const first = items[0];
      if (!first) return;
      selectedKey.value = `${first.purpose}|${first.locale}`;
      adopt(first);
      return;
    }
    if (baseline === null || (subject.value === baseline.subject && body.value === baseline.body)) {
      adopt(current);
    }
  },
  { immediate: true },
);

const dirty = computed(() => {
  if (baseline === null) return false;
  return subject.value !== (baseline.subject ?? "") || body.value !== baseline.body;
});

function placeholders(text: string): string[] {
  const names: string[] = [];
  let rest = text;
  while (rest.includes("{{")) {
    const start = rest.indexOf("{{");
    const after = rest.slice(start + 2);
    const end = after.indexOf("}}");
    if (end < 0) return ["__unclosed__"];
    const name = after.slice(0, end).replaceAll(" ", "");
    if (!names.includes(name)) names.push(name);
    rest = after.slice(end + 2);
  }
  return names;
}

const unknown = computed(() => {
  if (selected.value === null) return [];
  const allowed = selected.value.variables;
  return [...placeholders(subject.value), ...placeholders(body.value)].filter(
    (name) => !allowed.includes(name),
  );
});

const canSave = computed(
  () => canWrite.value && selected.value !== null && dirty.value && unknown.value.length === 0,
);

async function save(): Promise<void> {
  const template = selected.value;
  if (template === null) return;
  try {
    const saved = await update.mutateAsync({
      purpose: template.purpose,
      locale: template.locale,
      body: { subject: subject.value, body: body.value },
    });
    adopt(saved);
    toast({
      title: t("messageTemplates.saved"),
      description: t("messageTemplates.savedDescription", {
        purpose: template.purpose,
        locale: template.locale,
      }),
      variant: "success",
    });
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

async function reset(): Promise<void> {
  const template = selected.value;
  if (template === null) return;
  try {
    await remove.mutateAsync({ purpose: template.purpose, locale: template.locale });
    await templates.refetch();
    toast({
      title: t("messageTemplates.reset"),
      description: t("messageTemplates.resetDescription", {
        purpose: template.purpose,
        locale: template.locale,
      }),
      variant: "success",
    });
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

async function restoreBuiltin(): Promise<void> {
  const template = selected.value;
  if (template === null) return;
  try {
    const restored = await restore.mutateAsync({
      purpose: template.purpose,
      locale: template.locale,
    });
    adopt(restored);
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('messageTemplates.title')"
      :subtitle="t('messageTemplates.subtitle', { tenant: ui.tenant })"
      :stats="[t('messageTemplates.count', { count: rows.length })]"
    >
      <template #actions>
        <NativeSelect v-model="channel" class="w-[9rem]">
          <option value="all">{{ t('messageTemplates.channel') }}: all</option>
          <option value="email">email</option>
          <option value="sms">sms</option>
        </NativeSelect>
        <Button variant="ghost" size="sm" @click="templates.refetch()">
          <RefreshCw :class="templates.isFetching.value ? 'animate-spin' : ''" />
          {{ t("common.refresh") }}
        </Button>
      </template>
    </PageHeader>

    <Card v-if="!canWrite">
      <CardContent class="pt-4 text-[13px] text-ink-muted">
        <Badge variant="muted">{{ t("tenant.readOnly") }}</Badge>
        <span class="ml-2">{{ t("tenant.readOnlyHint") }}</span>
      </CardContent>
    </Card>

    <QueryBoundary
      :loading="templates.isPending.value"
      :error="templates.error.value"
      :empty="rows.length === 0"
      empty-title="No message templates"
      :on-retry="() => templates.refetch()"
    >
      <div class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <Card>
          <CardHeader>
            <CardTitle>{{ t("messageTemplates.title") }}</CardTitle>
            <CardDescription>{{ t("messageTemplates.subtitle", { tenant: ui.tenant }) }}</CardDescription>
          </CardHeader>
          <CardContent class="p-0">
            <Table>
              <TableHeader>
                <TableRow class="hover:bg-transparent">
                  <TableHead>{{ t("messageTemplates.purpose") }}</TableHead>
                  <TableHead>{{ t("messageTemplates.locale") }}</TableHead>
                  <TableHead>{{ t("messageTemplates.state") }}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow
                  v-for="template in rows"
                  :key="`${template.purpose}|${template.locale}`"
                  class="cursor-pointer"
                  :class="selectedKey === `${template.purpose}|${template.locale}` ? 'bg-muted/50' : ''"
                  @click="((selectedKey = `${template.purpose}|${template.locale}`), adopt(template))"
                >
                  <TableCell class="text-[12.5px]">{{ template.purpose }}</TableCell>
                  <TableCell class="mono-data text-[11.5px]">{{ template.locale }}</TableCell>
                  <TableCell>
                    <Badge :variant="template.customized ? 'warn' : 'muted'">
                      {{
                        template.customized
                          ? t("messageTemplates.customized")
                          : t("messageTemplates.builtin")
                      }}
                    </Badge>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>
              {{
                selected
                  ? t("messageTemplates.editorTitle", {
                      purpose: selected.purpose,
                      locale: selected.locale,
                    })
                  : t("messageTemplates.title")
              }}
            </CardTitle>
            <CardDescription>{{ t("messageTemplates.editorHint") }}</CardDescription>
          </CardHeader>
          <CardContent v-if="selected" class="flex flex-col gap-3">
            <div class="flex flex-wrap gap-1.5">
              <Badge v-for="name in selected.variables" :key="name" variant="muted">
                {{ name }}
              </Badge>
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="message-subject">{{ t("messageTemplates.subject") }}</Label>
              <Input id="message-subject" v-model="subject" :disabled="!canWrite" />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="message-body">{{ t("messageTemplates.body") }}</Label>
              <Textarea id="message-body" v-model="body" rows="7" :disabled="!canWrite" />
            </div>
            <p v-if="unknown.length > 0" class="m-0 text-[12px] text-deny">
              {{ t("messageTemplates.invalidPlaceholder") }}: {{ unknown.join(", ") }}
            </p>
            <p v-if="formError" class="m-0 text-[12px] text-deny">{{ formError }}</p>
            <div class="flex items-center gap-2">
              <Button variant="secondary" size="sm" :disabled="!canWrite || !selected.customized" @click="reset">
                {{ t("messageTemplates.reset") }}
              </Button>
              <Button
                v-if="!selected.customized"
                variant="ghost"
                size="sm"
                :disabled="!canWrite"
                @click="restoreBuiltin"
              >
                {{ t("messageTemplates.builtin") }}
              </Button>
              <Button class="ml-auto" variant="primary" size="sm" :disabled="!canSave" @click="save">
                {{ t("messageTemplates.save") }}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </QueryBoundary>
  </div>
</template>
