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
  toast,
} from "@monaca/ui";
import { CircleAlert, Gauge, Plus, RefreshCw, Trash2 } from "lucide-vue-next";
import { computed, ref, watch } from "vue";

import { describeError } from "@/api/contract";
import type { RateLimitItem } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import { useRateLimits, useUpdateRateLimits } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Request gates — §6.2.
 *
 * The page shows three things the API returns in one document:
 * - the four built-in endpoint defaults and the per-IP layer (server settings);
 * - every configured tenant or client override, editable here;
 * - the live counters, so "is this layer rejecting right now?" has an answer in the UI instead
 *   of a `curl` against `/v1/rate-limits`.
 *
 * A save replaces the whole override list, which is the API's semantic; the page therefore
 * edits a local copy and sends every row it keeps, not a patch of one field.
 */
const ui = useUiStore();
const limits = useRateLimits();
const update = useUpdateRateLimits();

const rows = ref<RateLimitItem[]>([]);
const endpoint = ref("token");
const clientId = ref("");
const limitValue = ref("600");
const windowValue = ref("60");
const saving = ref(false);

watch(
  () => limits.data.value,
  (document) => {
    if (document === undefined) return;
    rows.value = document.items.map((item) => ({ ...item }));
  },
  { immediate: true },
);

const stats = computed(() => [
  `${t("rateLimits.statsDefaults")} ${limits.data.value?.defaults.length ?? 0}`,
  `${t("rateLimits.statsOverrides")} ${rows.value.length}`,
  `${t("rateLimits.statsIp")} ${
    limits.data.value === undefined
      ? "—"
      : `${limits.data.value.ip.limit}/${limits.data.value.ip.window_secs}s`
  }`,
]);

const status = computed(() => limits.data.value?.status ?? []);
const limited = computed(() => status.value.filter((item) => item.limited).length);
const labelFor = (client: string | null | undefined): string =>
  client === null || client === undefined ? t("rateLimits.tenantLayer") : client;

function addRow(): void {
  const client = clientId.value.trim();
  const item: RateLimitItem = {
    endpoint: endpoint.value,
    client_id: client === "" ? null : client,
    limit: Number(limitValue.value),
    window_secs: Number(windowValue.value),
  };
  const duplicate = rows.value.some(
    (row) => row.endpoint === item.endpoint && (row.client_id ?? null) === item.client_id,
  );
  if (duplicate) {
    toast({ title: t("rateLimits.duplicate"), variant: "error" });
    return;
  }
  rows.value = [...rows.value, item];
  clientId.value = "";
}

function removeRow(index: number): void {
  rows.value = rows.value.filter((_, position) => position !== index);
}

async function save(): Promise<void> {
  saving.value = true;
  try {
    const saved = await update.mutateAsync({ items: rows.value });
    rows.value = saved.items.map((item) => ({ ...item }));
    toast({ title: t("rateLimits.saved"), variant: "success" });
  } catch (error) {
    toast({
      title: t("rateLimits.saveFailed"),
      description: describeError(error).title,
      variant: "error",
    });
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('rateLimits.title')"
      :subtitle="t('rateLimits.subtitle', { tenant: ui.tenant })"
      :stats="stats"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="limits.refetch()">
          <RefreshCw :class="limits.isFetching.value ? 'animate-spin' : ''" />
          {{ t("common.refresh") }}
        </Button>
        <Button variant="primary" size="sm" :disabled="saving" @click="save">
          {{ saving ? t("rateLimits.saving") : t("rateLimits.save") }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="limits.isPending.value"
      :error="limits.error.value"
      :on-retry="() => limits.refetch()"
    >
      <div class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div class="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle class="flex items-center gap-2">
                <Gauge class="size-4" />
                {{ t("rateLimits.defaultsTitle") }}
              </CardTitle>
              <CardDescription>{{ t("rateLimits.defaultsHint") }}</CardDescription>
            </CardHeader>
            <CardContent>
              <div class="grid gap-3 sm:grid-cols-2">
                <div
                  v-for="item in limits.data.value?.defaults ?? []"
                  :key="item.endpoint"
                  class="flex items-center justify-between rounded-lg border border-border/60 px-3 py-2"
                >
                  <span class="font-mono text-sm">{{ item.endpoint }}</span>
                  <span class="text-sm text-muted-foreground">
                    {{ item.limit }} / {{ item.window_secs }}s
                  </span>
                </div>
              </div>
              <div class="mt-4 flex items-start justify-between gap-3 rounded-lg bg-muted/40 px-3 py-2">
                <div>
                  <div class="text-sm font-medium">{{ t("rateLimits.ipTitle") }}</div>
                  <div class="text-xs text-muted-foreground">{{ limits.data.value?.ip.scope }}</div>
                </div>
                <div class="text-sm text-muted-foreground">
                  {{ limits.data.value?.ip.limit }} / {{ limits.data.value?.ip.window_secs }}s
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{{ t("rateLimits.overridesTitle") }}</CardTitle>
              <CardDescription>{{ t("rateLimits.overridesHint") }}</CardDescription>
            </CardHeader>
            <CardContent class="flex flex-col gap-4">
              <div
                v-if="rows.length === 0"
                class="rounded-lg border border-dashed border-border px-3 py-6 text-center text-sm text-muted-foreground"
              >
                {{ t("rateLimits.noOverrides") }}
              </div>
              <div v-else class="flex flex-col divide-y divide-border/60">
                <div
                  v-for="(row, index) in rows"
                  :key="`${row.endpoint}-${row.client_id ?? 'tenant'}`"
                  class="flex items-center justify-between gap-3 py-2"
                >
                  <div class="flex min-w-0 flex-col">
                    <span class="font-mono text-sm">{{ row.endpoint }}</span>
                    <span class="truncate text-xs text-muted-foreground">
                      {{ labelFor(row.client_id) }}
                    </span>
                  </div>
                  <div class="flex items-center gap-3">
                    <span class="text-sm text-muted-foreground">
                      {{ row.limit }} / {{ row.window_secs }}s
                    </span>
                    <Button variant="ghost" size="sm" @click="removeRow(index)">
                      <Trash2 class="size-4" />
                    </Button>
                  </div>
                </div>
              </div>

              <div class="grid gap-3 rounded-lg border border-border/60 p-3 sm:grid-cols-2">
                <div class="flex flex-col gap-1">
                  <Label for="rate-endpoint">{{ t("rateLimits.endpoint") }}</Label>
                  <NativeSelect id="rate-endpoint" v-model="endpoint">
                    <option
                      v-for="item in limits.data.value?.defaults ?? []"
                      :key="item.endpoint"
                      :value="item.endpoint"
                    >
                      {{ item.endpoint }}
                    </option>
                  </NativeSelect>
                </div>
                <div class="flex flex-col gap-1">
                  <Label for="rate-client">{{ t("rateLimits.client") }}</Label>
                  <Input
                    id="rate-client"
                    v-model="clientId"
                    :placeholder="t('rateLimits.clientPlaceholder')"
                  />
                </div>
                <div class="flex flex-col gap-1">
                  <Label for="rate-limit">{{ t("rateLimits.limit") }}</Label>
                  <Input id="rate-limit" v-model="limitValue" type="number" min="1" />
                </div>
                <div class="flex flex-col gap-1">
                  <Label for="rate-window">{{ t("rateLimits.window") }}</Label>
                  <Input id="rate-window" v-model="windowValue" type="number" min="1" />
                </div>
                <div class="sm:col-span-2">
                  <Button variant="secondary" size="sm" @click="addRow">
                    <Plus class="size-4" />
                    {{ t("rateLimits.add") }}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle class="flex items-center gap-2">
              <CircleAlert v-if="limited > 0" class="size-4 text-destructive" />
              {{ t("rateLimits.statusTitle") }}
            </CardTitle>
            <CardDescription>{{ t("rateLimits.statusHint") }}</CardDescription>
          </CardHeader>
          <CardContent class="flex flex-col gap-3">
            <div
              v-if="status.length === 0"
              class="rounded-lg border border-dashed border-border px-3 py-6 text-center text-sm text-muted-foreground"
            >
              {{ t("rateLimits.noStatus") }}
            </div>
            <div v-for="item in status" :key="`${item.endpoint}-${item.client_id ?? 'tenant'}`" class="flex flex-col gap-1">
              <div class="flex items-center justify-between gap-2">
                <span class="font-mono text-sm">{{ item.endpoint }}</span>
                <Badge :variant="item.limited ? 'deny' : 'allow'">
                  {{ item.limited ? t("rateLimits.limited") : t("rateLimits.ok") }}
                </Badge>
              </div>
              <div class="text-xs text-muted-foreground">
                {{ labelFor(item.client_id) }} · {{ item.count }} / {{ item.limit }} ·
                <span v-if="item.limited">{{ t("rateLimits.retry", { seconds: item.retry_after }) }}</span>
                <span v-else>{{ t("rateLimits.windowStarted", { at: item.window_started_at }) }}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </QueryBoundary>
  </div>
</template>
