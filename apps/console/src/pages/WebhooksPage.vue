<script setup lang="ts">
import {
  Badge,
  Button,
  Checkbox,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
  WEBHOOK_EVENTS,
} from "@monaca/ui";
import { Copy, Plus, RefreshCw } from "lucide-vue-next";
import { computed, ref, watch } from "vue";

import { describeError } from "@/api/contract";
import type { Webhook } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import {
  useCreateWebhook,
  useDeleteWebhook,
  useRotateWebhookSecret,
  useUpdateWebhook,
  useWebhookDeliveries,
  useWebhooks,
} from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Webhooks — the tenant's outbound event subscriptions (§6.2).
 *
 * Delivery is the server's job: this page only configures where the events go and lets an
 * administrator verify the receiver by reading the signed-delivery log. The signing key is shown
 * once, on creation and on rotation, because a list that echoes it would turn any console session
 * into every receiver's key.
 */
const ui = useUiStore();

const webhooks = useWebhooks();
const createWebhook = useCreateWebhook();
const updateWebhook = useUpdateWebhook();
const rotateWebhookSecret = useRotateWebhookSecret();
const deleteWebhook = useDeleteWebhook();

const rows = computed(() => webhooks.data.value?.items ?? []);

// --- Create -------------------------------------------------------------------------------------

const createOpen = ref(false);
const endpoint = ref("");
const selected = ref<string[]>([]);
const formError = ref<string | null>(null);

const endpointLooksValid = computed(() => /^https?:\/\/[^\s]+$/.test(endpoint.value.trim()));
const selectedCount = computed(() => selected.value.length);

function openCreate(): void {
  endpoint.value = "";
  selected.value = [];
  formError.value = null;
  createOpen.value = true;
}

function toggleEvent(event: string, on: boolean | "indeterminate"): void {
  formError.value = null;
  selected.value =
    on === true
      ? [...selected.value, event]
      : selected.value.filter((candidate) => candidate !== event);
}

watch(endpoint, () => (formError.value = null));

async function submit(): Promise<void> {
  if (!endpointLooksValid.value) {
    formError.value = t("webhooks.invalidUrl");
    return;
  }
  if (selected.value.length === 0) {
    formError.value = t("webhooks.noEvents");
    return;
  }
  formError.value = null;

  try {
    const created = await createWebhook.mutateAsync({
      url: endpoint.value.trim(),
      events: selected.value,
    });
    createOpen.value = false;
    toast({
      title: t("webhooks.createdToast"),
      description: t("webhooks.createdDescription", { url: created.url }),
      variant: "success",
    });
    showSecret(created.url, created.secret);
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

// --- The one-time signing key --------------------------------------------------------------------

const secretOpen = ref(false);
const secretValue = ref("");
const secretEndpoint = ref("");

function showSecret(forUrl: string, secret: string): void {
  secretEndpoint.value = forUrl;
  secretValue.value = secret;
  secretOpen.value = true;
}

async function copySecret(): Promise<void> {
  try {
    await navigator.clipboard.writeText(secretValue.value);
    toast({ title: t("webhooks.secretCopied"), variant: "success" });
  } catch {
    // Clipboard permission is not required to complete the flow; the field stays selectable.
  }
}

// --- Pause / resume -----------------------------------------------------------------------------

async function toggleEnabled(row: Webhook): Promise<void> {
  try {
    await updateWebhook.mutateAsync({ webhookId: row.id, body: { enabled: !row.enabled } });
    toast({
      title: row.enabled ? t("webhooks.pausedToast") : t("webhooks.resumedToast"),
      description: t("webhooks.toggleDescription", { url: row.url }),
      variant: "success",
    });
  } catch (error) {
    toast({ title: describeError(error).title, variant: "error" });
  }
}

// --- Rotation ------------------------------------------------------------------------------------

const rotateOpen = ref(false);
const rotateTarget = ref<Webhook | null>(null);
const rotateError = ref<string | null>(null);

function openRotate(row: Webhook): void {
  rotateTarget.value = row;
  rotateError.value = null;
  rotateOpen.value = true;
}

async function confirmRotate(): Promise<void> {
  const target = rotateTarget.value;
  if (!target) return;
  rotateError.value = null;
  try {
    const rotated = await rotateWebhookSecret.mutateAsync({ webhookId: target.id });
    rotateOpen.value = false;
    toast({
      title: t("webhooks.rotatedToast"),
      description: t("webhooks.rotatedDescription", { url: target.url }),
      variant: "success",
    });
    showSecret(target.url, rotated.secret);
  } catch (error) {
    rotateError.value = describeError(error).title;
  }
}

// --- Deliveries ----------------------------------------------------------------------------------

const deliveriesOpen = ref(false);
const deliveriesTarget = ref<Webhook | null>(null);
const deliveriesId = computed(() => deliveriesTarget.value?.id ?? null);
const deliveries = useWebhookDeliveries(deliveriesId);
const deliveryRows = computed(() => deliveries.data.value?.items ?? []);

function openDeliveries(row: Webhook): void {
  deliveriesTarget.value = row;
  deliveriesOpen.value = true;
}

// --- Delete --------------------------------------------------------------------------------------

const deleteOpen = ref(false);
const deleteTarget = ref<Webhook | null>(null);
const deleteError = ref<string | null>(null);

function openDelete(row: Webhook): void {
  deleteTarget.value = row;
  deleteError.value = null;
  deleteOpen.value = true;
}

async function confirmDelete(): Promise<void> {
  const target = deleteTarget.value;
  if (!target) return;
  deleteError.value = null;
  try {
    await deleteWebhook.mutateAsync({ webhookId: target.id });
    deleteOpen.value = false;
    toast({
      title: t("webhooks.deletedToast"),
      description: t("webhooks.deletedDescription", { url: target.url }),
      variant: "success",
    });
  } catch (error) {
    deleteError.value = describeError(error).title;
  }
}

function formatStamp(at: string): string {
  const parsed = new Date(at);
  if (Number.isNaN(parsed.getTime())) return at;
  const date = parsed.toISOString().slice(0, 10);
  const time = parsed.toISOString().slice(11, 19);
  return `${date} ${time}`;
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('webhooks.title')"
      :subtitle="t('webhooks.subtitle', { tenant: ui.tenant })"
      :stats="[rows.length === 1 ? t('webhooks.countOne') : t('webhooks.count', { count: rows.length })]"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="webhooks.refetch()">
          <RefreshCw :class="webhooks.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openCreate">
          <Plus />
          {{ t('webhooks.create') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="webhooks.isPending.value"
      :error="webhooks.error.value"
      :empty="rows.length === 0"
      :empty-title="t('webhooks.empty')"
      :empty-hint="t('webhooks.emptyHint')"
      :on-retry="() => webhooks.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openCreate">
          <Plus />
          {{ t('webhooks.create') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('webhooks.endpoint') }}</TableHead>
            <TableHead>{{ t('webhooks.events') }}</TableHead>
            <TableHead>{{ t('webhooks.status') }}</TableHead>
            <TableHead>{{ t('webhooks.updated') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="row in rows" :key="row.id">
            <TableCell class="max-w-[280px]">
              <span class="mono-data block truncate text-[12px] text-ink">{{ row.url }}</span>
              <span class="mono-data mt-0.5 block truncate text-[10.5px] text-ink-faint">
                {{ row.id }}
              </span>
            </TableCell>
            <TableCell class="max-w-[260px]">
              <span class="flex flex-wrap gap-1">
                <Badge v-for="event in row.events.slice(0, 3)" :key="event" variant="muted">
                  {{ event }}
                </Badge>
                <Badge v-if="row.events.length > 3" variant="muted">
                  +{{ row.events.length - 3 }}
                </Badge>
              </span>
            </TableCell>
            <TableCell>
              <Badge :variant="row.enabled ? 'allow' : 'muted'">
                {{ row.enabled ? t('webhooks.active') : t('webhooks.paused') }}
              </Badge>
            </TableCell>
            <TableCell class="mono-data whitespace-nowrap text-[11.5px] text-ink-faint">
              {{ formatStamp(row.updated_at) }}
            </TableCell>
            <TableCell>
              <div class="flex justify-end gap-1.5">
                <Button variant="ghost" size="xs" @click="openDeliveries(row)">
                  {{ t('webhooks.deliveries') }}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  :disabled="updateWebhook.isPending.value"
                  @click="toggleEnabled(row)"
                >
                  {{ row.enabled ? t('webhooks.pause') : t('webhooks.resume') }}
                </Button>
                <Button variant="ghost" size="xs" @click="openRotate(row)">
                  {{ t('webhooks.rotate') }}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  class="text-ink-muted hover:text-deny"
                  @click="openDelete(row)"
                >
                  {{ t('webhooks.delete') }}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </QueryBoundary>

    <Dialog v-model:open="createOpen">
      <DialogContent class="max-w-[560px]">
        <DialogHeader>
          <DialogTitle>{{ t('webhooks.createTitle') }}</DialogTitle>
          <DialogDescription>{{ t('webhooks.createDescription') }}</DialogDescription>
        </DialogHeader>

        <form class="flex max-h-[65vh] flex-col gap-3.5 overflow-y-auto pr-0.5" @submit.prevent="submit">
          <div class="flex flex-col gap-1.5">
            <Label for="webhook-endpoint">{{ t('webhooks.urlField') }}</Label>
            <Input
              id="webhook-endpoint"
              v-model="endpoint"
              :invalid="endpoint.length > 0 && !endpointLooksValid"
              placeholder="https://receiver.example/hooks/monaca"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('webhooks.urlHint') }}</p>
          </div>

          <div class="flex flex-col gap-2">
            <div class="flex items-baseline justify-between gap-2">
              <Label>{{ t('webhooks.eventsField') }}</Label>
              <span class="text-[11px] text-ink-faint">
                {{ t('webhooks.selected', { count: selectedCount }) }}
              </span>
            </div>
            <div
              class="grid max-h-[240px] grid-cols-2 gap-x-4 gap-y-1.5 overflow-y-auto rounded-md border border-rule bg-surface-muted p-3"
            >
              <label
                v-for="event in WEBHOOK_EVENTS"
                :key="event"
                class="flex items-center gap-2 text-[11.5px] text-ink-muted"
              >
                <Checkbox
                  :model-value="selected.includes(event)"
                  @update:model-value="(value: boolean | 'indeterminate') => toggleEvent(event, value)"
                />
                <span class="mono-data truncate">{{ event }}</span>
              </label>
            </div>
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('webhooks.eventsHint') }}</p>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="createOpen = false">{{ t('common.cancel') }}</Button>
            <Button variant="primary" type="submit" :disabled="createWebhook.isPending.value">
              {{ createWebhook.isPending.value ? t('common.saving') : t('webhooks.create') }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="secretOpen">
      <DialogContent class="max-w-[540px]">
        <DialogHeader>
          <DialogTitle>{{ t('webhooks.secretTitle') }}</DialogTitle>
          <DialogDescription>{{ t('webhooks.secretDescription', { url: secretEndpoint }) }}</DialogDescription>
        </DialogHeader>

        <div class="flex flex-col gap-2">
          <div class="flex items-center gap-2">
            <Input
              :model-value="secretValue"
              readonly
              class="mono-data h-8 text-[12px]"
              @focus="($event.target as HTMLInputElement).select()"
            />
            <Button variant="secondary" size="sm" @click="copySecret">
              <Copy />
              {{ t('webhooks.copySecret') }}
            </Button>
          </div>
          <p class="text-[11.5px] leading-snug text-warn">{{ t('webhooks.secretWarning') }}</p>
          <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('webhooks.verifyHint') }}</p>
        </div>

        <DialogFooter>
          <Button variant="primary" type="button" @click="secretOpen = false">{{ t('common.close') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="rotateOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('webhooks.rotateTitle') }}</DialogTitle>
          <DialogDescription>{{ t('webhooks.rotateDescription') }}</DialogDescription>
        </DialogHeader>

        <p v-if="rotateError" class="text-[12.5px] text-deny">{{ rotateError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="rotateOpen = false">{{ t('common.cancel') }}</Button>
          <Button
            variant="primary"
            type="button"
            :disabled="rotateWebhookSecret.isPending.value"
            @click="confirmRotate"
          >
            {{ rotateWebhookSecret.isPending.value ? t('common.saving') : t('webhooks.rotate') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('webhooks.deleteTitle') }}</DialogTitle>
          <DialogDescription>{{ t('webhooks.deleteDescription', { url: deleteTarget?.url ?? '' }) }}</DialogDescription>
        </DialogHeader>

        <p v-if="deleteError" class="text-[12.5px] text-deny">{{ deleteError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="deleteWebhook.isPending.value" @click="confirmDelete">
            {{ deleteWebhook.isPending.value ? t('common.saving') : t('webhooks.delete') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deliveriesOpen">
      <DialogContent class="max-w-[640px]">
        <DialogHeader>
          <DialogTitle>{{ t('webhooks.deliveriesTitle') }}</DialogTitle>
          <DialogDescription>{{ t('webhooks.deliveriesDescription', { url: deliveriesTarget?.url ?? '' }) }}</DialogDescription>
        </DialogHeader>

        <QueryBoundary
          :loading="deliveries.isPending.value"
          :error="deliveries.error.value"
          :empty="deliveryRows.length === 0"
          :empty-title="t('webhooks.deliveriesEmpty')"
          :empty-hint="t('webhooks.deliveriesEmptyHint')"
          :on-retry="() => deliveries.refetch()"
        >
          <Table>
            <TableHeader>
              <TableRow class="hover:bg-transparent">
                <TableHead>{{ t('webhooks.event') }}</TableHead>
                <TableHead>{{ t('webhooks.result') }}</TableHead>
                <TableHead>{{ t('webhooks.statusCode') }}</TableHead>
                <TableHead>{{ t('webhooks.attempts') }}</TableHead>
                <TableHead>{{ t('webhooks.when') }}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="delivery in deliveryRows" :key="delivery.id">
                <TableCell class="mono-data text-[11.5px]">{{ delivery.event }}</TableCell>
                <TableCell>
                  <Badge :variant="delivery.success ? 'allow' : 'deny'">
                    {{ delivery.success ? t('webhooks.delivered') : t('webhooks.failed') }}
                  </Badge>
                </TableCell>
                <TableCell class="mono-data text-[11.5px] text-ink-muted">
                  {{ delivery.status_code ?? '—' }}
                </TableCell>
                <TableCell class="mono-data text-[11.5px] text-ink-muted">
                  {{ delivery.attempts }}
                </TableCell>
                <TableCell class="mono-data whitespace-nowrap text-[11px] text-ink-faint">
                  {{ formatStamp(delivery.created_at) }}
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
          <p
            v-if="!deliveryRows.every((delivery) => delivery.success)"
            class="text-[11.5px] leading-snug text-ink-faint"
          >
            {{ t('webhooks.failureHint') }}
          </p>
        </QueryBoundary>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="deliveries.refetch()">
            <RefreshCw />
            {{ t('common.refresh') }}
          </Button>
          <Button variant="primary" type="button" @click="deliveriesOpen = false">{{ t('common.close') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
