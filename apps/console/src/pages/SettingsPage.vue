<script setup lang="ts">
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  Separator,
  toast,
} from "@monaca/ui";
import { Check, Copy, Monitor, Moon, Sun } from "lucide-vue-next";
import { computed, ref, watch } from "vue";

import { GATEWAY_URL, USE_MOCKS } from "@/api";
import { describeError } from "@/api/contract";
import PageHeader from "@/components/PageHeader.vue";
import { useTheme } from "@/composables/use-theme";
import { t } from "@/i18n";
import {
  useSession,
  useTenant,
  useUpdateTenant,
  useUpdateUsage,
  useUsage,
} from "@/queries";
import { useUiStore, type ThemeChoice } from "@/stores/ui";

/**
 * Settings.
 *
 * Read-mostly by design. Everything here that is a server policy — token lifetime, org membership,
 * the tenant — is shown as a fact rather than an editable field, because a console that renders a
 * disabled-looking control for something it cannot change is worse than one that states the value.
 *
 * The diagnostics block exists so a bug report can be one copy-paste: version, mode, origins, and
 * the ids that identify the session.
 */
const ui = useUiStore();
const session = useSession();
const tenantQuery = useTenant();
const usageQuery = useUsage();
const updateTenant = useUpdateTenant();
const updateUsage = useUpdateUsage();
const { resolved, apply } = useTheme(() => ui.theme);

const canWrite = computed(() => {
  const tier = session.data.value?.management ?? "none";
  return tier === "write" || tier === "full";
});
const tenant = computed(() => tenantQuery.data.value ?? null);
const usage = computed(() => usageQuery.data.value ?? null);
const quota = ref("");
watch(
  () => usage.value,
  (value) => {
    if (value) quota.value = value.users.quota === null ? "" : String(value.users.quota);
  },
  { immediate: true },
);

const archiveOpen = ref(false);
const actionError = ref<string | null>(null);

async function archiveTenant(): Promise<void> {
  actionError.value = null;
  try {
    const updated = await updateTenant.mutateAsync({ state: "archived" });
    archiveOpen.value = false;
    toast({
      title: t("tenant.archivedToast"),
      description: t("tenant.archivedDescription", { tenant: updated.slug }),
      variant: "success",
    });
  } catch (error) {
    actionError.value = describeError(error).title;
  }
}

async function reactivateTenant(): Promise<void> {
  actionError.value = null;
  try {
    const updated = await updateTenant.mutateAsync({ state: "active" });
    toast({
      title: t("tenant.reactivatedToast"),
      description: t("tenant.reactivatedDescription", { tenant: updated.slug }),
      variant: "success",
    });
  } catch (error) {
    actionError.value = describeError(error).title;
  }
}

async function saveQuota(): Promise<void> {
  const raw = quota.value.trim();
  const value = raw === "" ? null : Number(raw);
  if (value !== null && (!Number.isInteger(value) || value < 0 || value > 10_000_000)) {
    toast({ title: t("tenant.quotaFailed"), description: "0–10,000,000 or empty", variant: "error" });
    return;
  }
  try {
    await updateUsage.mutateAsync({ max_accounts: value });
    toast({ title: t("tenant.quotaSaved"), variant: "success" });
  } catch (error) {
    toast({ title: t("tenant.quotaFailed"), description: describeError(error).title, variant: "error" });
  }
}

function setTheme(choice: ThemeChoice): void {
  ui.setTheme(choice);
  apply();
}

const diagnostics = computed(() => ({
  mode: import.meta.env.MODE,
  mocks: USE_MOCKS,
  gateway: GATEWAY_URL,
  tenant: ui.tenant,
  org: ui.org,
  account_id: session.data.value?.account_id ?? null,
  theme: `${ui.theme} (${resolved.value})`,
  user_agent: navigator.userAgent,
}));

async function copyDiagnostics(): Promise<void> {
  await navigator.clipboard.writeText(JSON.stringify(diagnostics.value, null, 2));
  toast({ title: t("settings.diagnosticsCopied"), variant: "success" });
}

const themeOptions: { value: ThemeChoice; label: string; icon: typeof Sun }[] = [
  { value: "system", label: t("theme.system"), icon: Monitor },
  { value: "light", label: t("theme.light"), icon: Sun },
  { value: "dark", label: t("theme.dark"), icon: Moon },
];
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader :title="t('settings.title')" :subtitle="t('settings.subtitle')" />

    <Card>
      <CardHeader>
        <CardTitle>{{ t('settings.appearance') }}</CardTitle>
        <CardDescription>{{ t('settings.appearanceHint') }}</CardDescription>
      </CardHeader>
      <CardContent class="flex flex-col gap-2">
        <Label>{{ t('settings.theme') }}</Label>
        <div class="flex flex-wrap gap-1.5" role="group" :aria-label="t('settings.theme')">
          <Button
            v-for="option in themeOptions"
            :key="option.value"
            :variant="ui.theme === option.value ? 'secondary' : 'ghost'"
            size="sm"
            :aria-pressed="ui.theme === option.value"
            @click="setTheme(option.value)"
          >
            <component :is="option.icon" />
            {{ option.label }}
            <Check v-if="ui.theme === option.value" class="size-3 text-brand" />
          </Button>
        </div>
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle>{{ t('settings.identity') }}</CardTitle>
        <CardDescription>{{ t('session.signedInAs') }}</CardDescription>
      </CardHeader>
      <CardContent class="flex flex-col">
        <dl class="grid grid-cols-[minmax(9rem,auto)_1fr] items-baseline gap-x-4 gap-y-2.5 text-[13px]">
          <dt class="text-ink-faint">{{ t('settings.account') }}</dt>
          <dd class="m-0 truncate text-ink">{{ session.data.value?.email ?? t('common.unknown') }}</dd>

          <dt class="text-ink-faint">{{ t('settings.tenant') }}</dt>
          <dd class="m-0">
            <Badge variant="muted">{{ ui.tenant }}</Badge>
          </dd>

          <dt class="text-ink-faint">{{ t('settings.organization') }}</dt>
          <dd class="m-0 flex flex-wrap items-center gap-1.5">
            <Badge variant="brand">{{ ui.org }}</Badge>
            <span class="mono-data text-[11.5px] text-ink-faint">
              {{ session.data.value?.orgs.find((o) => o.slug === ui.org)?.role ?? "" }}
            </span>
          </dd>

          <dt class="text-ink-faint">{{ t('members.accountId') }}</dt>
          <dd class="mono-data m-0 break-all text-[11.5px] text-ink-muted">
            {{ session.data.value?.account_id ?? "—" }}
          </dd>

          <dt class="text-ink-faint">{{ t('settings.tokenTtl') }}</dt>
          <dd class="m-0 text-[12.5px] text-ink-muted">{{ t('settings.tokenTtlHint') }}</dd>
        </dl>
      </CardContent>
    </Card>

    <Card>
      <CardHeader class="flex-row items-center justify-between">
        <div>
          <CardTitle>{{ t('tenant.title') }}</CardTitle>
          <CardDescription>{{ t('tenant.subtitle', { tenant: ui.tenant }) }}</CardDescription>
        </div>
        <Badge v-if="!canWrite" variant="muted">{{ t('tenant.readOnly') }}</Badge>
      </CardHeader>
      <CardContent>
        <dl class="grid grid-cols-[minmax(8rem,auto)_1fr] items-baseline gap-x-4 gap-y-2.5 text-[13px]">
          <dt class="text-ink-faint">{{ t('tenant.state') }}</dt>
          <dd class="m-0">
            <Badge :variant="tenant?.state === 'active' ? 'allow' : 'deny'">
              {{
                tenant?.state === "active"
                  ? t("tenant.active")
                  : tenant?.state === "archived"
                    ? t("tenant.archived")
                    : t("tenant.suspended")
              }}
            </Badge>
          </dd>
          <dt class="text-ink-faint">{{ t('settings.tenant') }}</dt>
          <dd class="mono-data m-0">{{ tenant?.slug ?? ui.tenant }}</dd>
          <dt class="text-ink-faint">{{ t('tenant.issuer') }}</dt>
          <dd class="mono-data m-0 break-all text-[11.5px] text-ink-muted">
            {{ tenant?.issuer ?? "—" }}
          </dd>
        </dl>
        <p v-if="actionError" class="mt-3 text-[12.5px] text-deny">{{ actionError }}</p>
        <div class="mt-3 flex items-center gap-2">
          <Button
            v-if="tenant?.state === 'active'"
            variant="danger"
            size="sm"
            :disabled="!canWrite || updateTenant.isPending.value"
            @click="archiveOpen = true"
          >
            {{ t('tenant.archive') }}
          </Button>
          <Button
            v-else-if="tenant?.state === 'archived'"
            variant="primary"
            size="sm"
            :disabled="!canWrite || updateTenant.isPending.value"
            @click="reactivateTenant"
          >
            {{ t('tenant.reactivate') }}
          </Button>
          <span v-if="tenant?.state === 'suspended'" class="text-[12px] text-ink-faint">
            {{ t('tenant.suspended') }} — resume through the platform CLI.
          </span>
        </div>
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle>{{ t('tenant.usage') }}</CardTitle>
        <CardDescription>{{ t('tenant.enforcement') }}</CardDescription>
      </CardHeader>
      <CardContent>
        <dl class="grid grid-cols-[minmax(8rem,auto)_1fr] items-baseline gap-x-4 gap-y-2.5 text-[13px]">
          <dt class="text-ink-faint">{{ t('tenant.usersTotal') }}</dt>
          <dd class="m-0">{{ usage?.users.total ?? "—" }}</dd>
          <dt class="text-ink-faint">{{ t('tenant.quota') }}</dt>
          <dd class="m-0">
            {{ usage?.users.quota === null ? t('tenant.unlimited') : usage?.users.quota }}
          </dd>
          <dt class="text-ink-faint">{{ t('tenant.remaining') }}</dt>
          <dd class="m-0">
            {{ usage?.users.remaining === null ? t('tenant.unlimited') : usage?.users.remaining }}
          </dd>
          <dt class="text-ink-faint">{{ t('tenant.activeToday') }}</dt>
          <dd class="m-0">{{ usage?.daily.active_accounts ?? "—" }}</dd>
          <dt class="text-ink-faint">{{ t('tenant.loginsToday') }}</dt>
          <dd class="m-0">{{ usage?.daily.logins ?? "—" }}</dd>
        </dl>
        <div class="mt-4 flex flex-col gap-1.5">
          <Label for="quota">{{ t('tenant.quotaField') }}</Label>
          <p class="m-0 text-[11.5px] text-ink-faint">{{ t('tenant.quotaHint') }}</p>
          <div class="flex items-center gap-2">
            <Input
              id="quota"
              v-model="quota"
              type="number"
              min="0"
              max="10000000"
              :disabled="!canWrite || updateUsage.isPending.value"
            />
            <Button
              variant="primary"
              size="sm"
              :disabled="!canWrite || updateUsage.isPending.value"
              @click="saveQuota"
            >
              {{ t('tenant.saveQuota') }}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle>{{ t('settings.mockMode') }}</CardTitle>
        <CardDescription>{{ t('settings.mockModeHint') }}</CardDescription>
      </CardHeader>
      <CardContent class="flex items-center gap-2">
        <Badge :variant="USE_MOCKS ? 'warn' : 'allow'">
          VITE_USE_MOCKS={{ USE_MOCKS ? "true" : "false" }}
        </Badge>
      </CardContent>
    </Card>

    <Card>
      <CardHeader class="flex-row items-center justify-between">
        <div>
          <CardTitle>{{ t('settings.diagnostics') }}</CardTitle>
          <CardDescription>{{ t('settings.gateway') }}</CardDescription>
        </div>
        <Button variant="secondary" size="sm" @click="copyDiagnostics">
          <Copy />
          {{ t('settings.copyDiagnostics') }}
        </Button>
      </CardHeader>
      <CardContent>
        <Separator class="mb-3" />
        <dl class="mono-data grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1.5 text-[11.5px]">
          <template v-for="(value, key) in diagnostics" :key="key">
            <dt class="text-ink-faint">{{ key }}</dt>
            <dd class="m-0 break-all text-ink-muted">{{ value }}</dd>
          </template>
        </dl>
      </CardContent>
    </Card>

    <Dialog v-model:open="archiveOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('tenant.archiveTitle', { tenant: tenant?.slug ?? ui.tenant }) }}</DialogTitle>
          <DialogDescription>{{ t('tenant.archiveDescription') }}</DialogDescription>
        </DialogHeader>
        <p v-if="actionError" class="text-[12.5px] text-deny">{{ actionError }}</p>
        <DialogFooter>
          <Button variant="ghost" type="button" @click="archiveOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="updateTenant.isPending.value" @click="archiveTenant">
            {{ updateTenant.isPending.value ? t('common.saving') : t('tenant.archive') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
