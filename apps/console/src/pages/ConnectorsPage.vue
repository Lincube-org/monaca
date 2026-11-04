<script setup lang="ts">
import {
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
  NativeSelect,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from "@monaca/ui";
import { Plus, RefreshCw } from "lucide-vue-next";
import { computed, ref, watch } from "vue";

import { describeError } from "@/api/contract";
import type { Connector } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import {
  useConnectors,
  useCreateConnector,
  useDeleteConnector,
  useUpdateConnector,
} from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Connectors — the social providers the sign-in page offers (§6.2).
 *
 * Registration is the only edit: the server exposes create, list and delete, and the secret is
 * sealed at rest, so a page cannot show it or change it. Deleting is destructive in a way the
 * confirmation states: every identity linked through the connector goes with it.
 */
const ui = useUiStore();

const connectors = useConnectors();
const createConnector = useCreateConnector();
const updateConnector = useUpdateConnector();
const deleteConnector = useDeleteConnector();

const rows = computed(() => connectors.data.value?.items ?? []);

// --- Register -----------------------------------------------------------------------------------

const createOpen = ref(false);
const connectorId = ref("");
const provider = ref<"generic" | "github" | "google">("github");
const linkPolicy = ref<"auto_link_verified_email" | "confirm_link" | "create_new_only">(
  "confirm_link",
);
const displayName = ref("");
const authorizeUrl = ref("");
const tokenUrl = ref("");
const userinfoUrl = ref("");
const clientId = ref("");
const clientSecret = ref("");
const scopesText = ref("");
const formError = ref<string | null>(null);

/** The endpoints and scopes the server owns for a built-in provider. */
const PROVIDER_PRESETS = {
  github: {
    authorize_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    userinfo_url: "https://api.github.com/user",
    scopes: "read:user user:email",
  },
  google: {
    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
    scopes: "openid email profile",
  },
} as const;

const builtIn = computed(() => provider.value !== "generic");

function applyPreset(): void {
  if (provider.value === "generic") return;
  const preset = PROVIDER_PRESETS[provider.value];
  authorizeUrl.value = preset.authorize_url;
  tokenUrl.value = preset.token_url;
  userinfoUrl.value = preset.userinfo_url;
  scopesText.value = preset.scopes;
}

watch(provider, applyPreset);

const connectorIdLooksValid = computed(() => /^[a-z0-9][a-z0-9-]{1,31}$/.test(connectorId.value.trim().toLowerCase()));

const urlsLookValid = computed(
  () =>
    builtIn.value ||
    [authorizeUrl.value, tokenUrl.value, userinfoUrl.value].every((url) =>
      /^https?:\/\/[^\s]+$/.test(url.trim()),
    ),
);

const scopesLookValid = computed(() =>
  splitScopes(scopesText.value).every((scope) => !/\s/.test(scope)),
);

function splitScopes(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);
}

watch(
  [
    connectorId,
    provider,
    linkPolicy,
    displayName,
    authorizeUrl,
    tokenUrl,
    userinfoUrl,
    clientId,
    clientSecret,
    scopesText,
  ],
  () => (formError.value = null),
);

function openCreate(): void {
  connectorId.value = "";
  provider.value = "github";
  linkPolicy.value = "confirm_link";
  displayName.value = "";
  authorizeUrl.value = "";
  tokenUrl.value = "";
  userinfoUrl.value = "";
  clientId.value = "";
  clientSecret.value = "";
  scopesText.value = "";
  formError.value = null;
  applyPreset();
  createOpen.value = true;
}

async function submit(): Promise<void> {
  if (!connectorIdLooksValid.value) {
    formError.value = t("connectors.invalidConnectorId");
    return;
  }
  if (displayName.value.trim().length === 0) {
    formError.value = t("connectors.invalidDisplayName");
    return;
  }
  if (!urlsLookValid.value) {
    formError.value = t("connectors.invalidUrls");
    return;
  }
  if (clientId.value.trim().length === 0 || clientSecret.value.length === 0) {
    formError.value = t("connectors.invalidCredentials");
    return;
  }
  if (!scopesLookValid.value) {
    formError.value = t("connectors.invalidScopes");
    return;
  }
  formError.value = null;

  try {
    const created = await createConnector.mutateAsync({
      connector_id: connectorId.value.trim().toLowerCase(),
      provider: provider.value,
      display_name: displayName.value.trim(),
      link_policy: linkPolicy.value,
      enabled: true,
      authorize_url: authorizeUrl.value.trim(),
      token_url: tokenUrl.value.trim(),
      userinfo_url: userinfoUrl.value.trim(),
      client_id: clientId.value.trim(),
      client_secret: clientSecret.value,
      scopes: splitScopes(scopesText.value),
    });
    toast({
      title: t("connectors.createdToast"),
      description: t("connectors.createdDescription", { connectorId: created.connector_id }),
      variant: "success",
    });
    createOpen.value = false;
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

// --- Delete -------------------------------------------------------------------------------------

const deleteOpen = ref(false);
const deleteTarget = ref<Connector | null>(null);
const deleteError = ref<string | null>(null);

function openDelete(connector: Connector): void {
  deleteTarget.value = connector;
  deleteError.value = null;
  deleteOpen.value = true;
}

async function confirmDelete(): Promise<void> {
  const target = deleteTarget.value;
  if (!target) return;
  deleteError.value = null;
  try {
    await deleteConnector.mutateAsync({ connectorId: target.connector_id });
    deleteOpen.value = false;
    toast({
      title: t("connectors.deletedToast"),
      description: t("connectors.deletedDescription", { connectorId: target.connector_id }),
      variant: "success",
    });
  } catch (error) {
    deleteError.value = describeError(error).title;
  }
}

async function setPolicy(connector: Connector, value: string): Promise<void> {
  const policy = value as Connector["link_policy"];
  try {
    await updateConnector.mutateAsync({
      connectorId: connector.connector_id,
      body: { link_policy: policy },
    });
  } catch (error) {
    toast({
      title: t("connectors.updateFailed"),
      description: describeError(error).title,
      variant: "error",
    });
  }
}

async function setEnabled(connector: Connector, value: boolean | "indeterminate"): Promise<void> {
  try {
    await updateConnector.mutateAsync({
      connectorId: connector.connector_id,
      body: { enabled: value === true },
    });
  } catch (error) {
    toast({
      title: t("connectors.updateFailed"),
      description: describeError(error).title,
      variant: "error",
    });
  }
}

function formatDate(at: string): string {
  const parsed = new Date(at);
  return Number.isNaN(parsed.getTime()) ? at : parsed.toISOString().slice(0, 10);
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('connectors.title')"
      :subtitle="t('connectors.subtitle', { tenant: ui.tenant })"
      :stats="[t('connectors.count', { count: rows.length })]"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="connectors.refetch()">
          <RefreshCw :class="connectors.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openCreate">
          <Plus />
          {{ t('connectors.create') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="connectors.isPending.value"
      :error="connectors.error.value"
      :empty="rows.length === 0"
      :empty-title="t('connectors.empty')"
      :empty-hint="t('connectors.emptyHint')"
      :on-retry="() => connectors.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openCreate">
          <Plus />
          {{ t('connectors.create') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('connectors.name') }}</TableHead>
            <TableHead>{{ t('connectors.providerField') }}</TableHead>
            <TableHead>{{ t('connectors.linkPolicyField') }}</TableHead>
            <TableHead>{{ t('connectors.enabledField') }}</TableHead>
            <TableHead>{{ t('connectors.created') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="connector in rows" :key="connector.connector_id">
            <TableCell class="max-w-[220px]">
              <span class="block truncate font-medium text-ink">{{ connector.display_name }}</span>
              <span class="mono-data mt-0.5 block truncate text-[11px] text-ink-faint">
                {{ connector.connector_id }}
              </span>
            </TableCell>
            <TableCell class="text-[11.5px] text-ink-muted">
              {{ t(`connectors.provider_${connector.provider}`) }}
            </TableCell>
            <TableCell>
              <NativeSelect
                :model-value="connector.link_policy"
                :disabled="updateConnector.isPending.value"
                @update:model-value="(value: string) => setPolicy(connector, value)"
              >
                <option value="auto_link_verified_email">{{ t('connectors.linkPolicyAuto') }}</option>
                <option value="confirm_link">{{ t('connectors.linkPolicyConfirm') }}</option>
                <option value="create_new_only">{{ t('connectors.linkPolicyCreate') }}</option>
              </NativeSelect>
            </TableCell>
            <TableCell>
              <Checkbox
                :model-value="connector.enabled"
                :disabled="updateConnector.isPending.value"
                :aria-label="t('connectors.enabledField')"
                @update:model-value="(value: boolean | 'indeterminate') => setEnabled(connector, value)"
              />
            </TableCell>
            <TableCell class="mono-data whitespace-nowrap text-[11.5px] text-ink-faint">
              {{ formatDate(connector.created_at) }}
            </TableCell>
            <TableCell>
              <div class="flex justify-end">
                <Button
                  variant="secondary"
                  size="xs"
                  class="text-ink-muted hover:text-deny"
                  :disabled="deleteConnector.isPending.value"
                  @click="openDelete(connector)"
                >
                  {{ t('connectors.delete') }}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </QueryBoundary>

    <Dialog v-model:open="createOpen">
      <DialogContent class="max-w-[540px]">
        <DialogHeader>
          <DialogTitle>{{ t('connectors.createTitle') }}</DialogTitle>
          <DialogDescription>{{ t('connectors.createDescription') }}</DialogDescription>
        </DialogHeader>

        <form class="flex max-h-[65vh] flex-col gap-3.5 overflow-y-auto pr-0.5" @submit.prevent="submit">
          <div class="grid grid-cols-[160px_1fr] gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="connector-id">{{ t('connectors.connectorIdField') }}</Label>
              <Input
                id="connector-id"
                v-model="connectorId"
                :invalid="connectorId.length > 0 && !connectorIdLooksValid"
                placeholder="github"
                autocomplete="off"
                spellcheck="false"
              />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="connector-name">{{ t('connectors.displayNameField') }}</Label>
              <Input
                id="connector-name"
                v-model="displayName"
                placeholder="GitHub"
                autocomplete="off"
                spellcheck="false"
              />
            </div>
          </div>
          <p class="-mt-1.5 text-[11.5px] leading-snug text-ink-faint">
            {{ connectorId.length > 0 && !connectorIdLooksValid ? t('connectors.invalidConnectorId') : t('connectors.connectorIdHint') }}
          </p>

          <div class="grid grid-cols-2 gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="connector-provider">{{ t('connectors.providerField') }}</Label>
              <NativeSelect id="connector-provider" v-model="provider">
                <option value="github">{{ t('connectors.provider_github') }}</option>
                <option value="google">{{ t('connectors.provider_google') }}</option>
                <option value="generic">{{ t('connectors.provider_generic') }}</option>
              </NativeSelect>
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="connector-policy">{{ t('connectors.linkPolicyField') }}</Label>
              <NativeSelect id="connector-policy" v-model="linkPolicy">
                <option value="auto_link_verified_email">{{ t('connectors.linkPolicyAuto') }}</option>
                <option value="confirm_link">{{ t('connectors.linkPolicyConfirm') }}</option>
                <option value="create_new_only">{{ t('connectors.linkPolicyCreate') }}</option>
              </NativeSelect>
            </div>
          </div>
          <p class="-mt-1.5 text-[11.5px] leading-snug text-ink-faint">
            {{ t('connectors.linkPolicyHint') }}
          </p>

          <p v-if="builtIn" class="text-[11.5px] leading-snug text-ink-faint">
            {{ t('connectors.providerPresetHint') }}
          </p>

          <div v-if="!builtIn" class="flex flex-col gap-1.5">
            <Label for="connector-authorize">{{ t('connectors.authorizeUrlField') }}</Label>
            <Input
              id="connector-authorize"
              v-model="authorizeUrl"
              :invalid="authorizeUrl.length > 0 && !urlsLookValid"
              placeholder="https://github.com/login/oauth/authorize"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('connectors.authorizeUrlHint') }}</p>
          </div>

          <div v-if="!builtIn" class="flex flex-col gap-1.5">
            <Label for="connector-token">{{ t('connectors.tokenUrlField') }}</Label>
            <Input
              id="connector-token"
              v-model="tokenUrl"
              :invalid="tokenUrl.length > 0 && !urlsLookValid"
              placeholder="https://github.com/login/oauth/access_token"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('connectors.tokenUrlHint') }}</p>
          </div>

          <div v-if="!builtIn" class="flex flex-col gap-1.5">
            <Label for="connector-userinfo">{{ t('connectors.userinfoUrlField') }}</Label>
            <Input
              id="connector-userinfo"
              v-model="userinfoUrl"
              :invalid="userinfoUrl.length > 0 && !urlsLookValid"
              placeholder="https://api.github.com/user"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('connectors.userinfoUrlHint') }}</p>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="connector-client-id">{{ t('connectors.clientIdField') }}</Label>
              <Input
                id="connector-client-id"
                v-model="clientId"
                placeholder="Iv1.abc123"
                autocomplete="off"
                spellcheck="false"
              />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="connector-secret">{{ t('connectors.clientSecretField') }}</Label>
              <Input
                id="connector-secret"
                v-model="clientSecret"
                type="password"
                :aria-label="t('connectors.clientSecretField')"
                autocomplete="new-password"
                spellcheck="false"
              />
            </div>
          </div>
          <p class="-mt-1.5 text-[11.5px] leading-snug text-ink-faint">{{ t('connectors.clientSecretHint') }}</p>

          <div v-if="!builtIn" class="flex flex-col gap-1.5">
            <Label for="connector-scopes">{{ t('connectors.scopesField') }}</Label>
            <Input
              id="connector-scopes"
              v-model="scopesText"
              :invalid="!scopesLookValid"
              placeholder="read:user user:email"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('connectors.scopesHint') }}</p>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="createOpen = false">{{ t('common.cancel') }}</Button>
            <Button variant="primary" type="submit" :disabled="createConnector.isPending.value">
              {{ createConnector.isPending.value ? t('common.saving') : t('connectors.create') }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('connectors.deleteTitle', { name: deleteTarget?.display_name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('connectors.deleteDescription') }}</DialogDescription>
        </DialogHeader>

        <p v-if="deleteError" class="text-[12.5px] text-deny">{{ deleteError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="deleteConnector.isPending.value" @click="confirmDelete">
            {{ deleteConnector.isPending.value ? t('common.saving') : t('connectors.delete') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
