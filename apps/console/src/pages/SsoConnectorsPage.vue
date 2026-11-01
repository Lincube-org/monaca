<script setup lang="ts">
import {
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  ScopeBadge,
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
import type { SsoConnector } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import {
  useCreateSsoConnector,
  useDeleteSsoConnector,
  useSsoConnectors,
} from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Enterprise SSO — the identity providers the sign-in page routes by email domain (§6.2).
 *
 * Registration is the only edit: create, list and delete, with the secret sealed at rest. The page
 * states the routing rule plainly because it is the security property: a provider may only sign in
 * the addresses at the domains it owns, and one domain belongs to one provider.
 */
const ui = useUiStore();

const connectors = useSsoConnectors();
const createConnector = useCreateSsoConnector();
const deleteConnector = useDeleteSsoConnector();

const rows = computed(() => connectors.data.value?.items ?? []);

// --- Register -----------------------------------------------------------------------------------

const createOpen = ref(false);
const connectorId = ref("");
const displayName = ref("");
const issuer = ref("");
const authorizeUrl = ref("");
const tokenUrl = ref("");
const userinfoUrl = ref("");
const clientId = ref("");
const clientSecret = ref("");
const scopesText = ref("");
const domainsText = ref("");
const formError = ref<string | null>(null);

const connectorIdLooksValid = computed(() =>
  /^[a-z0-9][a-z0-9-]{1,31}$/.test(connectorId.value.trim().toLowerCase()),
);

const urlsLookValid = computed(() =>
  [issuer.value, authorizeUrl.value, tokenUrl.value, userinfoUrl.value].every((url) =>
    /^https?:\/\/[^\s]+$/.test(url.trim()),
  ),
);

const scopesLookValid = computed(() =>
  splitTokens(scopesText.value).every((scope) => !/\s/.test(scope)),
);

const domains = computed(() => splitTokens(domainsText.value));
const domainsLookValid = computed(() => domains.value.length > 0);

function splitTokens(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
}

watch(
  [
    connectorId,
    displayName,
    issuer,
    authorizeUrl,
    tokenUrl,
    userinfoUrl,
    clientId,
    clientSecret,
    scopesText,
    domainsText,
  ],
  () => (formError.value = null),
);

function openCreate(): void {
  connectorId.value = "";
  displayName.value = "";
  issuer.value = "";
  authorizeUrl.value = "";
  tokenUrl.value = "";
  userinfoUrl.value = "";
  clientId.value = "";
  clientSecret.value = "";
  scopesText.value = "";
  domainsText.value = "";
  formError.value = null;
  createOpen.value = true;
}

async function submit(): Promise<void> {
  if (!connectorIdLooksValid.value) {
    formError.value = t("sso.invalidConnectorId");
    return;
  }
  if (displayName.value.trim().length === 0) {
    formError.value = t("sso.invalidDisplayName");
    return;
  }
  if (!urlsLookValid.value) {
    formError.value = t("sso.invalidUrls");
    return;
  }
  if (clientId.value.trim().length === 0 || clientSecret.value.length === 0) {
    formError.value = t("sso.invalidCredentials");
    return;
  }
  if (!scopesLookValid.value) {
    formError.value = t("sso.invalidScopes");
    return;
  }
  if (!domainsLookValid.value) {
    formError.value = t("sso.invalidDomains");
    return;
  }
  formError.value = null;

  try {
    const created = await createConnector.mutateAsync({
      connector_id: connectorId.value.trim().toLowerCase(),
      display_name: displayName.value.trim(),
      issuer: issuer.value.trim(),
      authorize_url: authorizeUrl.value.trim(),
      token_url: tokenUrl.value.trim(),
      userinfo_url: userinfoUrl.value.trim(),
      client_id: clientId.value.trim(),
      client_secret: clientSecret.value,
      scopes: splitTokens(scopesText.value),
      email_domains: domains.value,
    });
    toast({
      title: t("sso.createdToast"),
      description: t("sso.createdDescription", {
        connectorId: created.connector_id,
        domains: created.email_domains.join(", "),
      }),
      variant: "success",
    });
    createOpen.value = false;
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

// --- Delete -------------------------------------------------------------------------------------

const deleteOpen = ref(false);
const deleteTarget = ref<SsoConnector | null>(null);
const deleteError = ref<string | null>(null);

function openDelete(connector: SsoConnector): void {
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
      title: t("sso.deletedToast"),
      description: t("sso.deletedDescription", { connectorId: target.connector_id }),
      variant: "success",
    });
  } catch (error) {
    deleteError.value = describeError(error).title;
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
      :title="t('sso.title')"
      :subtitle="t('sso.subtitle', { tenant: ui.tenant })"
      :stats="[
        rows.length === 1 ? t('sso.countOne') : t('sso.count', { count: rows.length }),
      ]"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="connectors.refetch()">
          <RefreshCw :class="connectors.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openCreate">
          <Plus />
          {{ t('sso.create') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="connectors.isPending.value"
      :error="connectors.error.value"
      :empty="rows.length === 0"
      :empty-title="t('sso.empty')"
      :empty-hint="t('sso.emptyHint')"
      :on-retry="() => connectors.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openCreate">
          <Plus />
          {{ t('sso.create') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('sso.name') }}</TableHead>
            <TableHead>{{ t('sso.domains') }}</TableHead>
            <TableHead>{{ t('sso.issuer') }}</TableHead>
            <TableHead>{{ t('sso.scopes') }}</TableHead>
            <TableHead>{{ t('sso.created') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="connector in rows" :key="connector.connector_id">
            <TableCell class="max-w-[200px]">
              <span class="block truncate font-medium text-ink">{{ connector.display_name }}</span>
              <span class="mono-data mt-0.5 block truncate text-[11px] text-ink-faint">
                {{ connector.connector_id }}
              </span>
            </TableCell>
            <TableCell class="max-w-[220px]">
              <span class="flex flex-wrap gap-1">
                <Badge v-for="domain in connector.email_domains" :key="domain" variant="muted">
                  {{ domain }}
                </Badge>
              </span>
            </TableCell>
            <TableCell class="max-w-[240px]">
              <span class="mono-data block truncate text-[11.5px] text-ink-muted">
                {{ connector.issuer }}
              </span>
            </TableCell>
            <TableCell class="max-w-[180px]">
              <span v-if="connector.scopes.length > 0" class="flex flex-wrap gap-1">
                <ScopeBadge v-for="scope in connector.scopes" :key="scope" :scope="scope" />
              </span>
              <span v-else class="text-[11.5px] text-ink-faint">—</span>
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
                  {{ t('sso.delete') }}
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
          <DialogTitle>{{ t('sso.createTitle') }}</DialogTitle>
          <DialogDescription>{{ t('sso.createDescription') }}</DialogDescription>
        </DialogHeader>

        <form class="flex max-h-[65vh] flex-col gap-3.5 overflow-y-auto pr-0.5" @submit.prevent="submit">
          <div class="grid grid-cols-[160px_1fr] gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="sso-connector-id">{{ t('sso.connectorIdField') }}</Label>
              <Input
                id="sso-connector-id"
                v-model="connectorId"
                :invalid="connectorId.length > 0 && !connectorIdLooksValid"
                placeholder="okta"
                autocomplete="off"
                spellcheck="false"
              />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="sso-connector-name">{{ t('sso.displayNameField') }}</Label>
              <Input
                id="sso-connector-name"
                v-model="displayName"
                placeholder="Acme Okta"
                autocomplete="off"
                spellcheck="false"
              />
            </div>
          </div>
          <p class="-mt-1.5 text-[11.5px] leading-snug text-ink-faint">
            {{ connectorId.length > 0 && !connectorIdLooksValid ? t('sso.invalidConnectorId') : t('sso.connectorIdHint') }}
          </p>

          <div class="flex flex-col gap-1.5">
            <Label for="sso-issuer">{{ t('sso.issuerField') }}</Label>
            <Input
              id="sso-issuer"
              v-model="issuer"
              :invalid="issuer.length > 0 && !urlsLookValid"
              placeholder="https://acme.okta.com"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('sso.issuerHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="sso-authorize">{{ t('sso.authorizeUrlField') }}</Label>
            <Input
              id="sso-authorize"
              v-model="authorizeUrl"
              :invalid="authorizeUrl.length > 0 && !urlsLookValid"
              placeholder="https://acme.okta.com/oauth2/v1/authorize"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="sso-token">{{ t('sso.tokenUrlField') }}</Label>
            <Input
              id="sso-token"
              v-model="tokenUrl"
              :invalid="tokenUrl.length > 0 && !urlsLookValid"
              placeholder="https://acme.okta.com/oauth2/v1/token"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="sso-userinfo">{{ t('sso.userinfoUrlField') }}</Label>
            <Input
              id="sso-userinfo"
              v-model="userinfoUrl"
              :invalid="userinfoUrl.length > 0 && !urlsLookValid"
              placeholder="https://acme.okta.com/oauth2/v1/userinfo"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="sso-client-id">{{ t('sso.clientIdField') }}</Label>
              <Input
                id="sso-client-id"
                v-model="clientId"
                placeholder="0oa1abc2def"
                autocomplete="off"
                spellcheck="false"
              />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="sso-secret">{{ t('sso.clientSecretField') }}</Label>
              <Input
                id="sso-secret"
                v-model="clientSecret"
                type="password"
                :aria-label="t('sso.clientSecretField')"
                autocomplete="new-password"
                spellcheck="false"
              />
            </div>
          </div>
          <p class="-mt-1.5 text-[11.5px] leading-snug text-ink-faint">{{ t('sso.clientSecretHint') }}</p>

          <div class="flex flex-col gap-1.5">
            <Label for="sso-scopes">{{ t('sso.scopesField') }}</Label>
            <Input
              id="sso-scopes"
              v-model="scopesText"
              :invalid="!scopesLookValid"
              placeholder="openid profile email"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('sso.scopesHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="sso-domains">{{ t('sso.domainsField') }}</Label>
            <Input
              id="sso-domains"
              v-model="domainsText"
              :invalid="domainsText.length > 0 && !domainsLookValid"
              placeholder="acme.example partner.example"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('sso.domainsHint') }}</p>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="createOpen = false">{{ t('common.cancel') }}</Button>
            <Button variant="primary" type="submit" :disabled="createConnector.isPending.value">
              {{ createConnector.isPending.value ? t('common.saving') : t('sso.create') }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('sso.deleteTitle', { name: deleteTarget?.display_name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('sso.deleteDescription') }}</DialogDescription>
        </DialogHeader>

        <p v-if="deleteError" class="text-[12.5px] text-deny">{{ deleteError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="deleteConnector.isPending.value" @click="confirmDelete">
            {{ deleteConnector.isPending.value ? t('common.saving') : t('sso.delete') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
