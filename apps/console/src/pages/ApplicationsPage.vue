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
import { Copy, Plus, RefreshCw } from "lucide-vue-next";
import { computed, ref, watch } from "vue";

import { describeError } from "@/api/contract";
import type { Client, ClientKind } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import { useClients, useCreateClient, useDeleteClient, useRotateClientSecret, useUpdateClient } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Applications — the console's view of `tenant.clients` (§6.2).
 *
 * The page is tenant-level, like Organizations: one `client_id` namespace serves the whole tenant,
 * so nesting it under the org switcher would imply a scoping the server does not have.
 *
 * Two rules drive the layout. A secret is plaintext exactly once — on create and on rotate — so it
 * is shown in a dedicated dialog that says so, never in the table. And `client_id` plus `kind` are
 * fixed at registration, because both are baked into every authorize URL and into the credential
 * strategy; an edit may rename the application and replace its URIs and scopes, nothing else.
 */
const ui = useUiStore();

const clients = useClients();
const createClient = useCreateClient();
const updateClient = useUpdateClient();
const rotateClientSecret = useRotateClientSecret();
const deleteClient = useDeleteClient();

const rows = computed(() => clients.data.value?.items ?? []);

const kindLabel: Record<ClientKind, string> = {
  public: t("applications.kindPublic"),
  confidential: t("applications.kindConfidential"),
};

// --- Register / edit ---------------------------------------------------------------------------

const formOpen = ref(false);
const editing = ref<Client | null>(null);
const name = ref("");
const clientId = ref("");
const kind = ref<ClientKind>("public");
const redirectUrisText = ref("");
const postLogoutText = ref("");
const scopesText = ref("");
const thirdParty = ref(false);
const customCss = ref("");
const formError = ref<string | null>(null);

/** The protocol-id rule from §6.2, checked before a round trip is spent on it. */
const clientIdLooksValid = computed(() => /^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$/.test(clientId.value.trim()));

const urisLookValid = computed(
  () =>
    splitLines(redirectUrisText.value).every((uri) => /^https?:\/\/[^\s]+$/.test(uri)) &&
    splitLines(postLogoutText.value).every((uri) => /^https?:\/\/[^\s]+$/.test(uri)),
);

/** §6.2: the same 20,000-character ceiling the server enforces. */
const cssLooksValid = computed(() => [...customCss.value.trim()].length <= 20_000);

function splitLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function splitScopes(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);
}

watch([name, clientId, redirectUrisText, postLogoutText, customCss], () => (formError.value = null));

function openCreate(): void {
  editing.value = null;
  clientId.value = "";
  name.value = "";
  kind.value = "public";
  redirectUrisText.value = "";
  postLogoutText.value = "";
  scopesText.value = "openid profile email";
  thirdParty.value = false;
  customCss.value = "";
  formError.value = null;
  formOpen.value = true;
}

function openEdit(client: Client): void {
  editing.value = client;
  clientId.value = client.client_id;
  name.value = client.name;
  kind.value = client.kind;
  redirectUrisText.value = client.redirect_uris.join("\n");
  postLogoutText.value = client.post_logout_redirect_uris.join("\n");
  scopesText.value = client.scopes.join(" ");
  thirdParty.value = client.is_third_party;
  customCss.value = client.custom_css ?? "";
  formError.value = null;
  formOpen.value = true;
}

async function submit(): Promise<void> {
  if (editing.value === null && !clientIdLooksValid.value) {
    formError.value = t("applications.invalidClientId");
    return;
  }
  if (name.value.trim().length === 0) {
    formError.value = t("applications.invalidName");
    return;
  }
  if (!urisLookValid.value) {
    formError.value = t("applications.invalidUris");
    return;
  }
  if (!cssLooksValid.value) {
    formError.value = t("applications.invalidCustomCss");
    return;
  }
  formError.value = null;

  const body = {
    name: name.value.trim(),
    redirect_uris: splitLines(redirectUrisText.value),
    post_logout_redirect_uris: splitLines(postLogoutText.value),
    scopes: splitScopes(scopesText.value),
  };

  try {
    if (editing.value === null) {
      const created = await createClient.mutateAsync({
        client_id: clientId.value.trim(),
        kind: kind.value,
        is_third_party: thirdParty.value,
        ...body,
      });
      formOpen.value = false;
      toast({
        title: t("applications.createdToast"),
        description: t("applications.createdDescription", { clientId: created.client_id }),
        variant: "success",
      });
      // A confidential client's secret exists only in this response — hand it over before the
      // administrator can navigate away from it.
      if (created.client_secret !== undefined) {
        showSecret(created.client_id, created.client_secret);
      }
    } else {
      const updated = await updateClient.mutateAsync({
        clientId: editing.value.id,
        body: { ...body, custom_css: customCss.value },
      });
      formOpen.value = false;
      toast({
        title: t("applications.updatedToast"),
        description: t("applications.updatedDescription", { clientId: updated.client_id }),
        variant: "success",
      });
    }
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

// --- The one-time secret ------------------------------------------------------------------------

const secretOpen = ref(false);
const secretValue = ref("");
const secretClientId = ref("");

function showSecret(forClient: string, secret: string): void {
  secretClientId.value = forClient;
  secretValue.value = secret;
  secretOpen.value = true;
}

async function copySecret(): Promise<void> {
  try {
    await navigator.clipboard.writeText(secretValue.value);
    toast({ title: t("applications.secretCopied"), variant: "success" });
  } catch {
    // Clipboard permission is not required to complete the flow; the field stays selectable.
  }
}

// --- Rotation ------------------------------------------------------------------------------------

const rotateOpen = ref(false);
const rotateTarget = ref<Client | null>(null);
const rotateError = ref<string | null>(null);

function openRotate(client: Client): void {
  rotateTarget.value = client;
  rotateError.value = null;
  rotateOpen.value = true;
}

async function confirmRotate(): Promise<void> {
  const target = rotateTarget.value;
  if (!target) return;
  rotateError.value = null;
  try {
    const result = await rotateClientSecret.mutateAsync({ clientId: target.id });
    rotateOpen.value = false;
    toast({
      title: t("applications.rotatedToast"),
      description: t("applications.rotatedDescription", { clientId: result.client_id }),
      variant: "success",
    });
    showSecret(result.client_id, result.client_secret);
  } catch (error) {
    rotateError.value = describeError(error).title;
  }
}

// --- Delete --------------------------------------------------------------------------------------

const deleteOpen = ref(false);
const deleteTarget = ref<Client | null>(null);
const deleteError = ref<string | null>(null);

function openDelete(client: Client): void {
  deleteTarget.value = client;
  deleteError.value = null;
  deleteOpen.value = true;
}

async function confirmDelete(): Promise<void> {
  const target = deleteTarget.value;
  if (!target) return;
  deleteError.value = null;
  try {
    await deleteClient.mutateAsync({ clientId: target.id });
    deleteOpen.value = false;
    toast({
      title: t("applications.deletedToast"),
      description: t("applications.deletedDescription", { clientId: target.client_id }),
      variant: "success",
    });
  } catch (error) {
    deleteError.value = describeError(error).title;
  }
}

// --- Table helpers -------------------------------------------------------------------------------

function primaryUri(client: Client): string | null {
  return client.redirect_uris[0] ?? null;
}

function formatDate(at: string): string {
  const parsed = new Date(at);
  return Number.isNaN(parsed.getTime()) ? at : parsed.toISOString().slice(0, 10);
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('applications.title')"
      :subtitle="t('applications.subtitle', { tenant: ui.tenant })"
      :stats="[t('applications.count', { count: rows.length })]"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="clients.refetch()">
          <RefreshCw :class="clients.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openCreate">
          <Plus />
          {{ t('applications.create') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="clients.isPending.value"
      :error="clients.error.value"
      :empty="rows.length === 0"
      :empty-title="t('applications.empty')"
      :empty-hint="t('applications.emptyHint')"
      :on-retry="() => clients.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openCreate">
          <Plus />
          {{ t('applications.create') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('applications.name') }}</TableHead>
            <TableHead>{{ t('applications.kind') }}</TableHead>
            <TableHead>{{ t('applications.redirects') }}</TableHead>
            <TableHead>{{ t('applications.scopes') }}</TableHead>
            <TableHead>{{ t('applications.created') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="client in rows" :key="client.id">
            <TableCell class="max-w-[240px]">
              <span class="flex items-center gap-1.5">
                <span class="truncate font-medium text-ink">{{ client.name }}</span>
                <Badge v-if="client.is_third_party" variant="warn">
                  {{ t('applications.thirdPartyBadge') }}
                </Badge>
              </span>
              <span class="mono-data mt-0.5 block truncate text-[11px] text-ink-faint">
                {{ client.client_id }}
              </span>
            </TableCell>
            <TableCell>
              <Badge :variant="client.kind === 'confidential' ? 'info' : 'muted'">
                {{ kindLabel[client.kind] }}
              </Badge>
            </TableCell>
            <TableCell class="max-w-[220px]">
              <template v-if="primaryUri(client)">
                <span class="mono-data block truncate text-[11.5px] text-ink-muted">{{ primaryUri(client) }}</span>
                <span v-if="client.redirect_uris.length > 1" class="mt-0.5 block text-[11px] text-ink-faint">
                  {{ t('applications.redirectsCount', { count: client.redirect_uris.length }) }}
                </span>
              </template>
              <span v-else class="text-[11.5px] text-ink-faint">{{ t('applications.noRedirects') }}</span>
            </TableCell>
            <TableCell class="max-w-[180px]">
              <span v-if="client.scopes.length > 0" class="mono-data text-[11.5px] text-ink-muted">
                {{ client.scopes.join(" ") }}
              </span>
              <span v-else class="text-[11.5px] text-ink-faint">{{ t('applications.noScopes') }}</span>
            </TableCell>
            <TableCell class="mono-data whitespace-nowrap text-[11.5px] text-ink-faint">
              {{ formatDate(client.created_at) }}
            </TableCell>
            <TableCell>
              <div class="flex justify-end gap-1.5">
                <Button variant="secondary" size="xs" @click="openEdit(client)">
                  {{ t('applications.edit') }}
                </Button>
                <Button
                  v-if="client.kind === 'confidential'"
                  variant="secondary"
                  size="xs"
                  :disabled="rotateClientSecret.isPending.value || deleteClient.isPending.value"
                  @click="openRotate(client)"
                >
                  {{ t('applications.rotate') }}
                </Button>
                <Button
                  variant="secondary"
                  size="xs"
                  class="text-ink-muted hover:text-deny"
                  :disabled="deleteClient.isPending.value"
                  @click="openDelete(client)"
                >
                  {{ t('applications.delete') }}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </QueryBoundary>

    <Dialog v-model:open="formOpen">
      <DialogContent class="max-w-[520px]">
        <DialogHeader>
          <DialogTitle>
            {{ editing ? t('applications.editTitle', { name: editing.name }) : t('applications.createTitle') }}
          </DialogTitle>
          <DialogDescription>
            {{ editing ? t('applications.editDescription') : t('applications.createDescription') }}
          </DialogDescription>
        </DialogHeader>

        <form class="flex max-h-[65vh] flex-col gap-3.5 overflow-y-auto pr-0.5" @submit.prevent="submit">
          <div class="flex flex-col gap-1.5">
            <Label for="app-name">{{ t('applications.nameField') }}</Label>
            <Input id="app-name" v-model="name" placeholder="My App" autocomplete="off" spellcheck="false" />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('applications.nameHint') }}</p>
          </div>

          <div class="grid grid-cols-[1fr_160px] gap-3">
            <div class="flex flex-col gap-1.5">
              <Label for="app-client-id">{{ t('applications.clientIdField') }}</Label>
              <Input
                id="app-client-id"
                v-model="clientId"
                :disabled="editing !== null"
                :invalid="clientId.length > 0 && !clientIdLooksValid"
                placeholder="my-app"
                autocomplete="off"
                spellcheck="false"
              />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label for="app-kind">{{ t('applications.kindField') }}</Label>
              <NativeSelect id="app-kind" v-model="kind" :disabled="editing !== null">
                <option value="public">{{ kindLabel.public }}</option>
                <option value="confidential">{{ kindLabel.confidential }}</option>
              </NativeSelect>
            </div>
          </div>
          <p class="-mt-1.5 text-[11.5px] leading-snug text-ink-faint">
            {{ editing ? t('applications.clientIdHint') : kind === "public" ? t('applications.kindPublicHint') : t('applications.kindConfidentialHint') }}
          </p>

          <div class="flex flex-col gap-1.5">
            <Label for="app-redirects">{{ t('applications.redirectUrisField') }}</Label>
            <Textarea
              id="app-redirects"
              v-model="redirectUrisText"
              :invalid="!urisLookValid"
              placeholder="https://app.example/callback"
              spellcheck="false"
              class="mono-data min-h-[64px] text-[12px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('applications.redirectUrisHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="app-post-logout">{{ t('applications.postLogoutUrisField') }}</Label>
            <Textarea
              id="app-post-logout"
              v-model="postLogoutText"
              :invalid="!urisLookValid"
              placeholder="https://app.example/"
              spellcheck="false"
              class="mono-data min-h-[56px] text-[12px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('applications.postLogoutUrisHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="app-scopes">{{ t('applications.scopesField') }}</Label>
            <Input id="app-scopes" v-model="scopesText" placeholder="openid profile email" autocomplete="off" spellcheck="false" />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('applications.scopesHint') }}</p>
          </div>

          <div v-if="editing !== null" class="flex flex-col gap-1.5">
            <Label for="app-custom-css">{{ t('applications.customCssField') }}</Label>
            <Textarea
              id="app-custom-css"
              v-model="customCss"
              :invalid="!cssLooksValid"
              rows="6"
              placeholder=":root { --monaca-accent: #4f46e5; }"
              spellcheck="false"
              class="mono-data text-[12px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">
              {{ t('applications.customCssHint') }}
            </p>
          </div>

          <div v-if="editing === null" class="flex items-start gap-2">
            <Checkbox
              id="app-third-party"
              :model-value="thirdParty"
              @update:model-value="(value: boolean | 'indeterminate') => (thirdParty = value === true)"
            />
            <div class="min-w-0">
              <Label for="app-third-party">{{ t('applications.thirdPartyField') }}</Label>
              <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('applications.thirdPartyHint') }}</p>
            </div>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="formOpen = false">{{ t('common.cancel') }}</Button>
            <Button
              variant="primary"
              type="submit"
              :disabled="createClient.isPending.value || updateClient.isPending.value"
            >
              {{
                createClient.isPending.value || updateClient.isPending.value
                  ? t('common.saving')
                  : editing
                    ? t('applications.edit')
                    : t('applications.create')
              }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="secretOpen">
      <DialogContent class="max-w-[520px]">
        <DialogHeader>
          <DialogTitle>{{ t('applications.secretTitle', { clientId: secretClientId }) }}</DialogTitle>
          <DialogDescription>{{ t('applications.secretDescription') }}</DialogDescription>
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
              {{ t('applications.copySecret') }}
            </Button>
          </div>
          <p class="text-[11.5px] leading-snug text-warn">{{ t('applications.secretWarning') }}</p>
        </div>

        <DialogFooter>
          <Button variant="primary" type="button" @click="secretOpen = false">{{ t('common.close') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="rotateOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('applications.rotateTitle', { clientId: rotateTarget?.client_id ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('applications.rotateDescription') }}</DialogDescription>
        </DialogHeader>

        <p v-if="rotateError" class="text-[12.5px] text-deny">{{ rotateError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="rotateOpen = false">{{ t('common.cancel') }}</Button>
          <Button
            variant="primary"
            type="button"
            :disabled="rotateClientSecret.isPending.value"
            @click="confirmRotate"
          >
            {{ rotateClientSecret.isPending.value ? t('common.saving') : t('applications.rotate') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('applications.deleteTitle', { clientId: deleteTarget?.client_id ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('applications.deleteDescription') }}</DialogDescription>
        </DialogHeader>

        <p v-if="deleteError" class="text-[12.5px] text-deny">{{ deleteError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="deleteClient.isPending.value" @click="confirmDelete">
            {{ deleteClient.isPending.value ? t('common.saving') : t('applications.delete') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
