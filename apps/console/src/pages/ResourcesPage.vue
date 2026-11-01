<script setup lang="ts">
import {
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
import type { ApiResource } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import { useCreateResource, useDeleteResource, useResources, useUpdateResource } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * API resources — the audiences an application may request (§6.2).
 *
 * Tenant-level like Applications: one identifier namespace serves every client, and `authorize`
 * refuses a custom scope no registered resource defines. The identifier is fixed at registration
 * because it is the audience baked into tokens; only the display name and the scope set are
 * editable.
 */
const ui = useUiStore();

const resources = useResources();
const createResource = useCreateResource();
const updateResource = useUpdateResource();
const deleteResource = useDeleteResource();

const rows = computed(() => resources.data.value?.items ?? []);

// --- Create / edit ------------------------------------------------------------------------------

const formOpen = ref(false);
const editing = ref<ApiResource | null>(null);
const name = ref("");
const identifier = ref("");
const scopesText = ref("");
const formError = ref<string | null>(null);

const identifierLooksValid = computed(() => /^https?:\/\/[^\s]+$/.test(identifier.value.trim()));

const scopesLookValid = computed(() =>
  splitScopes(scopesText.value).every((scope) => /^[a-z][a-z0-9_.-]*(:[a-z][a-z0-9_.-]*)*$/.test(scope)),
);

function splitScopes(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);
}

watch([name, identifier, scopesText], () => (formError.value = null));

function openCreate(): void {
  editing.value = null;
  name.value = "";
  identifier.value = "";
  scopesText.value = "";
  formError.value = null;
  formOpen.value = true;
}

function openEdit(resource: ApiResource): void {
  editing.value = resource;
  name.value = resource.name;
  identifier.value = resource.identifier;
  scopesText.value = resource.scopes.join(" ");
  formError.value = null;
  formOpen.value = true;
}

async function submit(): Promise<void> {
  if (name.value.trim().length === 0) {
    formError.value = t("resources.invalidName");
    return;
  }
  if (editing.value === null && !identifierLooksValid.value) {
    formError.value = t("resources.invalidIdentifier");
    return;
  }
  if (!scopesLookValid.value) {
    formError.value = t("resources.invalidScopes");
    return;
  }
  formError.value = null;

  try {
    if (editing.value === null) {
      const created = await createResource.mutateAsync({
        name: name.value.trim(),
        identifier: identifier.value.trim(),
        scopes: splitScopes(scopesText.value),
      });
      toast({
        title: t("resources.createdToast"),
        description: t("resources.createdDescription", { identifier: created.identifier }),
        variant: "success",
      });
    } else {
      const updated = await updateResource.mutateAsync({
        resourceId: editing.value.id,
        body: { name: name.value.trim(), scopes: splitScopes(scopesText.value) },
      });
      toast({
        title: t("resources.updatedToast"),
        description: t("resources.updatedDescription", { name: updated.name }),
        variant: "success",
      });
    }
    formOpen.value = false;
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

// --- Delete -------------------------------------------------------------------------------------

const deleteOpen = ref(false);
const deleteTarget = ref<ApiResource | null>(null);
const deleteError = ref<string | null>(null);

function openDelete(resource: ApiResource): void {
  deleteTarget.value = resource;
  deleteError.value = null;
  deleteOpen.value = true;
}

async function confirmDelete(): Promise<void> {
  const target = deleteTarget.value;
  if (!target) return;
  deleteError.value = null;
  try {
    await deleteResource.mutateAsync({ resourceId: target.id });
    deleteOpen.value = false;
    toast({
      title: t("resources.deletedToast"),
      description: t("resources.deletedDescription", { identifier: target.identifier }),
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
      :title="t('resources.title')"
      :subtitle="t('resources.subtitle', { tenant: ui.tenant })"
      :stats="[t('resources.count', { count: rows.length })]"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="resources.refetch()">
          <RefreshCw :class="resources.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openCreate">
          <Plus />
          {{ t('resources.create') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="resources.isPending.value"
      :error="resources.error.value"
      :empty="rows.length === 0"
      :empty-title="t('resources.empty')"
      :empty-hint="t('resources.emptyHint')"
      :on-retry="() => resources.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openCreate">
          <Plus />
          {{ t('resources.create') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('resources.name') }}</TableHead>
            <TableHead>{{ t('resources.scopes') }}</TableHead>
            <TableHead>{{ t('resources.created') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="resource in rows" :key="resource.id">
            <TableCell class="max-w-[320px]">
              <span class="block truncate font-medium text-ink">{{ resource.name }}</span>
              <span class="mono-data mt-0.5 block truncate text-[11px] text-ink-faint">
                {{ resource.identifier }}
              </span>
            </TableCell>
            <TableCell>
              <span v-if="resource.scopes.length > 0" class="flex flex-wrap gap-1">
                <ScopeBadge v-for="scope in resource.scopes" :key="scope" :scope="scope" />
              </span>
              <span v-else class="text-[11.5px] text-ink-faint">{{ t('resources.noScopes') }}</span>
            </TableCell>
            <TableCell class="mono-data whitespace-nowrap text-[11.5px] text-ink-faint">
              {{ formatDate(resource.created_at) }}
            </TableCell>
            <TableCell>
              <div class="flex justify-end gap-1.5">
                <Button variant="secondary" size="xs" @click="openEdit(resource)">
                  {{ t('resources.edit') }}
                </Button>
                <Button
                  variant="secondary"
                  size="xs"
                  class="text-ink-muted hover:text-deny"
                  :disabled="deleteResource.isPending.value"
                  @click="openDelete(resource)"
                >
                  {{ t('resources.delete') }}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </QueryBoundary>

    <Dialog v-model:open="formOpen">
      <DialogContent class="max-w-[480px]">
        <DialogHeader>
          <DialogTitle>
            {{ editing ? t('resources.editTitle', { name: editing.name }) : t('resources.createTitle') }}
          </DialogTitle>
          <DialogDescription>
            {{ editing ? t('resources.editDescription') : t('resources.createDescription') }}
          </DialogDescription>
        </DialogHeader>

        <form class="flex flex-col gap-3.5" @submit.prevent="submit">
          <div class="flex flex-col gap-1.5">
            <Label for="resource-name">{{ t('resources.nameField') }}</Label>
            <Input id="resource-name" v-model="name" placeholder="Notes API" autocomplete="off" spellcheck="false" />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('resources.nameHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="resource-identifier">{{ t('resources.identifierField') }}</Label>
            <Input
              id="resource-identifier"
              v-model="identifier"
              :disabled="editing !== null"
              :invalid="identifier.length > 0 && !identifierLooksValid"
              placeholder="https://api.example.com"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('resources.identifierHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="resource-scopes">{{ t('resources.scopesField') }}</Label>
            <Input
              id="resource-scopes"
              v-model="scopesText"
              :invalid="scopesText.length > 0 && !scopesLookValid"
              placeholder="tools:read tools:write"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('resources.scopesHint') }}</p>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="formOpen = false">{{ t('common.cancel') }}</Button>
            <Button
              variant="primary"
              type="submit"
              :disabled="createResource.isPending.value || updateResource.isPending.value"
            >
              {{
                createResource.isPending.value || updateResource.isPending.value
                  ? t('common.saving')
                  : editing
                    ? t('resources.edit')
                    : t('resources.create')
              }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('resources.deleteTitle', { name: deleteTarget?.name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('resources.deleteDescription', { identifier: deleteTarget?.identifier ?? '' }) }}</DialogDescription>
        </DialogHeader>

        <p v-if="deleteError" class="text-[12.5px] text-deny">{{ deleteError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="deleteResource.isPending.value" @click="confirmDelete">
            {{ deleteResource.isPending.value ? t('common.saving') : t('resources.delete') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
