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
import type { OrgRoleDetail } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import { useCreateOrgRole, useDeleteOrgRole, useOrgRoles, useUpdateOrgRole } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Roles — the org's named scope sets (§6.2).
 *
 * The table is the definition; who holds a role is managed from the Members page, because the API
 * addresses assignments by member. A role's scopes are what an id_token carries while signing into
 * this org, so deleting one silently revoking scopes is called out in the confirmation.
 */
const ui = useUiStore();
const org = computed(() => ui.org);

const roles = useOrgRoles(org);
const createRole = useCreateOrgRole(org);
const updateRole = useUpdateOrgRole(org);
const deleteRole = useDeleteOrgRole(org);

const rows = computed(() => roles.data.value?.items ?? []);

// --- Create / edit ------------------------------------------------------------------------------

const formOpen = ref(false);
const editing = ref<OrgRoleDetail | null>(null);
const name = ref("");
const descriptionText = ref("");
const scopesText = ref("");
const formError = ref<string | null>(null);

const scopesLookValid = computed(() =>
  splitScopes(scopesText.value).every((scope) => /^[a-z][a-z0-9_.-]*(:[a-z][a-z0-9_.-]*)*$/.test(scope)),
);

function splitScopes(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);
}

watch([name, descriptionText, scopesText], () => (formError.value = null));

function openCreate(): void {
  editing.value = null;
  name.value = "";
  descriptionText.value = "";
  scopesText.value = "";
  formError.value = null;
  formOpen.value = true;
}

function openEdit(role: OrgRoleDetail): void {
  editing.value = role;
  name.value = role.name;
  descriptionText.value = role.description;
  scopesText.value = role.scopes.join(" ");
  formError.value = null;
  formOpen.value = true;
}

async function submit(): Promise<void> {
  if (name.value.trim().length === 0) {
    formError.value = t("roles.invalidName");
    return;
  }
  if (!scopesLookValid.value) {
    formError.value = t("roles.invalidScopes");
    return;
  }
  formError.value = null;

  const body = {
    name: name.value.trim(),
    description: descriptionText.value.trim(),
    scopes: splitScopes(scopesText.value),
  };

  try {
    if (editing.value === null) {
      const created = await createRole.mutateAsync(body);
      toast({
        title: t("roles.createdToast"),
        description: t("roles.createdDescription", { name: created.name }),
        variant: "success",
      });
    } else {
      const updated = await updateRole.mutateAsync({ roleId: editing.value.id, body });
      toast({
        title: t("roles.updatedToast"),
        description: t("roles.updatedDescription", { name: updated.name }),
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
const deleteTarget = ref<OrgRoleDetail | null>(null);
const deleteError = ref<string | null>(null);

function openDelete(role: OrgRoleDetail): void {
  deleteTarget.value = role;
  deleteError.value = null;
  deleteOpen.value = true;
}

async function confirmDelete(): Promise<void> {
  const target = deleteTarget.value;
  if (!target) return;
  deleteError.value = null;
  try {
    await deleteRole.mutateAsync({ roleId: target.id });
    deleteOpen.value = false;
    toast({
      title: t("roles.deletedToast"),
      description: t("roles.deletedDescription", { name: target.name }),
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
      :title="t('roles.title')"
      :subtitle="t('roles.subtitle', { org })"
      :stats="[t('roles.count', { count: rows.length })]"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="roles.refetch()">
          <RefreshCw :class="roles.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openCreate">
          <Plus />
          {{ t('roles.create') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="roles.isPending.value"
      :error="roles.error.value"
      :empty="rows.length === 0"
      :empty-title="t('roles.empty')"
      :empty-hint="t('roles.emptyHint')"
      :on-retry="() => roles.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openCreate">
          <Plus />
          {{ t('roles.create') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('roles.name') }}</TableHead>
            <TableHead>{{ t('roles.scopes') }}</TableHead>
            <TableHead>{{ t('roles.created') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="role in rows" :key="role.id">
            <TableCell class="max-w-[300px]">
              <span class="block truncate font-medium text-ink">{{ role.name }}</span>
              <span class="mt-0.5 block truncate text-[11.5px] text-ink-faint">
                {{ role.description || t('roles.noDescription') }}
              </span>
            </TableCell>
            <TableCell>
              <span v-if="role.scopes.length > 0" class="flex flex-wrap gap-1">
                <ScopeBadge v-for="scope in role.scopes" :key="scope" :scope="scope" />
              </span>
              <span v-else class="text-[11.5px] text-ink-faint">{{ t('roles.noScopes') }}</span>
            </TableCell>
            <TableCell class="mono-data whitespace-nowrap text-[11.5px] text-ink-faint">
              {{ formatDate(role.created_at) }}
            </TableCell>
            <TableCell>
              <div class="flex justify-end gap-1.5">
                <Button variant="secondary" size="xs" @click="openEdit(role)">
                  {{ t('roles.edit') }}
                </Button>
                <Button
                  variant="secondary"
                  size="xs"
                  class="text-ink-muted hover:text-deny"
                  :disabled="deleteRole.isPending.value"
                  @click="openDelete(role)"
                >
                  {{ t('roles.delete') }}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </QueryBoundary>

    <Dialog v-model:open="formOpen">
      <DialogContent class="max-w-[460px]">
        <DialogHeader>
          <DialogTitle>
            {{ editing ? t('roles.editTitle', { name: editing.name }) : t('roles.createTitle') }}
          </DialogTitle>
          <DialogDescription>
            {{ editing ? t('roles.editDescription') : t('roles.createDescription') }}
          </DialogDescription>
        </DialogHeader>

        <form class="flex flex-col gap-3.5" @submit.prevent="submit">
          <div class="flex flex-col gap-1.5">
            <Label for="role-name">{{ t('roles.nameField') }}</Label>
            <Input id="role-name" v-model="name" placeholder="support" autocomplete="off" spellcheck="false" />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('roles.nameHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="role-description">{{ t('roles.descriptionField') }}</Label>
            <Input
              id="role-description"
              v-model="descriptionText"
              placeholder="Read tool results during the support rotation."
              autocomplete="off"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('roles.descriptionHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="role-scopes">{{ t('roles.scopesField') }}</Label>
            <Input
              id="role-scopes"
              v-model="scopesText"
              :invalid="scopesText.length > 0 && !scopesLookValid"
              placeholder="tools:read tools:write"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('roles.scopesHint') }}</p>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="formOpen = false">{{ t('common.cancel') }}</Button>
            <Button
              variant="primary"
              type="submit"
              :disabled="createRole.isPending.value || updateRole.isPending.value"
            >
              {{
                createRole.isPending.value || updateRole.isPending.value
                  ? t('common.saving')
                  : editing
                    ? t('roles.edit')
                    : t('roles.create')
              }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('roles.deleteTitle', { name: deleteTarget?.name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('roles.deleteDescription') }}</DialogDescription>
        </DialogHeader>

        <p v-if="deleteError" class="text-[12.5px] text-deny">{{ deleteError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="deleteRole.isPending.value" @click="confirmDelete">
            {{ deleteRole.isPending.value ? t('common.saving') : t('roles.delete') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
