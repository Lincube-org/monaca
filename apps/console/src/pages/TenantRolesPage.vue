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
import type { TenantRole } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import { useCreateTenantRole, useDeleteTenantRole, useTenantRoles } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Tenant roles — permission sets that apply in every organization (§6.2).
 *
 * The table is the definition only: who holds a role is managed from the Users page, because the
 * directory row is what carries an account's roles. A role is immutable after creation, so there is
 * no edit action — a changed permission set is a new role. Deleting one revokes its scopes on every
 * holder's next token, which the confirmation says rather than leaving to be discovered.
 */
const ui = useUiStore();

const roles = useTenantRoles();
const createRole = useCreateTenantRole();
const deleteRole = useDeleteTenantRole();

const rows = computed(() => roles.data.value?.items ?? []);

// --- Create -------------------------------------------------------------------------------------

const createOpen = ref(false);
const name = ref("");
const descriptionText = ref("");
const permissionsText = ref("");
const formError = ref<string | null>(null);

const permissionsLookValid = computed(() =>
  splitPermissions(permissionsText.value).every((permission) =>
    /^[a-z][a-z0-9_.-]*(:[a-z][a-z0-9_.-]*)*$/.test(permission),
  ),
);

function splitPermissions(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((permission) => permission.trim())
    .filter((permission) => permission.length > 0);
}

watch([name, descriptionText, permissionsText], () => (formError.value = null));

function openCreate(): void {
  name.value = "";
  descriptionText.value = "";
  permissionsText.value = "";
  formError.value = null;
  createOpen.value = true;
}

async function submit(): Promise<void> {
  if (name.value.trim().length === 0) {
    formError.value = t("tenantRoles.invalidName");
    return;
  }
  if (!permissionsLookValid.value) {
    formError.value = t("tenantRoles.invalidPermissions");
    return;
  }
  formError.value = null;

  try {
    const created = await createRole.mutateAsync({
      name: name.value.trim(),
      description: descriptionText.value.trim(),
      permissions: splitPermissions(permissionsText.value),
    });
    toast({
      title: t("tenantRoles.createdToast"),
      description: t("tenantRoles.createdDescription", { name: created.name }),
      variant: "success",
    });
    createOpen.value = false;
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

// --- Delete -------------------------------------------------------------------------------------

const deleteOpen = ref(false);
const deleteTarget = ref<TenantRole | null>(null);
const deleteError = ref<string | null>(null);

function openDelete(role: TenantRole): void {
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
      title: t("tenantRoles.deletedToast"),
      description: t("tenantRoles.deletedDescription", { name: target.name }),
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
      :title="t('tenantRoles.title')"
      :subtitle="t('tenantRoles.subtitle', { tenant: ui.tenant })"
      :stats="[t('tenantRoles.count', { count: rows.length })]"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="roles.refetch()">
          <RefreshCw :class="roles.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openCreate">
          <Plus />
          {{ t('tenantRoles.create') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="roles.isPending.value"
      :error="roles.error.value"
      :empty="rows.length === 0"
      :empty-title="t('tenantRoles.empty')"
      :empty-hint="t('tenantRoles.emptyHint')"
      :on-retry="() => roles.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openCreate">
          <Plus />
          {{ t('tenantRoles.create') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('tenantRoles.name') }}</TableHead>
            <TableHead>{{ t('tenantRoles.permissions') }}</TableHead>
            <TableHead>{{ t('tenantRoles.created') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="role in rows" :key="role.id">
            <TableCell class="max-w-[300px]">
              <span class="block truncate font-medium text-ink">{{ role.name }}</span>
              <span class="mt-0.5 block truncate text-[11.5px] text-ink-faint">
                {{ role.description || t('tenantRoles.noDescription') }}
              </span>
            </TableCell>
            <TableCell>
              <span v-if="role.permissions.length > 0" class="flex flex-wrap gap-1">
                <ScopeBadge v-for="permission in role.permissions" :key="permission" :scope="permission" />
              </span>
              <span v-else class="text-[11.5px] text-ink-faint">{{ t('tenantRoles.noPermissions') }}</span>
            </TableCell>
            <TableCell class="mono-data whitespace-nowrap text-[11.5px] text-ink-faint">
              {{ formatDate(role.created_at) }}
            </TableCell>
            <TableCell>
              <div class="flex justify-end">
                <Button
                  variant="secondary"
                  size="xs"
                  class="text-ink-muted hover:text-deny"
                  :disabled="deleteRole.isPending.value"
                  @click="openDelete(role)"
                >
                  {{ t('tenantRoles.delete') }}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </QueryBoundary>

    <Dialog v-model:open="createOpen">
      <DialogContent class="max-w-[460px]">
        <DialogHeader>
          <DialogTitle>{{ t('tenantRoles.createTitle') }}</DialogTitle>
          <DialogDescription>{{ t('tenantRoles.createDescription') }}</DialogDescription>
        </DialogHeader>

        <form class="flex flex-col gap-3.5" @submit.prevent="submit">
          <div class="flex flex-col gap-1.5">
            <Label for="tenant-role-name">{{ t('tenantRoles.nameField') }}</Label>
            <Input
              id="tenant-role-name"
              v-model="name"
              placeholder="viewer"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('tenantRoles.nameHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="tenant-role-description">{{ t('tenantRoles.descriptionField') }}</Label>
            <Input
              id="tenant-role-description"
              v-model="descriptionText"
              placeholder="Read-only access to the tenant's tools."
              autocomplete="off"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('tenantRoles.descriptionHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="tenant-role-permissions">{{ t('tenantRoles.permissionsField') }}</Label>
            <Input
              id="tenant-role-permissions"
              v-model="permissionsText"
              :invalid="permissionsText.length > 0 && !permissionsLookValid"
              placeholder="tools:read tools:write"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('tenantRoles.permissionsHint') }}</p>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="createOpen = false">{{ t('common.cancel') }}</Button>
            <Button variant="primary" type="submit" :disabled="createRole.isPending.value">
              {{ createRole.isPending.value ? t('common.saving') : t('tenantRoles.create') }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('tenantRoles.deleteTitle', { name: deleteTarget?.name ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('tenantRoles.deleteDescription') }}</DialogDescription>
        </DialogHeader>

        <p v-if="deleteError" class="text-[12.5px] text-deny">{{ deleteError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="deleteRole.isPending.value" @click="confirmDelete">
            {{ deleteRole.isPending.value ? t('common.saving') : t('tenantRoles.delete') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
