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
import type { Organization } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import { useCreateOrganization, useOrganizations, useUpdateOrganization } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Organizations.
 *
 * The one page in the console that is not scoped to the org switcher: it is the tenant's list of
 * organizations, and archiving is the reversible substitute for deleting one (§6.2). The default
 * org carries the fallback for every flow that names none, so it never offers Archive.
 */
const ui = useUiStore();
const organizations = useOrganizations();
const createOrganization = useCreateOrganization();
const updateOrganization = useUpdateOrganization();

const createOpen = ref(false);
const slug = ref("");
const formError = ref<string | null>(null);

const archiveOpen = ref(false);
const archiveTarget = ref<Organization | null>(null);
const actionError = ref<string | null>(null);

const rows = computed(() => organizations.data.value?.items ?? []);

/** The slug rule from §6.2, checked before a round trip is spent on it. */
const slugLooksValid = computed(() => /^[a-z0-9][a-z0-9-]{1,30}$/.test(slug.value.trim()));

function openCreate(): void {
  slug.value = "";
  formError.value = null;
  createOpen.value = true;
}

watch(slug, () => (formError.value = null));

async function submitCreate(): Promise<void> {
  if (!slugLooksValid.value) {
    formError.value = t("organizations.slugHint");
    return;
  }
  formError.value = null;
  try {
    const created = await createOrganization.mutateAsync({ slug: slug.value.trim() });
    toast({
      title: t("organizations.createdToast"),
      description: t("organizations.createdDescription", { slug: created.slug }),
      variant: "success",
    });
    createOpen.value = false;
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

function openArchive(org: Organization): void {
  archiveTarget.value = org;
  actionError.value = null;
  archiveOpen.value = true;
}

async function confirmArchive(): Promise<void> {
  const target = archiveTarget.value;
  if (!target) return;
  actionError.value = null;
  try {
    const archived = await updateOrganization.mutateAsync({
      organizationId: target.id,
      body: { state: "archived" },
    });
    toast({
      title: t("organizations.archivedToast"),
      description: t("organizations.archivedDescription", { slug: archived.slug }),
      variant: "success",
    });
    archiveOpen.value = false;
  } catch (error) {
    actionError.value = describeError(error).title;
  }
}

async function reactivate(org: Organization): Promise<void> {
  try {
    const updated = await updateOrganization.mutateAsync({
      organizationId: org.id,
      body: { state: "active" },
    });
    toast({
      title: t("organizations.reactivatedToast"),
      description: t("organizations.reactivatedDescription", { slug: updated.slug }),
      variant: "success",
    });
  } catch (error) {
    toast({ title: t("organizations.actionFailed"), description: describeError(error).title, variant: "error" });
  }
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('organizations.title')"
      :subtitle="t('organizations.subtitle', { tenant: ui.tenant })"
      :stats="[t('organizations.count', { count: rows.length })]"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="organizations.refetch()">
          <RefreshCw :class="organizations.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openCreate">
          <Plus />
          {{ t('organizations.create') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="organizations.isPending.value"
      :error="organizations.error.value"
      :empty="rows.length === 0"
      :empty-title="t('organizations.empty')"
      :empty-hint="t('organizations.emptyHint')"
      :on-retry="() => organizations.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openCreate">
          <Plus />
          {{ t('organizations.create') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('organizations.slug') }}</TableHead>
            <TableHead>{{ t('organizations.state') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="org in rows" :key="org.id">
            <TableCell>
              <span class="flex items-center gap-1.5">
                <span class="font-medium text-ink">{{ org.slug }}</span>
                <Badge v-if="org.is_default" variant="brand">{{ t('organizations.defaultBadge') }}</Badge>
              </span>
              <span class="mono-data mt-0.5 block text-[11px] text-ink-faint">{{ org.id }}</span>
            </TableCell>
            <TableCell>
              <Badge :variant="org.state === 'active' ? 'allow' : 'muted'">
                {{ org.state === "active" ? t("organizations.stateActive") : t("organizations.stateArchived") }}
              </Badge>
            </TableCell>
            <TableCell>
              <div class="flex justify-end gap-1.5">
                <Button
                  v-if="org.state === 'active' && !org.is_default"
                  variant="secondary"
                  size="xs"
                  :disabled="updateOrganization.isPending.value"
                  @click="openArchive(org)"
                >
                  {{ t('organizations.archive') }}
                </Button>
                <Button
                  v-else-if="org.state === 'archived'"
                  variant="secondary"
                  size="xs"
                  :disabled="updateOrganization.isPending.value"
                  @click="reactivate(org)"
                >
                  {{ t('organizations.reactivate') }}
                </Button>
                <span
                  v-else-if="org.is_default"
                  class="text-[11.5px] text-ink-faint"
                  :title="t('organizations.defaultHint')"
                >
                  {{ t('organizations.defaultHint') }}
                </span>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </QueryBoundary>

    <Dialog v-model:open="createOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('organizations.createTitle') }}</DialogTitle>
          <DialogDescription>{{ t('organizations.createDescription') }}</DialogDescription>
        </DialogHeader>

        <form class="flex flex-col gap-3.5" @submit.prevent="submitCreate">
          <div class="flex flex-col gap-1.5">
            <Label for="org-slug">{{ t('organizations.slugField') }}</Label>
            <Input
              id="org-slug"
              v-model="slug"
              :invalid="slug.length > 0 && !slugLooksValid"
              placeholder="acme-team"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('organizations.slugHint') }}</p>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="createOpen = false">{{ t('common.cancel') }}</Button>
            <Button variant="primary" type="submit" :disabled="createOrganization.isPending.value">
              {{ createOrganization.isPending.value ? t('common.saving') : t('organizations.create') }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="archiveOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('organizations.archiveTitle', { slug: archiveTarget?.slug ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('organizations.archiveDescription') }}</DialogDescription>
        </DialogHeader>

        <p v-if="actionError" class="text-[12.5px] text-deny">{{ actionError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="archiveOpen = false">{{ t('common.cancel') }}</Button>
          <Button
            variant="primary"
            type="button"
            :disabled="updateOrganization.isPending.value"
            @click="confirmArchive"
          >
            {{ updateOrganization.isPending.value ? t('common.saving') : t('organizations.archive') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
