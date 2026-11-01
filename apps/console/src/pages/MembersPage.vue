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
  NativeSelect,
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
import type { Member, OrgRole, OrgRoleDetail } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import { useAddMember, useAssignOrgRole, useMembers, useMemberRoles, useOrgRoles, useUnassignOrgRole } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Members.
 *
 * A flat table, because that is what the data is: one row per account, three facts each. No
 * avatars (there are none in the contract), no expandable rows, no grouping — the moment a table
 * of five rows needs a disclosure triangle, it should have been a different page.
 */
const ui = useUiStore();
const org = computed(() => ui.org);

const members = useMembers(org);
const addMember = useAddMember(org);

const open = ref(false);
const accountId = ref("");
const role = ref<OrgRole>("member");
const formError = ref<string | null>(null);

const roleLabel: Record<OrgRole, string> = {
  owner: t("members.roleOwner"),
  admin: t("members.roleAdmin"),
  member: t("members.roleMember"),
};

/** The account id must look like a typed id before we spend a round trip on it (§5.2). */
const accountIdLooksValid = computed(() => /^acc_[0-9abcdefghjkmnpqrstvwxyz]{26}$/.test(accountId.value.trim()));

function openDialog(): void {
  accountId.value = "";
  role.value = "member";
  formError.value = null;
  open.value = true;
}

watch(accountId, () => (formError.value = null));

async function submit(): Promise<void> {
  if (!accountIdLooksValid.value) {
    formError.value = t("members.accountIdHint");
    return;
  }
  formError.value = null;
  try {
    const member = await addMember.mutateAsync({ account_id: accountId.value.trim(), role: role.value });
    toast({
      title: t("members.added"),
      description: t("members.addedDescription", { email: member.email, role: roleLabel[member.role] }),
      variant: "success",
    });
    open.value = false;
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

/**
 * Org role assignments.
 *
 * The API lists assignments per member, not per role, so the dialog is opened from the member side
 * and fetches only that member's roles. The available select is the org's role list minus what is
 * already held, which makes a repeated assignment impossible to initiate from the UI.
 */
const rolesQuery = useOrgRoles(org);
const assignAccount = ref<Member | null>(null);
const rolesDialogOpen = ref(false);
const selectedRoleId = ref("");
const assignmentError = ref<string | null>(null);

const memberRoles = useMemberRoles(org, computed(() => assignAccount.value?.account_id ?? null));
const assignRole = useAssignOrgRole(org);
const unassignRole = useUnassignOrgRole(org);

const assignedRoles = computed(() => memberRoles.data.value?.items ?? []);
const availableRoles = computed(() =>
  (rolesQuery.data.value?.items ?? []).filter(
    (role) => !assignedRoles.value.some((assigned) => assigned.id === role.id),
  ),
);

watch(
  availableRoles,
  (roles) => {
    if (!roles.some((role) => role.id === selectedRoleId.value)) {
      selectedRoleId.value = roles[0]?.id ?? "";
    }
  },
  { immediate: true },
);

function openRoles(member: Member): void {
  assignAccount.value = member;
  selectedRoleId.value = "";
  assignmentError.value = null;
  rolesDialogOpen.value = true;
}

async function assignSelected(): Promise<void> {
  const account = assignAccount.value;
  if (!account || selectedRoleId.value.length === 0) return;
  assignmentError.value = null;
  try {
    await assignRole.mutateAsync({ accountId: account.account_id, role_id: selectedRoleId.value });
    const role = rolesQuery.data.value?.items.find((candidate) => candidate.id === selectedRoleId.value);
    toast({
      title: t("members.assigned"),
      description: t("members.assignedDescription", {
        role: role?.name ?? selectedRoleId.value,
        email: account.email,
      }),
      variant: "success",
    });
  } catch (error) {
    assignmentError.value = describeError(error).title;
  }
}

async function removeRole(role: OrgRoleDetail): Promise<void> {
  const account = assignAccount.value;
  if (!account) return;
  assignmentError.value = null;
  try {
    await unassignRole.mutateAsync({ accountId: account.account_id, roleId: role.id });
    toast({
      title: t("members.unassigned"),
      description: t("members.unassignedDescription", { role: role.name, email: account.email }),
      variant: "success",
    });
  } catch (error) {
    assignmentError.value = describeError(error).title;
  }
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('members.title')"
      :subtitle="t('members.subtitle', { org })"
      :stats="members.data.value ? [t('members.count', { count: members.data.value.items.length })] : []"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="members.refetch()">
          <RefreshCw :class="members.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openDialog">
          <Plus />
          {{ t('members.invite') }}
        </Button>
      </template>
    </PageHeader>

    <QueryBoundary
      :loading="members.isPending.value"
      :error="members.error.value"
      :empty="(members.data.value?.items.length ?? 0) === 0"
      :empty-title="t('members.empty')"
      :empty-hint="t('members.emptyHint')"
      :on-retry="() => members.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openDialog">
          <Plus />
          {{ t('members.invite') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('members.account') }}</TableHead>
            <TableHead>{{ t('members.email') }}</TableHead>
            <TableHead>{{ t('members.role') }}</TableHead>
            <TableHead>{{ t('members.accountId') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="member in members.data.value?.items ?? []" :key="member.account_id">
            <TableCell class="font-medium text-ink">{{ member.email.split('@')[0] }}</TableCell>
            <TableCell class="text-ink-muted">{{ member.email }}</TableCell>
            <TableCell>
              <Badge :variant="member.role === 'owner' ? 'brand' : member.role === 'admin' ? 'info' : 'muted'">
                {{ roleLabel[member.role] }}
              </Badge>
            </TableCell>
            <TableCell class="mono-data text-[11.5px] text-ink-faint">{{ member.account_id }}</TableCell>
            <TableCell>
              <div class="flex justify-end">
                <Button variant="secondary" size="xs" @click="openRoles(member)">
                  {{ t('members.orgRoles') }}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </QueryBoundary>

    <Dialog v-model:open="open">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('members.inviteTitle', { org }) }}</DialogTitle>
          <DialogDescription>{{ t('members.inviteDescription') }}</DialogDescription>
        </DialogHeader>

        <form class="flex flex-col gap-3.5" @submit.prevent="submit">
          <div class="flex flex-col gap-1.5">
            <Label for="member-account">{{ t('members.accountId') }}</Label>
            <Input
              id="member-account"
              v-model="accountId"
              :invalid="accountId.length > 0 && !accountIdLooksValid"
              placeholder="acc_01h455vb4pex5vsknk084sn02q"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('members.accountIdHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="member-role">{{ t('members.role') }}</Label>
            <NativeSelect id="member-role" v-model="role">
              <option value="member">{{ roleLabel.member }}</option>
              <option value="admin">{{ roleLabel.admin }}</option>
              <option value="owner">{{ roleLabel.owner }}</option>
            </NativeSelect>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="open = false">{{ t('common.cancel') }}</Button>
            <Button variant="primary" type="submit" :disabled="addMember.isPending.value">
              {{ addMember.isPending.value ? t('common.saving') : t('members.invite') }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="rolesDialogOpen">
      <DialogContent class="max-w-[520px]">
        <DialogHeader>
          <DialogTitle>{{ t('members.orgRolesTitle', { email: assignAccount?.email ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('members.orgRolesDescription', { org }) }}</DialogDescription>
        </DialogHeader>

        <div class="flex flex-col gap-2">
          <p v-if="memberRoles.isPending.value" class="text-[12.5px] text-ink-faint">
            {{ t('members.orgRolesLoading') }}
          </p>
          <p v-else-if="memberRoles.error.value" class="text-[12.5px] text-deny">
            {{ describeError(memberRoles.error.value).title }}
          </p>
          <p v-else-if="assignedRoles.length === 0" class="text-[12.5px] text-ink-faint">
            {{ t('members.orgRolesEmpty') }}
          </p>
          <div v-else class="divide-y divide-rule rounded-md border border-rule">
            <div v-for="role in assignedRoles" :key="role.id" class="flex items-center gap-2 px-2.5 py-2">
              <div class="min-w-0 flex-1">
                <span class="block text-[12.5px] font-medium text-ink">{{ role.name }}</span>
                <span class="mt-0.5 flex flex-wrap gap-1">
                  <ScopeBadge v-for="scope in role.scopes" :key="scope" :scope="scope" />
                </span>
              </div>
              <Button
                variant="secondary"
                size="xs"
                :disabled="unassignRole.isPending.value"
                @click="removeRole(role)"
              >
                {{ t('members.unassign') }}
              </Button>
            </div>
          </div>
        </div>

        <div class="flex flex-col gap-1.5 border-t border-rule pt-3">
          <div v-if="availableRoles.length > 0" class="flex items-end gap-2">
            <div class="flex min-w-0 flex-1 flex-col gap-1.5">
              <Label for="member-role-assign">{{ t('members.assignRole') }}</Label>
              <NativeSelect id="member-role-assign" v-model="selectedRoleId">
                <option v-for="role in availableRoles" :key="role.id" :value="role.id">{{ role.name }}</option>
              </NativeSelect>
            </div>
            <Button
              variant="primary"
              size="sm"
              :disabled="assignRole.isPending.value"
              @click="assignSelected"
            >
              {{ assignRole.isPending.value ? t('common.saving') : t('members.assign') }}
            </Button>
          </div>
          <p v-else class="text-[11.5px] text-ink-faint">{{ t('members.allRolesAssigned') }}</p>
          <p v-if="assignmentError" class="text-[12.5px] text-deny">{{ assignmentError }}</p>
        </div>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="rolesDialogOpen = false">{{ t('common.close') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
