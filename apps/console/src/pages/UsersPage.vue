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
import { Plus, RefreshCw, Search } from "lucide-vue-next";
import { computed, ref, watch } from "vue";
import { RouterLink } from "vue-router";

import { describeError } from "@/api/contract";
import type {
  AccountDeletion,
  AccountPasskey,
  AccountRole,
  AccountSession,
  AccountWithRoles,
} from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import {
  useAccount,
  useAccountSecurity,
  useAccountSessions,
  useAccounts,
  useAssignAccountRole,
  useCreateAccount,
  useDeleteAccount,
  useDeleteAccountPasskey,
  useResetAccountMfa,
  useRevokeAccountSession,
  useRevokeAccountSessions,
  useSession,
  useTenantRoles,
  useUnassignAccountRole,
  useUpdateAccount,
} from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Users — the tenant-wide account directory (§6.2).
 *
 * Distinct from Members: membership is per organization and is managed there. This page is where
 * an identity exists at all, and suspension is the tenant-wide lever: it revokes every session and
 * refresh token, which is why the confirmation says so rather than offering a silent toggle.
 */
const ui = useUiStore();
const session = useSession();
const canWrite = computed(() => {
  const tier = session.data.value?.management ?? "none";
  return tier === "write" || tier === "full";
});

const searchInput = ref("");
const appliedSearch = ref("");
const accounts = useAccounts(appliedSearch);
const createAccount = useCreateAccount();
const updateAccount = useUpdateAccount();

const rows = computed(() => accounts.data.value?.items ?? []);

function applySearch(): void {
  appliedSearch.value = searchInput.value.trim();
}

function clearSearch(): void {
  searchInput.value = "";
  appliedSearch.value = "";
}

// --- Create --------------------------------------------------------------------------------------

const createOpen = ref(false);
const email = ref("");
const displayName = ref("");
const password = ref("");
const formError = ref<string | null>(null);

const emailLooksValid = computed(() => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim()));

watch([email, displayName, password], () => (formError.value = null));

function openCreate(): void {
  email.value = "";
  displayName.value = "";
  password.value = "";
  formError.value = null;
  createOpen.value = true;
}

async function submit(): Promise<void> {
  if (!emailLooksValid.value) {
    formError.value = t("users.invalidEmail");
    return;
  }
  if (password.value.length === 0) {
    formError.value = t("users.invalidPassword");
    return;
  }
  formError.value = null;
  try {
    const created = await createAccount.mutateAsync({
      email: email.value.trim(),
      display_name: displayName.value.trim(),
      password: password.value,
    });
    toast({
      title: t("users.createdToast"),
      description: t("users.createdDescription", { email: created.email }),
      variant: "success",
    });
    createOpen.value = false;
  } catch (error) {
    formError.value = describeError(error).title;
  }
}

// --- Edit profile --------------------------------------------------------------------------------

const editOpen = ref(false);
const editTarget = ref<AccountWithRoles | null>(null);
const editName = ref("");
const editUsername = ref("");
const editAvatar = ref("");
const editError = ref<string | null>(null);
const editDetail = useAccount(computed(() => editTarget.value?.id ?? null));

watch(
  () => editDetail.data.value,
  (detail) => {
    if (!detail || editTarget.value === null || detail.id !== editTarget.value.id) return;
    editName.value = detail.display_name;
    editUsername.value = detail.username ?? "";
    editAvatar.value = detail.avatar_url ?? "";
  },
);

function openEdit(account: AccountWithRoles): void {
  editTarget.value = account;
  editName.value = account.display_name;
  editUsername.value = "";
  editAvatar.value = account.avatar_url ?? "";
  editError.value = null;
  editOpen.value = true;
}

async function submitEdit(): Promise<void> {
  const target = editTarget.value;
  if (!target) return;
  const name = editName.value.trim();
  if (name.length === 0 || name.length > 80) {
    editError.value = t("users.invalidDisplayName");
    return;
  }
  const username = editUsername.value.trim().toLowerCase();
  if (username !== "" && !/^[a-z0-9_-]{3,32}$/.test(username)) {
    editError.value = t("users.invalidUsername");
    return;
  }
  const avatar = editAvatar.value.trim();
  if (
    avatar !== "" &&
    (!/^https?:\/\/[^\s]+$/.test(avatar) || [...avatar].length > 2048)
  ) {
    editError.value = t("users.invalidAvatar");
    return;
  }
  editError.value = null;
  try {
    const updated = await updateAccount.mutateAsync({
      accountId: target.id,
      body: { display_name: name, username, avatar_url: avatar },
    });
    editOpen.value = false;
    toast({
      title: t("users.profileSavedToast"),
      description: t("users.profileSavedDescription", { email: updated.email }),
      variant: "success",
    });
  } catch (error) {
    const described = describeError(error);
    editError.value =
      described.code === "MONACA_USERNAME_TAKEN" ? t("users.usernameTaken") : described.title;
  }
}

// --- Delete -------------------------------------------------------------------------------------

const deleteOpen = ref(false);
const deleteTarget = ref<AccountWithRoles | null>(null);
const deletion = ref<AccountDeletion | null>(null);
const deleteConfirm = ref("");
const deleteError = ref<string | null>(null);
const removeAccount = useDeleteAccount();

async function openDelete(account: AccountWithRoles): Promise<void> {
  deleteTarget.value = account;
  deletion.value = null;
  deleteConfirm.value = "";
  deleteError.value = null;
  deleteOpen.value = true;
  try {
    deletion.value = await removeAccount.mutateAsync({ accountId: account.id });
  } catch (error) {
    deleteError.value = describeError(error).title;
  }
}

async function confirmDelete(): Promise<void> {
  const target = deleteTarget.value;
  if (!target) return;
  deleteError.value = null;
  try {
    await removeAccount.mutateAsync({ accountId: target.id, confirm: deleteConfirm.value });
    deleteOpen.value = false;
    toast({
      title: t("users.deletedToast"),
      description: t("users.deletedDescription", { email: target.email }),
      variant: "success",
    });
  } catch (error) {
    deleteError.value = describeError(error).title;
  }
}

// --- Suspend / reactivate -----------------------------------------------------------------------

const suspendOpen = ref(false);
const suspendTarget = ref<AccountWithRoles | null>(null);
const actionError = ref<string | null>(null);

function openSuspend(account: AccountWithRoles): void {
  suspendTarget.value = account;
  actionError.value = null;
  suspendOpen.value = true;
}

async function confirmSuspend(): Promise<void> {
  const target = suspendTarget.value;
  if (!target) return;
  actionError.value = null;
  try {
    const updated = await updateAccount.mutateAsync({
      accountId: target.id,
      body: { state: "disabled" },
    });
    suspendOpen.value = false;
    toast({
      title: t("users.suspendedToast"),
      description: t("users.suspendedDescription", { email: updated.email }),
      variant: "success",
    });
  } catch (error) {
    actionError.value = describeError(error).title;
  }
}

async function reactivate(account: AccountWithRoles): Promise<void> {
  try {
    const updated = await updateAccount.mutateAsync({
      accountId: account.id,
      body: { state: "active" },
    });
    toast({
      title: t("users.reactivatedToast"),
      description: t("users.reactivatedDescription", { email: updated.email }),
      variant: "success",
    });
  } catch (error) {
    toast({ title: t("users.actionFailed"), description: describeError(error).title, variant: "error" });
  }
}

function formatDate(at: string): string {
  const parsed = new Date(at);
  return Number.isNaN(parsed.getTime()) ? at : parsed.toISOString().slice(0, 10);
}

/**
 * Tenant roles, per account.
 *
 * There is no "list the holders of a role" endpoint: the directory row carries the roles an account
 * holds, so the dialog is opened from the account side and the available select is the role list
 * minus what is already held. That makes a repeated assignment impossible to start from the UI, and
 * the server treats one that arrives anyway as a no-op.
 */
const allRoles = useTenantRoles();
const assignAccountRole = useAssignAccountRole();
const unassignAccountRole = useUnassignAccountRole();

const rolesOpen = ref(false);
const rolesTarget = ref<AccountWithRoles | null>(null);
const selectedRoleId = ref("");
const rolesError = ref<string | null>(null);

/**
 * The account as the directory now reports it.
 *
 * `rolesTarget` is a snapshot taken when the dialog opened; after an assignment the query refetches
 * and this follows it, so the list in the open dialog is what the server will answer next.
 */
const currentRoles = computed(() => {
  const target = rolesTarget.value;
  if (!target) return [];
  return rows.value.find((account) => account.id === target.id)?.roles ?? target.roles;
});

const availableRoles = computed(() =>
  (allRoles.data.value?.items ?? []).filter(
    (role) => !currentRoles.value.some((held) => held.id === role.id),
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

function rolePermissions(roleId: string): string[] {
  return allRoles.data.value?.items.find((role) => role.id === roleId)?.permissions ?? [];
}

function openRoles(account: AccountWithRoles): void {
  rolesTarget.value = account;
  selectedRoleId.value = "";
  rolesError.value = null;
  rolesOpen.value = true;
}

async function assignSelected(): Promise<void> {
  const account = rolesTarget.value;
  if (!account || selectedRoleId.value.length === 0) return;
  rolesError.value = null;
  try {
    await assignAccountRole.mutateAsync({ accountId: account.id, roleId: selectedRoleId.value });
    const role = allRoles.data.value?.items.find((candidate) => candidate.id === selectedRoleId.value);
    toast({
      title: t("users.assigned"),
      description: t("users.assignedDescription", {
        role: role?.name ?? selectedRoleId.value,
        email: account.email,
      }),
      variant: "success",
    });
  } catch (error) {
    rolesError.value = describeError(error).title;
  }
}

async function removeRole(role: AccountRole): Promise<void> {
  const account = rolesTarget.value;
  if (!account) return;
  rolesError.value = null;
  try {
    await unassignAccountRole.mutateAsync({ accountId: account.id, roleId: role.id });
    toast({
      title: t("users.unassigned"),
      description: t("users.unassignedDescription", { role: role.name, email: account.email }),
      variant: "success",
    });
  } catch (error) {
    rolesError.value = describeError(error).title;
  }
}

/**
 * Live sessions.
 *
 * Fetched only while the dialog is open (`enabled` on the account id), because the directory page
 * should not pay for a request per row. Revoking one needs no confirmation — it is reversible by
 * signing in again — while "sign out everywhere" is destructive enough to deserve a dialog.
 */
const sessionsOpen = ref(false);
const sessionsTarget = ref<AccountWithRoles | null>(null);
const sessionsError = ref<string | null>(null);

const sessions = useAccountSessions(computed(() => sessionsTarget.value?.id ?? null));
const revokeSession = useRevokeAccountSession();
const revokeAllSessions = useRevokeAccountSessions();
const sessionRows = computed(() => sessions.data.value?.items ?? []);

const revokeAllOpen = ref(false);
const revokeAllTarget = ref<AccountWithRoles | null>(null);

function openSessions(account: AccountWithRoles): void {
  sessionsTarget.value = account;
  sessionsError.value = null;
  sessionsOpen.value = true;
}

async function revokeOne(session: AccountSession): Promise<void> {
  const account = sessionsTarget.value;
  if (!account) return;
  sessionsError.value = null;
  try {
    await revokeSession.mutateAsync({ accountId: account.id, sessionId: session.id });
    toast({
      title: t("users.revoked"),
      description: t("users.revokedDescription", {
        session: session.client_id ?? session.id,
      }),
      variant: "success",
    });
  } catch (error) {
    sessionsError.value = describeError(error).title;
  }
}

function openRevokeAll(): void {
  const account = sessionsTarget.value;
  if (!account) return;
  revokeAllTarget.value = account;
  sessionsError.value = null;
  revokeAllOpen.value = true;
}

async function confirmRevokeAll(): Promise<void> {
  const account = revokeAllTarget.value;
  if (!account) return;
  sessionsError.value = null;
  try {
    const result = await revokeAllSessions.mutateAsync({ accountId: account.id });
    revokeAllOpen.value = false;
    toast({
      title: t("users.signedOutEverywhere"),
      description: t("users.signedOutEverywhereDescription", { count: result.revoked }),
      variant: "success",
    });
  } catch (error) {
    sessionsError.value = describeError(error).title;
  }
}

/**
 * Enrolled second factors.
 *
 * The administrator sees presence, never a secret: whether an authenticator exists, how much of the
 * recovery-code set is left, and the passkeys with their labels. Resetting the authenticator is
 * destructive enough to be confirmed; removing one passkey is undone by enrolling another.
 */
const securityOpen = ref(false);
const securityTarget = ref<AccountWithRoles | null>(null);
const securityError = ref<string | null>(null);

const security = useAccountSecurity(computed(() => securityTarget.value?.id ?? null));
const resetMfa = useResetAccountMfa();
const deletePasskey = useDeleteAccountPasskey();
const resetMfaOpen = ref(false);

function openSecurity(account: AccountWithRoles): void {
  securityTarget.value = account;
  securityError.value = null;
  securityOpen.value = true;
}

function openResetMfa(): void {
  if (!securityTarget.value) return;
  securityError.value = null;
  resetMfaOpen.value = true;
}

async function confirmResetMfa(): Promise<void> {
  const account = securityTarget.value;
  if (!account) return;
  securityError.value = null;
  try {
    await resetMfa.mutateAsync({ accountId: account.id });
    resetMfaOpen.value = false;
    toast({
      title: t("users.mfaReset"),
      description: t("users.mfaResetDescription", { email: account.email }),
      variant: "success",
    });
  } catch (error) {
    securityError.value = describeError(error).title;
  }
}

async function removePasskey(passkey: AccountPasskey): Promise<void> {
  const account = securityTarget.value;
  if (!account) return;
  securityError.value = null;
  try {
    await deletePasskey.mutateAsync({ accountId: account.id, passkeyId: passkey.id });
    toast({
      title: t("users.passkeyRemoved"),
      description: t("users.passkeyRemovedDescription", {
        name: passkey.name ?? t("users.passkeyFallback"),
      }),
      variant: "success",
    });
  } catch (error) {
    securityError.value = describeError(error).title;
  }
}

function formatDateTime(at: string): string {
  const parsed = new Date(at);
  return Number.isNaN(parsed.getTime())
    ? at
    : `${parsed.toISOString().slice(0, 10)} ${parsed.toISOString().slice(11, 16)}`;
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('users.title')"
      :subtitle="t('users.subtitle', { tenant: ui.tenant })"
      :stats="[t('users.count', { count: rows.length })]"
    >
      <template #actions>
        <Button variant="ghost" size="sm" @click="accounts.refetch()">
          <RefreshCw :class="accounts.isFetching.value ? 'animate-spin' : ''" />
          {{ t('common.refresh') }}
        </Button>
        <Button variant="primary" size="sm" @click="openCreate">
          <Plus />
          {{ t('users.create') }}
        </Button>
      </template>
    </PageHeader>

    <form class="flex items-center gap-2" @submit.prevent="applySearch">
      <Input
        v-model="searchInput"
        :placeholder="t('users.searchPlaceholder')"
        autocomplete="off"
        spellcheck="false"
        class="max-w-[320px]"
      />
      <Button variant="secondary" size="sm" type="submit">
        <Search />
        {{ t('common.search') }}
      </Button>
      <Button v-if="appliedSearch" variant="ghost" size="sm" type="button" @click="clearSearch">
        {{ t('users.clearSearch') }}
      </Button>
    </form>

    <QueryBoundary
      :loading="accounts.isPending.value"
      :error="accounts.error.value"
      :empty="rows.length === 0"
      :empty-title="t('users.empty')"
      :empty-hint="t('users.emptyHint')"
      :on-retry="() => accounts.refetch()"
    >
      <template #empty-action>
        <Button variant="primary" size="sm" class="mt-2" @click="openCreate">
          <Plus />
          {{ t('users.create') }}
        </Button>
      </template>

      <Table>
        <TableHeader>
          <TableRow class="hover:bg-transparent">
            <TableHead>{{ t('users.name') }}</TableHead>
            <TableHead>{{ t('users.state') }}</TableHead>
            <TableHead>{{ t('users.roles') }}</TableHead>
            <TableHead>{{ t('users.created') }}</TableHead>
            <TableHead class="w-[1%]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="account in rows" :key="account.id">
            <TableCell class="max-w-[280px]">
              <span class="block truncate font-medium text-ink">
                {{ account.display_name || account.email }}
              </span>
              <span class="mt-0.5 block truncate text-[11.5px] text-ink-faint">{{ account.email }}</span>
            </TableCell>
            <TableCell>
              <Badge :variant="account.state === 'active' ? 'allow' : 'deny'">
                {{ account.state === "active" ? t("users.stateActive") : t("users.stateDisabled") }}
              </Badge>
            </TableCell>
            <TableCell>
              <span v-if="account.roles.length > 0" class="flex flex-wrap gap-1">
                <Badge v-for="role in account.roles" :key="role.id" variant="muted">{{ role.name }}</Badge>
              </span>
              <span v-else class="text-[11.5px] text-ink-faint">{{ t('users.noRoles') }}</span>
            </TableCell>
            <TableCell class="mono-data whitespace-nowrap text-[11.5px] text-ink-faint">
              {{ formatDate(account.created_at) }}
            </TableCell>
            <TableCell>
              <div class="flex justify-end gap-1.5">
                <Button variant="secondary" size="xs" @click="openEdit(account)">
                  {{ t('users.edit') }}
                </Button>
                <Button variant="secondary" size="xs" @click="openRoles(account)">
                  {{ t('users.manageRoles') }}
                </Button>
                <Button variant="secondary" size="xs" @click="openSessions(account)">
                  {{ t('users.sessions') }}
                </Button>
                <Button variant="secondary" size="xs" @click="openSecurity(account)">
                  {{ t('users.security') }}
                </Button>
                <Button
                  v-if="account.state === 'active'"
                  variant="secondary"
                  size="xs"
                  :disabled="!canWrite || updateAccount.isPending.value"
                  @click="openSuspend(account)"
                >
                  {{ t('users.suspend') }}
                </Button>
                <Button
                  v-else
                  variant="secondary"
                  size="xs"
                  :disabled="!canWrite || updateAccount.isPending.value"
                  @click="reactivate(account)"
                >
                  {{ t('users.reactivate') }}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  :disabled="!canWrite || removeAccount.isPending.value"
                  @click="openDelete(account)"
                >
                  {{ t('users.delete') }}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </QueryBoundary>

    <Dialog v-model:open="createOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('users.createTitle') }}</DialogTitle>
          <DialogDescription>{{ t('users.createDescription') }}</DialogDescription>
        </DialogHeader>

        <form class="flex flex-col gap-3.5" @submit.prevent="submit">
          <div class="flex flex-col gap-1.5">
            <Label for="user-email">{{ t('users.emailField') }}</Label>
            <Input
              id="user-email"
              v-model="email"
              :invalid="email.length > 0 && !emailLooksValid"
              placeholder="ada@example.com"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('users.emailHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="user-name">{{ t('users.displayNameField') }}</Label>
            <Input
              id="user-name"
              v-model="displayName"
              placeholder="Ada Lovelace"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('users.displayNameHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="user-password">{{ t('users.passwordField') }}</Label>
            <Input
              id="user-password"
              v-model="password"
              type="password"
              :aria-label="t('users.passwordField')"
              autocomplete="new-password"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('users.passwordHint') }}</p>
          </div>

          <p v-if="formError" class="text-[12.5px] text-deny">{{ formError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="createOpen = false">{{ t('common.cancel') }}</Button>
            <Button variant="primary" type="submit" :disabled="createAccount.isPending.value">
              {{ createAccount.isPending.value ? t('common.saving') : t('users.create') }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="editOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('users.editTitle') }}</DialogTitle>
          <DialogDescription>
            {{ t('users.editDescription', { email: editTarget?.email ?? '' }) }}
          </DialogDescription>
        </DialogHeader>

        <form class="flex flex-col gap-3.5" @submit.prevent="submitEdit">
          <div class="flex flex-col gap-1.5">
            <Label for="user-edit-name">{{ t('users.displayNameField') }}</Label>
            <Input
              id="user-edit-name"
              v-model="editName"
              :invalid="editName.trim().length === 0 || editName.trim().length > 80"
              autocomplete="off"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">
              {{ t('users.editDisplayNameHint') }}
            </p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="user-edit-username">{{ t('users.usernameField') }}</Label>
            <Input
              id="user-edit-username"
              v-model="editUsername"
              :invalid="editUsername.trim() !== '' && !/^[a-z0-9_-]{3,32}$/.test(editUsername.trim().toLowerCase())"
              placeholder="e.g. ada"
              autocomplete="off"
              spellcheck="false"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('users.usernameHint') }}</p>
          </div>

          <div class="flex flex-col gap-1.5">
            <Label for="user-edit-avatar">{{ t('users.avatarField') }}</Label>
            <Input
              id="user-edit-avatar"
              v-model="editAvatar"
              type="url"
              inputmode="url"
              :invalid="editAvatar.trim() !== '' && (!/^https?:\/\/[^\s]+$/.test(editAvatar.trim()) || [...editAvatar.trim()].length > 2048)"
              placeholder="https://cdn.example/ada.png"
              autocomplete="off"
              spellcheck="false"
              class="mono-data text-[12.5px]"
            />
            <p class="text-[11.5px] leading-snug text-ink-faint">{{ t('users.avatarHint') }}</p>
          </div>

          <p v-if="editError" class="text-[12.5px] text-deny">{{ editError }}</p>

          <DialogFooter>
            <Button variant="ghost" type="button" @click="editOpen = false">{{ t('common.cancel') }}</Button>
            <Button variant="primary" type="submit" :disabled="updateAccount.isPending.value">
              {{ updateAccount.isPending.value ? t('common.saving') : t('users.saveProfile') }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="suspendOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{{ t('users.suspendTitle', { email: suspendTarget?.email ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('users.suspendDescription') }}</DialogDescription>
        </DialogHeader>

        <p v-if="actionError" class="text-[12.5px] text-deny">{{ actionError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="suspendOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="updateAccount.isPending.value" @click="confirmSuspend">
            {{ updateAccount.isPending.value ? t('common.saving') : t('users.suspend') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="deleteOpen">
      <DialogContent class="max-w-[460px]">
        <DialogHeader>
          <DialogTitle>{{ t('users.deleteTitle', { email: deleteTarget?.email ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('users.deleteHint') }}</DialogDescription>
        </DialogHeader>

        <p v-if="deletion === null && deleteError === null" class="text-[12.5px] text-ink-muted">
          {{ t('users.deleteDryRun') }}
        </p>
        <p v-if="deletion" class="text-[12.5px] text-ink-muted">
          {{
            t('users.deleteCounts', {
              sessions: deletion.sessions,
              tokens: deletion.refresh_tokens,
            })
          }}
        </p>
        <p class="text-[12.5px] text-deny">{{ t('users.deletePermanent') }}</p>

        <div class="flex flex-col gap-1.5">
          <Label for="delete-confirm">{{ t('users.deleteConfirmField') }}</Label>
          <Input id="delete-confirm" v-model="deleteConfirm" autocomplete="off" />
        </div>

        <p v-if="deleteError" class="text-[12.5px] text-deny">{{ deleteError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="deleteOpen = false">{{ t('common.cancel') }}</Button>
          <Button
            variant="danger"
            type="button"
            :disabled="
              !canWrite ||
              removeAccount.isPending.value ||
              deleteTarget === null ||
              deleteConfirm.trim().toLowerCase() !== (deleteTarget?.email ?? '').toLowerCase()
            "
            @click="confirmDelete"
          >
            {{ removeAccount.isPending.value ? t('common.saving') : t('users.deleteConfirm') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="rolesOpen">
      <DialogContent class="max-w-[520px]">
        <DialogHeader>
          <DialogTitle>{{ t('users.rolesTitle', { email: rolesTarget?.email ?? '' }) }}</DialogTitle>
          <DialogDescription>{{ t('users.rolesDescription', { email: rolesTarget?.email ?? '' }) }}</DialogDescription>
        </DialogHeader>

        <div class="flex flex-col gap-2">
          <p v-if="allRoles.isPending.value" class="text-[12.5px] text-ink-faint">
            {{ t('users.rolesLoading') }}
          </p>
          <p v-else-if="allRoles.error.value" class="text-[12.5px] text-deny">
            {{ describeError(allRoles.error.value).title }}
          </p>
          <p v-else-if="currentRoles.length === 0" class="text-[12.5px] text-ink-faint">
            {{ t('users.rolesEmpty') }}
          </p>
          <div v-else class="divide-y divide-rule rounded-md border border-rule">
            <div v-for="role in currentRoles" :key="role.id" class="flex items-center gap-2 px-2.5 py-2">
              <div class="min-w-0 flex-1">
                <span class="block text-[12.5px] font-medium text-ink">{{ role.name }}</span>
                <span v-if="rolePermissions(role.id).length > 0" class="mt-0.5 flex flex-wrap gap-1">
                  <ScopeBadge v-for="permission in rolePermissions(role.id)" :key="permission" :scope="permission" />
                </span>
              </div>
              <Button
                variant="secondary"
                size="xs"
                :disabled="unassignAccountRole.isPending.value"
                @click="removeRole(role)"
              >
                {{ t('users.unassign') }}
              </Button>
            </div>
          </div>
        </div>

        <div class="flex flex-col gap-2 border-t border-rule pt-3">
          <div v-if="availableRoles.length > 0" class="flex items-end gap-2">
            <div class="flex min-w-0 flex-1 flex-col gap-1.5">
              <Label for="account-role-assign">{{ t('users.assignRole') }}</Label>
              <NativeSelect id="account-role-assign" v-model="selectedRoleId">
                <option v-for="role in availableRoles" :key="role.id" :value="role.id">{{ role.name }}</option>
              </NativeSelect>
            </div>
            <Button
              variant="primary"
              size="sm"
              :disabled="assignAccountRole.isPending.value"
              @click="assignSelected"
            >
              {{ assignAccountRole.isPending.value ? t('common.saving') : t('users.assign') }}
            </Button>
          </div>
          <p v-else class="text-[11.5px] text-ink-faint">{{ t('users.allRolesAssigned') }}</p>
          <p v-if="rolesError" class="text-[12.5px] text-deny">{{ rolesError }}</p>
          <RouterLink
            :to="{ name: 'tenant-roles' }"
            class="text-[11.5px] text-brand-ink underline decoration-brand/40 underline-offset-4 hover:decoration-brand"
          >
            {{ t('users.manageDefinitions') }}
          </RouterLink>
        </div>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="rolesOpen = false">{{ t('common.close') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="securityOpen">
      <DialogContent class="max-w-[560px]">
        <DialogHeader>
          <DialogTitle>{{ t('users.securityTitle', { email: securityTarget?.email ?? '' }) }}</DialogTitle>
          <DialogDescription>
            {{ t('users.securityDescription', { email: securityTarget?.email ?? '' }) }}
          </DialogDescription>
        </DialogHeader>

        <div class="flex flex-col gap-3">
          <p v-if="security.isPending.value" class="text-[12.5px] text-ink-faint">
            {{ t('common.loading') }}
          </p>
          <p v-else-if="security.error.value" class="text-[12.5px] text-deny">
            {{ describeError(security.error.value).title }}
          </p>
          <div v-else-if="security.data.value" class="flex flex-col gap-3">
            <div class="rounded-md border border-rule px-3 py-2.5">
              <div class="flex items-center justify-between gap-3">
                <span class="text-[12.5px] font-medium text-ink">{{ t('users.mfaTotp') }}</span>
                <Badge :variant="security.data.value.mfa.totp ? 'allow' : 'muted'">
                  {{ security.data.value.mfa.totp ? t('users.mfaOn') : t('users.mfaOff') }}
                </Badge>
              </div>
              <p class="mt-1 text-[11.5px] leading-snug text-ink-faint">
                {{ t('users.mfaBackupCodes', { count: security.data.value.mfa.backup_codes }) }}
                ·
                {{ t('users.trustedDevices', { count: security.data.value.trusted_devices }) }}
              </p>
              <p class="mt-1.5 text-[11.5px] leading-snug text-ink-faint">{{ t('users.mfaResetHint') }}</p>
              <Button
                variant="secondary"
                size="xs"
                class="mt-2"
                :disabled="!security.data.value.mfa.totp || resetMfa.isPending.value"
                @click="openResetMfa"
              >
                {{ t('users.mfaReset') }}
              </Button>
            </div>

            <div class="flex flex-col gap-1.5">
              <span class="text-[12.5px] font-medium text-ink">{{ t('users.passkeys') }}</span>
              <p v-if="security.data.value.passkeys.length === 0" class="text-[11.5px] text-ink-faint">
                {{ t('users.passkeysEmpty') }}
              </p>
              <div v-else class="divide-y divide-rule rounded-md border border-rule">
                <div
                  v-for="passkey in security.data.value.passkeys"
                  :key="passkey.id"
                  class="flex items-start gap-3 px-2.5 py-2"
                >
                  <div class="min-w-0 flex-1">
                    <span class="block truncate text-[12px] font-medium text-ink">
                      {{ passkey.name ?? t('users.passkeyFallback') }}
                    </span>
                    <span class="mt-0.5 flex flex-wrap gap-x-3 text-[11px] text-ink-faint">
                      <span>{{ t('users.passkeyCreated') }} {{ formatDateTime(passkey.created_at) }}</span>
                      <span v-if="passkey.last_used_at">
                        {{ t('users.passkeyLastUsed') }} {{ formatDateTime(passkey.last_used_at) }}
                      </span>
                    </span>
                  </div>
                  <Button
                    variant="secondary"
                    size="xs"
                    :disabled="deletePasskey.isPending.value"
                    @click="removePasskey(passkey)"
                  >
                    {{ t('users.passkeyRemove') }}
                  </Button>
                </div>
              </div>
            </div>
          </div>
          <p v-if="securityError" class="text-[12.5px] text-deny">{{ securityError }}</p>
        </div>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="securityOpen = false">{{ t('common.close') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="resetMfaOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>
            {{ t('users.mfaResetTitle', { email: securityTarget?.email ?? '' }) }}
          </DialogTitle>
          <DialogDescription>
            {{ t('users.mfaResetConfirmDescription', { email: securityTarget?.email ?? '' }) }}
          </DialogDescription>
        </DialogHeader>

        <p v-if="securityError" class="text-[12.5px] text-deny">{{ securityError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="resetMfaOpen = false">{{ t('common.cancel') }}</Button>
          <Button variant="danger" type="button" :disabled="resetMfa.isPending.value" @click="confirmResetMfa">
            {{ resetMfa.isPending.value ? t('common.saving') : t('users.mfaReset') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="sessionsOpen">
      <DialogContent class="max-w-[560px]">
        <DialogHeader>
          <DialogTitle>{{ t('users.sessionsTitle', { email: sessionsTarget?.email ?? '' }) }}</DialogTitle>
          <DialogDescription>
            {{ t('users.sessionsDescription', { email: sessionsTarget?.email ?? '' }) }}
          </DialogDescription>
        </DialogHeader>

        <div class="flex flex-col gap-2">
          <p v-if="sessions.isPending.value" class="text-[12.5px] text-ink-faint">
            {{ t('users.sessionsLoading') }}
          </p>
          <p v-else-if="sessions.error.value" class="text-[12.5px] text-deny">
            {{ describeError(sessions.error.value).title }}
          </p>
          <p v-else-if="sessionRows.length === 0" class="text-[12.5px] text-ink-faint">
            {{ t('users.sessionsEmpty') }}
          </p>
          <div v-else class="divide-y divide-rule rounded-md border border-rule">
            <div
              v-for="session in sessionRows"
              :key="session.id"
              class="flex items-start gap-3 px-2.5 py-2"
            >
              <div class="min-w-0 flex-1">
                <span class="mono-data block truncate text-[11.5px] text-ink">{{ session.id }}</span>
                <span
                  class="mt-0.5 block truncate text-[11.5px] text-ink-muted"
                  :title="session.user_agent ?? t('users.unknownAgent')"
                >
                  {{ session.user_agent ?? t('users.unknownAgent') }}
                </span>
                <span class="mt-0.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-ink-faint">
                  <span>{{ t('users.sessionLastSeen') }} {{ formatDateTime(session.last_seen_at) }}</span>
                  <span>{{ t('users.sessionExpires') }} {{ formatDateTime(session.expires_at) }}</span>
                  <span class="mono-data">{{ session.client_id ?? t('users.unknownClient') }}</span>
                </span>
              </div>
              <Button
                variant="secondary"
                size="xs"
                :disabled="revokeSession.isPending.value"
                @click="revokeOne(session)"
              >
                {{ t('users.revokeSession') }}
              </Button>
            </div>
          </div>
          <p v-if="sessionsError" class="text-[12.5px] text-deny">{{ sessionsError }}</p>
        </div>

        <DialogFooter>
          <Button
            variant="secondary"
            type="button"
            :disabled="sessionRows.length === 0 || revokeAllSessions.isPending.value"
            @click="openRevokeAll"
          >
            {{ t('users.signOutEverywhere') }}
          </Button>
          <Button variant="ghost" type="button" @click="sessionsOpen = false">{{ t('common.close') }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="revokeAllOpen">
      <DialogContent class="max-w-[440px]">
        <DialogHeader>
          <DialogTitle>
            {{ t('users.signOutEverywhereTitle', { email: revokeAllTarget?.email ?? '' }) }}
          </DialogTitle>
          <DialogDescription>
            {{ t('users.signOutEverywhereDescription', { email: revokeAllTarget?.email ?? '' }) }}
          </DialogDescription>
        </DialogHeader>

        <p v-if="sessionsError" class="text-[12.5px] text-deny">{{ sessionsError }}</p>

        <DialogFooter>
          <Button variant="ghost" type="button" @click="revokeAllOpen = false">{{ t('common.cancel') }}</Button>
          <Button
            variant="danger"
            type="button"
            :disabled="revokeAllSessions.isPending.value"
            @click="confirmRevokeAll"
          >
            {{ revokeAllSessions.isPending.value ? t('common.saving') : t('users.signOutEverywhere') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
