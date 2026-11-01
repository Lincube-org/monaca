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
import { Plus, RefreshCw, Search } from "lucide-vue-next";
import { computed, ref, watch } from "vue";

import { describeError } from "@/api/contract";
import type { AccountWithRoles } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import QueryBoundary from "@/components/QueryBoundary.vue";
import { t } from "@/i18n";
import { useAccounts, useCreateAccount, useUpdateAccount } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Users — the tenant-wide account directory (§6.2).
 *
 * Distinct from Members: membership is per organization and is managed there. This page is where
 * an identity exists at all, and suspension is the tenant-wide lever: it revokes every session and
 * refresh token, which is why the confirmation says so rather than offering a silent toggle.
 */
const ui = useUiStore();

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
              <div class="flex justify-end">
                <Button
                  v-if="account.state === 'active'"
                  variant="secondary"
                  size="xs"
                  :disabled="updateAccount.isPending.value"
                  @click="openSuspend(account)"
                >
                  {{ t('users.suspend') }}
                </Button>
                <Button
                  v-else
                  variant="secondary"
                  size="xs"
                  :disabled="updateAccount.isPending.value"
                  @click="reactivate(account)"
                >
                  {{ t('users.reactivate') }}
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
  </div>
</template>
