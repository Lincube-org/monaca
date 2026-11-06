<script setup lang="ts">
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
  NativeSelect,
  toast,
} from "@monaca/ui";
import { RefreshCw } from "lucide-vue-next";
import { computed, reactive, watch } from "vue";

import { describeError } from "@/api/contract";
import type { DeliveryConnector } from "@/api/types";
import PageHeader from "@/components/PageHeader.vue";
import { t } from "@/i18n";
import {
  useDeleteDeliveryConnector,
  useDeliveryConnector,
  useSession,
  useUpdateDeliveryConnector,
} from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * Delivery connectors — how the tenant sends mail and SMS (§6.2).
 *
 * The secret is write-only: the read reports `secret_set`, and saving with an empty secret keeps
 * the stored one. Removing the route is the explicit way to drop the credential.
 */
type Channel = "email" | "sms";

interface Form {
  provider: string;
  endpoint: string;
  from_address: string;
  from_name: string;
  secret: string;
  enabled: boolean;
}

const ui = useUiStore();
const session = useSession();
const canWrite = computed(() => {
  const tier = session.data.value?.management ?? "none";
  return tier === "write" || tier === "full";
});

const email = useDeliveryConnector("email");
const sms = useDeliveryConnector("sms");
const update = useUpdateDeliveryConnector();
const remove = useDeleteDeliveryConnector();

const channels = computed(() =>
  [
    { key: "email" as const, title: t("delivery.email"), query: email },
    { key: "sms" as const, title: t("delivery.sms"), query: sms },
  ],
);

const forms = reactive<Record<Channel, Form>>({
  email: { provider: "http", endpoint: "", from_address: "", from_name: "", secret: "", enabled: true },
  sms: { provider: "http", endpoint: "", from_address: "", from_name: "", secret: "", enabled: true },
});
const targets = reactive<Record<Channel, DeliveryConnector | null>>({ email: null, sms: null });

function adopt(channel: Channel, connector: DeliveryConnector): void {
  targets[channel] = connector;
  forms[channel].provider = connector.provider ?? (channel === "email" ? "http" : "http");
  forms[channel].endpoint = connector.endpoint ?? "";
  forms[channel].from_address = connector.from_address ?? "";
  forms[channel].from_name = connector.from_name ?? "";
  forms[channel].secret = "";
  forms[channel].enabled = connector.enabled;
}

watch(
  () => email.data.value,
  (value) => {
    if (value) adopt("email", value);
  },
  { immediate: true },
);
watch(
  () => sms.data.value,
  (value) => {
    if (value) adopt("sms", value);
  },
  { immediate: true },
);

async function save(channel: Channel): Promise<void> {
  const form = forms[channel];
  if (form.provider.trim() === "" || form.endpoint.trim() === "" || form.from_address.trim() === "") {
    toast({ title: t("delivery.invalid"), variant: "error" });
    return;
  }
  const body: {
    provider: string;
    endpoint: string;
    from_address: string;
    from_name: string | null;
    enabled: boolean;
    secret?: string;
  } = {
    provider: form.provider.trim(),
    endpoint: form.endpoint.trim(),
    from_address: form.from_address.trim(),
    from_name: form.from_name.trim() === "" ? null : form.from_name.trim(),
    enabled: form.enabled,
  };
  if (form.secret.trim() !== "") body.secret = form.secret.trim();
  try {
    const updated = await update.mutateAsync({ channel, body });
    adopt(channel, updated);
    toast({
      title: t("delivery.saved"),
      description: t("delivery.savedDescription", { channel }),
      variant: "success",
    });
  } catch (error) {
    toast({ title: t("delivery.saveFailed"), description: describeError(error).title, variant: "error" });
  }
}

async function removeRoute(channel: Channel): Promise<void> {
  try {
    await remove.mutateAsync(channel);
    const current = channel === "email" ? email : sms;
    await current.refetch();
    toast({
      title: t("delivery.removed"),
      description: t("delivery.removedDescription", { channel }),
      variant: "success",
    });
  } catch (error) {
    toast({ title: t("delivery.removeFailed"), description: describeError(error).title, variant: "error" });
  }
}
</script>

<template>
  <div class="flex flex-col gap-5">
    <PageHeader
      :title="t('delivery.title')"
      :subtitle="t('delivery.subtitle', { tenant: ui.tenant })"
    />

    <Card v-if="!canWrite">
      <CardContent class="pt-4 text-[13px] text-ink-muted">
        <Badge variant="muted">{{ t("tenant.readOnly") }}</Badge>
        <span class="ml-2">{{ t("tenant.readOnlyHint") }}</span>
      </CardContent>
    </Card>

    <Card v-for="channel in channels" :key="channel.key">
      <CardHeader class="flex-row items-center justify-between">
        <div>
          <CardTitle>{{ channel.title }}</CardTitle>
          <CardDescription>
            <Badge :variant="targets[channel.key]?.configured ? 'allow' : 'muted'">
              {{
                targets[channel.key]?.configured
                  ? t("delivery.configured")
                  : t("delivery.notConfigured")
              }}
            </Badge>
          </CardDescription>
        </div>
        <div class="flex items-center gap-1.5">
          <Button variant="ghost" size="sm" @click="channel.query.refetch()">
            <RefreshCw :class="channel.query.isFetching.value ? 'animate-spin' : ''" />
            {{ t("common.refresh") }}
          </Button>
          <Button
            v-if="targets[channel.key]?.configured"
            variant="ghost"
            size="sm"
            :disabled="!canWrite || remove.isPending.value"
            @click="removeRoute(channel.key)"
          >
            {{ t("delivery.remove") }}
          </Button>
        </div>
      </CardHeader>
      <CardContent class="flex flex-col gap-3">
        <p v-if="channel.query.isPending.value" class="m-0 text-[12.5px] text-ink-muted">
          {{ t("common.loading") }}
        </p>
        <div v-else-if="channel.query.error.value" class="flex items-center gap-2 text-[12.5px] text-deny">
          <span>{{ describeError(channel.query.error.value).title }}</span>
          <Button variant="secondary" size="sm" @click="channel.query.refetch()">
            {{ t("common.retry") }}
          </Button>
        </div>
        <div v-else class="grid gap-3 md:grid-cols-2">
            <div class="flex flex-col gap-1.5">
              <Label :for="`${channel.key}-provider`">{{ t("delivery.provider") }}</Label>
              <NativeSelect
                :id="`${channel.key}-provider`"
                v-model="forms[channel.key].provider"
                :disabled="!canWrite"
              >
                <option value="http">http</option>
                <option v-if="channel.key === 'email'" value="smtp">smtp</option>
                <option v-if="channel.key === 'sms'" value="twilio">twilio</option>
              </NativeSelect>
            </div>
            <div class="flex flex-col gap-1.5">
              <Label :for="`${channel.key}-from`">{{ t("delivery.fromAddress") }}</Label>
              <Input
                :id="`${channel.key}-from`"
                v-model="forms[channel.key].from_address"
                :disabled="!canWrite"
                placeholder="notifications@example.com"
              />
            </div>
            <div class="flex flex-col gap-1.5 md:col-span-2">
              <Label :for="`${channel.key}-endpoint`">{{ t("delivery.endpoint") }}</Label>
              <Input
                :id="`${channel.key}-endpoint`"
                v-model="forms[channel.key].endpoint"
                :disabled="!canWrite"
                placeholder="https://provider.example/send"
              />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label :for="`${channel.key}-name`">{{ t("delivery.fromName") }}</Label>
              <Input
                :id="`${channel.key}-name`"
                v-model="forms[channel.key].from_name"
                :disabled="!canWrite"
              />
            </div>
            <div class="flex flex-col gap-1.5">
              <Label :for="`${channel.key}-secret`">
                {{ t("delivery.secret") }}
                <span v-if="targets[channel.key]?.secret_set" class="text-ink-faint">
                  · {{ t("delivery.secretSet") }}
                </span>
              </Label>
              <Input
                :id="`${channel.key}-secret`"
                v-model="forms[channel.key].secret"
                :disabled="!canWrite"
                type="password"
                autocomplete="off"
              />
              <p class="m-0 text-[11.5px] text-ink-faint">{{ t("delivery.secretHint") }}</p>
            </div>
            <div class="mt-1 flex items-center gap-2 md:col-span-2">
              <input
                :id="`${channel.key}-enabled`"
                v-model="forms[channel.key].enabled"
                type="checkbox"
                :disabled="!canWrite"
                class="size-4 rounded border-line"
              />
              <Label :for="`${channel.key}-enabled`">{{ t("delivery.enabled") }}</Label>
              <Button
                class="ml-auto"
                variant="primary"
                size="sm"
                :disabled="!canWrite || update.isPending.value"
                @click="save(channel.key)"
              >
                {{ t("delivery.save") }}
              </Button>
            </div>
          </div>
      </CardContent>
    </Card>
  </div>
</template>
