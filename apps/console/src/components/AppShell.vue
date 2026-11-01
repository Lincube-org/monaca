<script setup lang="ts">
import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  SidebarNav,
  SidebarNavItem,
  Toaster,
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@monaca/ui";
import { useQueryClient } from "@tanstack/vue-query";
import {
  AppWindow,
  Bot,
  Boxes,
  Building2,
  Check,
  ChevronsUpDown,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Plug,
  ScrollText,
  Settings,
  ShieldCheck,
  Sun,
  UserRound,
  Users,
} from "lucide-vue-next";
import { computed, onMounted, type Component } from "vue";
import { RouterLink, RouterView, useRoute } from "vue-router";

import { USE_MOCKS } from "@/api";
import { useTheme } from "@/composables/use-theme";
import { t } from "@/i18n";
import { useSession } from "@/queries";
import { useUiStore } from "@/stores/ui";

/**
 * The console shell.
 *
 * Layout concept: a fixed rail carrying identity (org switcher), navigation, and a persistent
 * footer of ground truth — who you are, whether the data is real, and the theme. Content is a
 * single full-bleed column. No card grid and no floating chrome: density is the point here, and a
 * border is only ever drawn where it encodes a boundary.
 *
 * The org switcher deliberately shows the tenant *above* the organization. A console that hides
 * which tenant you are editing is a console that lets you edit the wrong one, and in this product
 * cross-tenant mistakes are the expensive kind.
 */
const ui = useUiStore();
const route = useRoute();
const client = useQueryClient();
const { resolved, apply } = useTheme(() => ui.theme);
const session = useSession();

const email = computed(() => session.data.value?.email ?? t("common.unknown"));
const orgs = computed(() => session.data.value?.orgs ?? []);

const navItems: { name: string; label: string; icon: Component }[] = [
  { name: "overview", label: t("nav.overview"), icon: LayoutDashboard },
  { name: "organizations", label: t("nav.organizations"), icon: Building2 },
  { name: "applications", label: t("nav.applications"), icon: AppWindow },
  { name: "resources", label: t("nav.resources"), icon: Boxes },
  { name: "users", label: t("nav.users"), icon: UserRound },
  { name: "members", label: t("nav.members"), icon: Users },
  { name: "roles", label: t("nav.roles"), icon: ShieldCheck },
  { name: "connectors", label: t("nav.connectors"), icon: Plug },
  { name: "agents", label: t("nav.agents"), icon: Bot },
  { name: "grants", label: t("nav.grants"), icon: KeyRound },
  { name: "audit", label: t("nav.audit"), icon: ScrollText },
  { name: "settings", label: t("nav.settings"), icon: Settings },
];

/** The route name drives the active marker, so a detail route keeps its section lit. */
const activeName = computed(() => String(route.name ?? ""));

function setTheme(choice: "system" | "light" | "dark"): void {
  ui.setTheme(choice);
  apply();
}

async function signOut(): Promise<void> {
  try {
    await fetch("/bff/logout", { method: "POST", credentials: "same-origin" });
  } catch {
    // A failed sign-out must not trap the user in a shell they explicitly asked to leave.
  }
  client.clear();
  window.location.href = "/bff/login";
}

onMounted(apply);
</script>

<template>
  <TooltipProvider>
    <div class="flex h-full min-h-screen bg-paper text-ink">
      <aside
        class="sticky top-0 z-30 hidden h-screen shrink-0 flex-col border-r border-rule bg-surface transition-[width] duration-150 sm:flex"
        :class="ui.sidebarCollapsed ? 'w-[68px]' : 'w-[232px]'"
        :aria-label="t('nav.primary')"
      >
        <div class="flex h-14 items-center px-4">
          <RouterLink
            :to="{ name: 'overview' }"
            class="flex min-w-0 items-center gap-2 rounded-sm outline-offset-4"
            :aria-label="`${t('app.name')} ${t('app.console')}`"
          >
            <span
              class="grid size-6 shrink-0 place-items-center rounded-[5px] bg-brand text-[12px] font-semibold text-brand-on"
              aria-hidden="true"
            >
              m
            </span>
            <span v-if="!ui.sidebarCollapsed" class="truncate text-[13.5px] font-semibold tracking-[-0.01em]">
              {{ t("app.name") }}
            </span>
          </RouterLink>
        </div>

        <div class="px-2.5 pb-2">
          <DropdownMenu>
            <DropdownMenuTrigger as-child>
              <button
                type="button"
                class="flex w-full items-center gap-2 rounded-md border border-rule bg-surface px-2 py-1.5 text-left transition-colors hover:border-rule-strong hover:bg-surface-muted"
                :aria-label="t('org.switcherLabel')"
              >
                <Building2 class="size-3.5 shrink-0 text-ink-faint" aria-hidden="true" />
                <span v-if="!ui.sidebarCollapsed" class="min-w-0 flex-1">
                  <span class="block truncate text-[12.5px] font-medium leading-tight">{{ ui.org }}</span>
                  <span class="mono-data block truncate text-[10.5px] leading-tight text-ink-faint">
                    {{ ui.tenant }}
                  </span>
                </span>
                <ChevronsUpDown
                  v-if="!ui.sidebarCollapsed"
                  class="size-3.5 shrink-0 text-ink-faint"
                  aria-hidden="true"
                />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" class="min-w-56">
              <DropdownMenuLabel>
                {{ t("org.tenant") }}
                <span class="mono-data font-normal">{{ ui.tenant }}</span>
              </DropdownMenuLabel>
              <DropdownMenuLabel class="pt-0">{{ t("org.organization") }}</DropdownMenuLabel>
              <DropdownMenuItem
                v-for="entry in orgs"
                :key="entry.slug"
                @select="ui.setOrg(entry.slug)"
              >
                <Check class="size-3.5" :class="entry.slug === ui.org ? 'opacity-100' : 'opacity-0'" />
                <span class="flex-1 truncate">{{ entry.slug }}</span>
                <span class="mono-data text-[11px] text-ink-faint">{{ entry.role }}</span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem :disabled="true">
                <span class="text-[11.5px] leading-snug text-ink-faint">{{ t("org.switcherLabel") }}</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <div class="scroll-thin min-h-0 flex-1 overflow-y-auto px-2.5 pb-3">
          <SidebarNav :label="t('nav.primary')">
            <SidebarNavItem
              v-for="item in navItems"
              :key="item.name"
              as-child
              :active="activeName === item.name"
            >
              <RouterLink :to="{ name: item.name }" :title="ui.sidebarCollapsed ? item.label : undefined">
                <component :is="item.icon" />
                <span v-if="!ui.sidebarCollapsed" class="truncate">{{ item.label }}</span>
              </RouterLink>
            </SidebarNavItem>
          </SidebarNav>
        </div>

        <!-- Ground-truth strip: the rail's last job is to say what you are looking at. -->
        <div class="border-t border-rule p-2.5">
          <SidebarNav :label="t('session.signedInAs')">
            <SidebarNavItem as-child>
              <button type="button" class="w-full" :title="t('session.signOut')" @click="signOut">
                <LogOut />
                <span v-if="!ui.sidebarCollapsed" class="min-w-0 flex-1 truncate text-left">{{ email }}</span>
              </button>
            </SidebarNavItem>
          </SidebarNav>

          <p
            v-if="USE_MOCKS"
            class="mt-1.5 flex items-center gap-1.5 px-2 text-[11px] text-ink-faint"
            :title="t('session.mocksHint')"
          >
            <span class="size-1.5 shrink-0 rounded-full bg-warn" aria-hidden="true" />
            <span v-if="!ui.sidebarCollapsed" class="truncate">{{ t("session.mocks") }}</span>
          </p>

          <div class="mt-1.5 flex items-center gap-1">
            <Tooltip>
              <TooltipTrigger as-child>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  :aria-label="t('theme.toggle')"
                  @click="setTheme(resolved === 'dark' ? 'light' : 'dark')"
                >
                  <Sun v-if="resolved === 'dark'" />
                  <Moon v-else />
                </Button>
              </TooltipTrigger>
              <TooltipContent>{{ resolved === "dark" ? t("theme.light") : t("theme.dark") }}</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger as-child>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  :aria-label="ui.sidebarCollapsed ? t('nav.expand') : t('nav.collapse')"
                  @click="ui.toggleSidebar()"
                >
                  <Menu />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {{ ui.sidebarCollapsed ? t("nav.expand") : t("nav.collapse") }}
              </TooltipContent>
            </Tooltip>
          </div>
        </div>
      </aside>

      <div class="flex min-w-0 flex-1 flex-col">
        <!-- Compact top bar for narrow viewports, where the rail is hidden. -->
        <header
          class="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-rule bg-paper/85 px-4 backdrop-blur-sm sm:px-5"
        >
          <RouterLink
            :to="{ name: 'overview' }"
            class="flex min-w-0 items-center gap-2 sm:hidden"
            :aria-label="`${t('app.name')} ${t('app.console')}`"
          >
            <span
              class="grid size-6 shrink-0 place-items-center rounded-[5px] bg-brand text-[12px] font-semibold text-brand-on"
              aria-hidden="true"
            >
              m
            </span>
          </RouterLink>

          <nav class="scroll-thin -mx-1 flex min-w-0 flex-1 items-center gap-1 overflow-x-auto sm:hidden">
            <RouterLink
              v-for="item in navItems"
              :key="item.name"
              :to="{ name: item.name }"
              class="shrink-0 rounded-md px-2 py-1 text-[12.5px] font-medium transition-colors"
              :class="activeName === item.name ? 'bg-surface-muted text-ink' : 'text-ink-muted hover:text-ink'"
            >
              {{ item.label }}
            </RouterLink>
          </nav>

          <span class="mono-data ml-auto hidden shrink-0 text-[11.5px] text-ink-faint sm:block">
            {{ ui.tenant }} / {{ ui.org }}
          </span>
        </header>

        <main class="min-w-0 flex-1 px-4 py-5 sm:px-5">
          <RouterView />
        </main>
      </div>
    </div>

    <Toaster :region-label="t('app.console')" />
  </TooltipProvider>
</template>
