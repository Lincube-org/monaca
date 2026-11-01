import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";

/**
 * Routes.
 *
 * Every page is lazily imported so the initial bundle carries the shell and the Overview only —
 * the Audit page's canonical-JSON machinery and the Agents page's WebCrypto flow are not paid for
 * by someone who came to read the member list.
 *
 * Names are stable identifiers: the shell's nav and the active marker match on `route.name`, not on
 * a path, so a URL change does not silently break the highlighted section.
 */
const routes: RouteRecordRaw[] = [
  {
    path: "/",
    name: "overview",
    component: () => import("@/pages/OverviewPage.vue"),
    meta: { title: "Overview" },
  },
  {
    path: "/organizations",
    name: "organizations",
    component: () => import("@/pages/OrganizationsPage.vue"),
    meta: { title: "Organizations" },
  },
  {
    path: "/applications",
    name: "applications",
    component: () => import("@/pages/ApplicationsPage.vue"),
    meta: { title: "Applications" },
  },
  {
    path: "/members",
    name: "members",
    component: () => import("@/pages/MembersPage.vue"),
    meta: { title: "Members" },
  },
  {
    path: "/agents",
    name: "agents",
    component: () => import("@/pages/AgentsPage.vue"),
    meta: { title: "Agents" },
  },
  {
    path: "/grants",
    name: "grants",
    component: () => import("@/pages/GrantsPage.vue"),
    meta: { title: "Grants" },
  },
  {
    path: "/audit",
    name: "audit",
    component: () => import("@/pages/AuditPage.vue"),
    meta: { title: "Audit" },
  },
  {
    path: "/settings",
    name: "settings",
    component: () => import("@/pages/SettingsPage.vue"),
    meta: { title: "Settings" },
  },
  {
    path: "/:pathMatch(.*)*",
    name: "not-found",
    component: () => import("@/pages/NotFoundPage.vue"),
    meta: { title: "Not found" },
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: (_to, _from, saved) => saved ?? { top: 0 },
});

router.afterEach((to) => {
  const title = to.meta["title"];
  document.title = typeof title === "string" ? `${title} · monaca` : "monaca";
});
