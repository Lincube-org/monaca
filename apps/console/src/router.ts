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
    path: "/resources",
    name: "resources",
    component: () => import("@/pages/ResourcesPage.vue"),
    meta: { title: "API resources" },
  },
  {
    path: "/users",
    name: "users",
    component: () => import("@/pages/UsersPage.vue"),
    meta: { title: "Users" },
  },
  {
    path: "/tenant-roles",
    name: "tenant-roles",
    component: () => import("@/pages/TenantRolesPage.vue"),
    meta: { title: "Tenant roles" },
  },
  {
    path: "/members",
    name: "members",
    component: () => import("@/pages/MembersPage.vue"),
    meta: { title: "Members" },
  },
  {
    path: "/roles",
    name: "roles",
    component: () => import("@/pages/RolesPage.vue"),
    meta: { title: "Roles" },
  },
  {
    path: "/sign-in-experience",
    name: "sign-in-experience",
    component: () => import("@/pages/SignInExperiencePage.vue"),
    meta: { title: "Sign-in experience" },
  },
  {
    path: "/rate-limits",
    name: "rate-limits",
    component: () => import("@/pages/RateLimitsPage.vue"),
    meta: { title: "Rate limits" },
  },
  {
    path: "/email-templates",
    name: "email-templates",
    component: () => import("@/pages/EmailTemplatesPage.vue"),
    meta: { title: "Email templates" },
  },
  {
    path: "/delivery",
    name: "delivery",
    component: () => import("@/pages/DeliveryPage.vue"),
    meta: { title: "Delivery connectors" },
  },
  {
    path: "/message-templates",
    name: "message-templates",
    component: () => import("@/pages/MessageTemplatesPage.vue"),
    meta: { title: "Message templates" },
  },
  {
    path: "/connectors",
    name: "connectors",
    component: () => import("@/pages/ConnectorsPage.vue"),
    meta: { title: "Connectors" },
  },
  {
    path: "/sso-connectors",
    name: "sso-connectors",
    component: () => import("@/pages/SsoConnectorsPage.vue"),
    meta: { title: "Enterprise SSO" },
  },
  {
    path: "/webhooks",
    name: "webhooks",
    component: () => import("@/pages/WebhooksPage.vue"),
    meta: { title: "Webhooks" },
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
