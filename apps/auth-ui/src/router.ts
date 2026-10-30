import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";

/**
 * Routes.
 *
 * The interaction id arrives in the query string (`?tenant=…&interaction=int_…`), exactly as the
 * authorize endpoint builds it (§6.1). The path form is also registered so a future move to
 * `/sign-in/{tenant}/{iid}` is a server-side change only — the page reads either.
 *
 * Everything else lands on the sign-in page, because a hosted sign-in origin has no other job. A
 * stray visit with no interaction id gets the page's own explanation rather than a 404, which is the
 * friendlier failure for a URL a person may have bookmarked or been handed.
 */
const routes: RouteRecordRaw[] = [
  {
    path: "/sign-in",
    name: "sign-in",
    component: () => import("@/pages/SignInPage.vue"),
  },
  {
    path: "/sign-in/:tenant/:interaction",
    name: "sign-in-path",
    component: () => import("@/pages/SignInPage.vue"),
  },
  {
    path: "/account/:tenant",
    name: "account",
    component: () => import("@/pages/AccountPage.vue"),
  },
  {
    path: "/",
    name: "root",
    component: () => import("@/pages/SignInPage.vue"),
  },
  {
    path: "/:pathMatch(.*)*",
    name: "catch-all",
    component: () => import("@/pages/SignInPage.vue"),
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
