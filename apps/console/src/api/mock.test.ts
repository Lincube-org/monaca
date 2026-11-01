import { describe, expect, test } from "bun:test";

import { jwkThumbprintHex, publicEcJwk } from "@monaca/ui";

import { ApiError } from "./contract";
import { appendToChain, verifyLog, type AuditLog } from "./fixtures";
import { mockApi, setMockLatency } from "./mock";
import type { AccountWithRoles } from "./types";
import { GENESIS_HASH, canonicalize } from "@/lib/jcs";
import { newId } from "@/lib/typed-id";

/**
 * End-to-end behaviour of the stage-0 mock layer.
 *
 * The mock is not a stub: it enforces the contract's rules and maintains a real hash chain, and the
 * console's pages rely on both. These tests hold it to that, because a mock that quietly stops
 * behaving like the server would make every page pass locally and fail in production.
 */

const ORG = "acme";

/**
 * The simulated network delay is for the browser, not for tests.
 *
 * These tests share one module-level store, which is the point — they assert that a write is
 * visible to a later read. That also means a test that times out can leave its write in flight and
 * corrupt the next test's counts, so the suite runs serially with a generous per-test budget. The
 * budget is not padding: every chain link costs a `crypto.subtle.digest`, and under Bun that is
 * ~15 ms per call against ~0.05 ms in a browser.
 */
setMockLatency(0);

/** Build the fixture once, before any test observes it. */
await mockApi.getSession();

/**
 * Per-test budget, declared in the file rather than passed on the command line, so the workspace's
 * plain `bun test` gets it too.
 *
 * It is not padding. Under Bun `crypto.subtle.digest` costs ~15 ms per call (in a browser it is
 * ~0.05 ms), and the fixture is a real hash chain, so a test that touches the chain spends real
 * time in SHA-256. The budget reflects the runtime, not leniency about the assertions.
 */
const TIMEOUT_MS = 30_000;
const it = (name: string, fn: () => void | Promise<void>): void => {
  test(name, fn, TIMEOUT_MS);
};


describe("session", () => {
  it("signs into tenant demo and its default org", async () => {
    const session = await mockApi.getSession();
    expect(session.authenticated).toBe(true);
    expect(session.tenant).toBe("demo");
    expect(session.orgs.map((o) => o.slug)).toContain("acme");
    expect(session.email).toBe("admin@demo.localhost");
  });
});

describe("organizations", () => {
  it("lists the tenant's default org as active", async () => {
    const page = await mockApi.listOrganizations();
    expect(page.next).toBe(null);
    const acme = page.items.find((org) => org.slug === ORG);
    expect(acme?.is_default).toBe(true);
    expect(acme?.state).toBe("active");
    for (const org of page.items) expect(org.id).toMatch(/^org_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
  });

  it("creating an org makes it visible and appends org.created", async () => {
    const slug = `team-${Date.now()}`;
    const created = await mockApi.createOrganization({ slug });
    expect(created.slug).toBe(slug);
    expect(created.is_default).toBe(false);
    expect(created.state).toBe("active");

    const page = await mockApi.listOrganizations();
    expect(page.items.map((org) => org.slug)).toContain(slug);

    const audit = await mockApi.listAudit(ORG, { action: "org.created", limit: 200 });
    expect(audit.items.some((event) => event.subject.id === created.id)).toBe(true);
  });

  it("refuses a duplicate slug and an invalid one", async () => {
    const duplicate = await mockApi.createOrganization({ slug: ORG }).catch((error: unknown) => error);
    expect(duplicate).toBeInstanceOf(ApiError);
    expect((duplicate as ApiError).code).toBe("MONACA_ORG_EXISTS");
    expect((duplicate as ApiError).status).toBe(409);

    const invalid = await mockApi.createOrganization({ slug: "Bad Team" }).catch((error: unknown) => error);
    expect((invalid as ApiError).status).toBe(400);
  });

  it("archives and reactivates, and refuses to archive the default org", async () => {
    const slug = `archive-${Date.now()}`;
    const org = await mockApi.createOrganization({ slug });

    expect((await mockApi.updateOrganization(org.id, { state: "archived" })).state).toBe("archived");
    expect((await mockApi.updateOrganization(org.id, { state: "archived" })).state).toBe("archived");
    expect((await mockApi.updateOrganization(org.id, { state: "active" })).state).toBe("active");

    const defaultOrg = (await mockApi.listOrganizations()).items.find((candidate) => candidate.is_default)!;
    const failure = await mockApi
      .updateOrganization(defaultOrg.id, { state: "archived" })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).status).toBe(400);
  });

  it("an unknown organization is a 404", async () => {
    const failure = await mockApi
      .updateOrganization(newId("org"), { state: "archived" })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).status).toBe(404);
  });
});

describe("applications", () => {
  async function freshClientId(prefix: string): Promise<string> {
    // The protocol id is capped at 32 characters, so the prefix is truncated and the suffix is a
    // short base-36 run rather than a full timestamp.
    return `${prefix.slice(0, 18)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  it("lists the seeded clients without secrets", async () => {
    const page = await mockApi.listClients();
    expect(page.next).toBe(null);
    expect(page.items.length).toBeGreaterThanOrEqual(3);
    expect(page.items.map((client) => client.client_id)).toContain("admin-console");
    expect(page.items.map((client) => client.client_id)).toContain("partner-portal");

    for (const client of page.items) {
      expect(client.id).toMatch(/^cli_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
      expect("client_secret" in client).toBe(false);
    }

    const confidential = page.items.find((client) => client.client_id === "notes-service");
    expect(confidential?.kind).toBe("confidential");
    expect(confidential?.token_auth_method).toBe("client_secret_basic");
  });

  it("registers a public client with no secret and a confidential one whose secret appears once", async () => {
    const publicId = await freshClientId("public-app");
    const publicClient = await mockApi.createClient({
      client_id: publicId,
      name: "Public app",
      kind: "public",
      redirect_uris: ["https://public.example/callback"],
      post_logout_redirect_uris: [],
      scopes: ["openid", "profile"],
      is_third_party: false,
    });
    expect(publicClient.kind).toBe("public");
    expect(publicClient.client_secret).toBeUndefined();
    expect(publicClient.redirect_uris).toEqual(["https://public.example/callback"]);

    const confidentialId = await freshClientId("confidential-app");
    const confidential = await mockApi.createClient({
      client_id: confidentialId,
      name: "Confidential app",
      kind: "confidential",
      redirect_uris: ["https://server.example/callback"],
      post_logout_redirect_uris: [],
      scopes: ["openid", "tools:read"],
      is_third_party: false,
    });
    expect(confidential.kind).toBe("confidential");
    expect(confidential.token_auth_method).toBe("client_secret_basic");
    expect(confidential.client_secret).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // The secret exists only in the create response; every later read is without it.
    const listed = (await mockApi.listClients()).items.find((client) => client.id === confidential.id);
    expect(listed).toBeDefined();
    expect("client_secret" in listed!).toBe(false);

    const audit = await mockApi.listAudit(ORG, { action: "client.created", limit: 200 });
    expect(audit.items.some((event) => event.payload["client_id"] === confidentialId)).toBe(true);
  });

  it("refuses a duplicate client_id and an invalid protocol id", async () => {
    const duplicate = await mockApi
      .createClient({
        client_id: "admin-console",
        name: "Copycat",
        kind: "public",
        redirect_uris: [],
        post_logout_redirect_uris: [],
        scopes: [],
        is_third_party: false,
      })
      .catch((error: unknown) => error);
    expect(duplicate).toBeInstanceOf(ApiError);
    expect((duplicate as ApiError).code).toBe("MONACA_CLIENT_EXISTS");
    expect((duplicate as ApiError).status).toBe(409);

    const invalid = await mockApi
      .createClient({
        client_id: "Bad_App",
        name: "Invalid",
        kind: "public",
        redirect_uris: [],
        post_logout_redirect_uris: [],
        scopes: [],
        is_third_party: false,
      })
      .catch((error: unknown) => error);
    expect((invalid as ApiError).status).toBe(400);

    const relative = await mockApi
      .createClient({
        client_id: await freshClientId("relative"),
        name: "Relative",
        kind: "public",
        redirect_uris: ["/callback"],
        post_logout_redirect_uris: [],
        scopes: [],
        is_third_party: false,
      })
      .catch((error: unknown) => error);
    expect((relative as ApiError).status).toBe(400);
  });

  it("rotates a confidential secret, and a public client has nothing to rotate", async () => {
    const clientId = await freshClientId("rotate");
    const created = await mockApi.createClient({
      client_id: clientId,
      name: "Rotating app",
      kind: "confidential",
      redirect_uris: ["https://rotate.example/callback"],
      post_logout_redirect_uris: [],
      scopes: ["openid"],
      is_third_party: false,
    });
    const first = created.client_secret;
    expect(first).toBeDefined();

    const rotated = await mockApi.rotateClientSecret(created.id);
    expect(rotated.client_id).toBe(clientId);
    expect(rotated.client_secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(rotated.client_secret).not.toBe(first);

    const audit = await mockApi.listAudit(ORG, { action: "client.secret_rotated", limit: 200 });
    expect(audit.items.some((event) => event.payload["client_id"] === clientId)).toBe(true);

    const publicFailure = await mockApi.rotateClientSecret("admin-console").catch((error: unknown) => error);
    expect(publicFailure).toBeInstanceOf(ApiError);
    expect((publicFailure as ApiError).status).toBe(400);
  });

  it("edits the name, URIs and scopes but never the client id or kind", async () => {
    const clientId = await freshClientId("edit");
    const created = await mockApi.createClient({
      client_id: clientId,
      name: "Before",
      kind: "public",
      redirect_uris: ["https://before.example/cb"],
      post_logout_redirect_uris: ["https://before.example/"],
      scopes: ["openid"],
      is_third_party: false,
    });

    const updated = await mockApi.updateClient(created.id, {
      name: "After",
      redirect_uris: ["https://after.example/cb", "https://after.example/cb"],
      post_logout_redirect_uris: [],
      scopes: ["openid", "profile"],
    });
    expect(updated.client_id).toBe(clientId);
    expect(updated.kind).toBe("public");
    expect(updated.name).toBe("After");
    expect(updated.redirect_uris).toEqual(["https://after.example/cb"]);
    expect(updated.post_logout_redirect_uris).toEqual([]);
    expect(updated.scopes).toEqual(["openid", "profile"]);
    // An absent CSS field leaves the stored value alone.
    expect(updated.custom_css).toBeNull();

    const audit = await mockApi.listAudit(ORG, { action: "client.updated", limit: 200 });
    expect(audit.items.some((event) => event.payload["client_id"] === clientId)).toBe(true);
  });

  it("sets, trims and clears an application's custom CSS, and refuses one that is too long", async () => {
    const clientId = await freshClientId("css");
    const created = await mockApi.createClient({
      client_id: clientId,
      name: "Styled",
      kind: "public",
      redirect_uris: ["https://styled.example/cb"],
      post_logout_redirect_uris: [],
      scopes: ["openid"],
      is_third_party: false,
    });
    expect(created.custom_css).toBeNull();

    const styled = await mockApi.updateClient(created.id, {
      custom_css: "  :root { --accent: #4f46e5; }  ",
    });
    expect(styled.custom_css).toBe(":root { --accent: #4f46e5; }");
    const listed = (await mockApi.listClients()).items.find((client) => client.id === created.id);
    expect(listed?.custom_css).toBe(":root { --accent: #4f46e5; }");

    const cleared = await mockApi.updateClient(created.id, { custom_css: "   " });
    expect(cleared.custom_css).toBeNull();

    const tooLong = "x".repeat(20_001);
    await expect(mockApi.updateClient(created.id, { custom_css: tooLong })).rejects.toThrow(/20000/);
  });

  it("deletes an application and refuses the second delete", async () => {
    const clientId = await freshClientId("delete");
    const created = await mockApi.createClient({
      client_id: clientId,
      name: "Temporary",
      kind: "public",
      redirect_uris: ["https://temporary.example/cb"],
      post_logout_redirect_uris: [],
      scopes: [],
      is_third_party: false,
    });

    await mockApi.deleteClient(created.id);
    expect((await mockApi.listClients()).items.some((client) => client.id === created.id)).toBe(false);

    const second = await mockApi.deleteClient(created.id).catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);

    const audit = await mockApi.listAudit(ORG, { action: "client.deleted", limit: 200 });
    expect(audit.items.some((event) => event.payload["client_id"] === clientId)).toBe(true);
  });
});

describe("org roles", () => {
  async function freshRoleName(prefix: string): Promise<string> {
    return `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
  }

  it("lists seeded roles with typed ids and their scopes", async () => {
    const page = await mockApi.listOrgRoles(ORG);
    expect(page.next).toBe(null);
    expect(page.items.map((role) => role.name)).toContain("support");
    for (const role of page.items) {
      expect(role.id).toMatch(/^rol_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
      expect(Array.isArray(role.scopes)).toBe(true);
    }
  });

  it("creates a role, refuses a duplicate name, and appends org.role.created", async () => {
    const name = await freshRoleName("reviewer");
    const created = await mockApi.createOrgRole(ORG, {
      name,
      description: "Review tool output.",
      scopes: ["tools:read"],
    });
    expect(created.name).toBe(name);
    expect(created.scopes).toEqual(["tools:read"]);
    expect((await mockApi.listOrgRoles(ORG)).items.map((role) => role.name)).toContain(name);

    const audit = await mockApi.listAudit(ORG, { action: "org.role.created", limit: 200 });
    expect(audit.items.some((event) => event.payload["role"] === name)).toBe(true);

    const duplicate = await mockApi
      .createOrgRole(ORG, { name, description: "", scopes: [] })
      .catch((error: unknown) => error);
    expect(duplicate).toBeInstanceOf(ApiError);
    expect((duplicate as ApiError).code).toBe("MONACA_ORG_ROLE_EXISTS");
    expect((duplicate as ApiError).status).toBe(409);

    const invalid = await mockApi
      .createOrgRole(ORG, { name: "", description: "", scopes: [] })
      .catch((error: unknown) => error);
    expect((invalid as ApiError).status).toBe(400);
  });

  it("updates name, description and scopes, and refuses an invalid scope", async () => {
    const name = await freshRoleName("editor");
    const created = await mockApi.createOrgRole(ORG, {
      name,
      description: "Before.",
      scopes: ["tools:read"],
    });

    const updated = await mockApi.updateOrgRole(ORG, created.id, {
      name: `${name}-v2`,
      description: "After.",
      scopes: ["tools:read", "tools:write"],
    });
    expect(updated.name).toBe(`${name}-v2`);
    expect(updated.description).toBe("After.");
    expect(updated.scopes).toEqual(["tools:read", "tools:write"]);

    await expect(mockApi.updateOrgRole(ORG, created.id, { scopes: ["bad scope"] })).rejects.toThrow(
      /scope grammar/,
    );

    const emptyPatch = await mockApi.updateOrgRole(ORG, created.id, {}).catch((error: unknown) => error);
    expect((emptyPatch as ApiError).status).toBe(400);
  });

  it("assigns a role idempotently and records the before/after set", async () => {
    const role = await mockApi.createOrgRole(ORG, {
      name: await freshRoleName("assignee"),
      description: "",
      scopes: ["tools:read"],
    });
    const member = (await mockApi.listMembers(ORG)).items[0]!;

    await mockApi.assignMemberRole(ORG, member.account_id, { role_id: role.id });
    await mockApi.assignMemberRole(ORG, member.account_id, { role_id: role.id }); // no-op

    const listed = await mockApi.listMemberRoles(ORG, member.account_id);
    expect(listed.items.map((assigned) => assigned.id)).toContain(role.id);

    const audit = await mockApi.listAudit(ORG, { action: "org.member.roles_changed", limit: 200 });
    const event = audit.items.find((candidate) => candidate.subject.id === member.account_id);
    expect(event).toBeDefined();
    expect(event!.payload["to"]).toContain(role.name);
    // The second assign changed nothing, so exactly one event carries this account.
    const forMember = audit.items.filter((candidate) => candidate.subject.id === member.account_id);
    expect(forMember.length).toBe(1);

    const unknownRole = await mockApi
      .assignMemberRole(ORG, member.account_id, { role_id: newId("rol") })
      .catch((error: unknown) => error);
    expect((unknownRole as ApiError).status).toBe(404);

    const unknownMember = await mockApi
      .assignMemberRole(ORG, newId("acc"), { role_id: role.id })
      .catch((error: unknown) => error);
    expect((unknownMember as ApiError).status).toBe(404);

    await mockApi.unassignMemberRole(ORG, member.account_id, role.id);
    expect((await mockApi.listMemberRoles(ORG, member.account_id)).items).toEqual([]);

    const again = await mockApi
      .unassignMemberRole(ORG, member.account_id, role.id)
      .catch((error: unknown) => error);
    expect((again as ApiError).status).toBe(404);
  });

  it("deleting a role removes every assignment of it", async () => {
    const role = await mockApi.createOrgRole(ORG, {
      name: await freshRoleName("doomed"),
      description: "",
      scopes: [],
    });
    const member = (await mockApi.listMembers(ORG)).items[0]!;
    await mockApi.assignMemberRole(ORG, member.account_id, { role_id: role.id });

    await mockApi.deleteOrgRole(ORG, role.id);
    expect((await mockApi.listOrgRoles(ORG)).items.some((candidate) => candidate.id === role.id)).toBe(false);
    expect((await mockApi.listMemberRoles(ORG, member.account_id)).items.some((candidate) => candidate.id === role.id)).toBe(false);

    const audit = await mockApi.listAudit(ORG, { action: "org.role.deleted", limit: 200 });
    expect(audit.items.some((event) => event.payload["role"] === role.name)).toBe(true);
  });
});

describe("api resources", () => {
  async function freshIdentifier(prefix: string): Promise<string> {
    return `https://${prefix}-${Math.random().toString(36).slice(2, 8)}.example`;
  }

  it("lists seeded resources ordered by identifier, including the audience the grants name", async () => {
    const page = await mockApi.listResources();
    expect(page.next).toBe(null);
    expect(page.items.length).toBeGreaterThanOrEqual(2);

    const identifiers = page.items.map((resource) => resource.identifier);
    expect(identifiers).toEqual([...identifiers].sort((left, right) => left.localeCompare(right)));
    expect(identifiers).toContain("http://localhost:8080/mcp/demo");

    for (const resource of page.items) {
      expect(resource.id).toMatch(/^res_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
      expect(Array.isArray(resource.scopes)).toBe(true);
    }
  });

  it("registers a resource, refuses a duplicate identifier, and appends resource.created", async () => {
    const identifier = await freshIdentifier("billing");
    const created = await mockApi.createResource({
      name: "Billing API",
      identifier,
      scopes: ["billing:read"],
    });
    expect(created.name).toBe("Billing API");
    expect(created.identifier).toBe(identifier);
    expect(created.scopes).toEqual(["billing:read"]);

    const audit = await mockApi.listAudit(ORG, { action: "resource.created", limit: 200 });
    expect(audit.items.some((event) => event.payload["identifier"] === identifier)).toBe(true);

    const duplicate = await mockApi
      .createResource({ name: "Copy", identifier, scopes: [] })
      .catch((error: unknown) => error);
    expect(duplicate).toBeInstanceOf(ApiError);
    expect((duplicate as ApiError).code).toBe("MONACA_RESOURCE_EXISTS");
    expect((duplicate as ApiError).status).toBe(409);

    const relative = await mockApi
      .createResource({ name: "Relative", identifier: "/api", scopes: [] })
      .catch((error: unknown) => error);
    expect((relative as ApiError).status).toBe(400);
  });

  it("edits the name and scopes but never the identifier", async () => {
    const identifier = await freshIdentifier("catalog");
    const created = await mockApi.createResource({
      name: "Catalog API",
      identifier,
      scopes: ["catalog:read"],
    });

    const updated = await mockApi.updateResource(created.id, {
      name: "Catalog API v2",
      scopes: ["catalog:read", "catalog:write"],
    });
    expect(updated.name).toBe("Catalog API v2");
    expect(updated.identifier).toBe(identifier);
    expect(updated.scopes).toEqual(["catalog:read", "catalog:write"]);

    const emptyPatch = await mockApi.updateResource(created.id, {}).catch((error: unknown) => error);
    expect((emptyPatch as ApiError).status).toBe(400);

    await expect(mockApi.updateResource(created.id, { scopes: ["bad scope"] })).rejects.toThrow(
      /scope grammar/,
    );

    const audit = await mockApi.listAudit(ORG, { action: "resource.updated", limit: 200 });
    expect(audit.items.some((event) => event.payload["identifier"] === identifier)).toBe(true);
  });

  it("deletes a resource and refuses the second delete", async () => {
    const identifier = await freshIdentifier("ephemeral");
    const created = await mockApi.createResource({
      name: "Ephemeral API",
      identifier,
      scopes: [],
    });

    await mockApi.deleteResource(created.id);
    expect((await mockApi.listResources()).items.some((resource) => resource.id === created.id)).toBe(false);

    const second = await mockApi.deleteResource(created.id).catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);

    const audit = await mockApi.listAudit(ORG, { action: "resource.deleted", limit: 200 });
    expect(audit.items.some((event) => event.payload["identifier"] === identifier)).toBe(true);
  });
});

describe("agents", () => {
  it("lists seeded agents with typed ids and RFC 7638 fingerprints", async () => {
    const page = await mockApi.listAgents(ORG);
    expect(page.items.length).toBeGreaterThan(0);
    expect(page.next).toBe(null);

    for (const agent of page.items) {
      expect(agent.id).toMatch(/^agt_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
      for (const key of agent.keys) {
        expect(key.fingerprint).toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });

  it("rejects a duplicate agent name", async () => {
    const existing = (await mockApi.listAgents(ORG)).items[0]!;
    await expect(
      mockApi.createAgent(ORG, { name: existing.name, description: "", owner_account_id: existing.owner_account_id }),
    ).rejects.toThrow(/already exists/);
  });

  it("rejects an owner who is not a member of the org", async () => {
    await expect(
      mockApi.createAgent(ORG, {
        name: `orphan-${Date.now()}`,
        description: "",
        owner_account_id: newId("acc"),
      }),
    ).rejects.toThrow(/not a member/);
  });

  it("creating an agent appends agent.created to the audit chain", async () => {
    const before = await mockApi.listAudit(ORG, { action: "agent.created", limit: 200 });
    const name = `test-bot-${Date.now()}`;
    const owner = (await mockApi.listMembers(ORG)).items[0]!;

    const created = await mockApi.createAgent(ORG, {
      name,
      description: "created by the mock layer test",
      owner_account_id: owner.account_id,
    });
    expect(created.name).toBe(name);
    expect(created.keys).toEqual([]);

    const after = await mockApi.listAudit(ORG, { action: "agent.created", limit: 200 });
    expect(after.items.length).toBe(before.items.length + 1);
    expect(after.items[0]?.subject.id).toBe(created.id);
    expect(after.items[0]?.payload["name"]).toBe(name);
  });
});

describe("agent keys", () => {
  async function freshAgent(): Promise<string> {
    const owner = (await mockApi.listMembers(ORG)).items[0]!;
    const agent = await mockApi.createAgent(ORG, {
      name: `key-test-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
      description: "",
      owner_account_id: owner.account_id,
    });
    return agent.id;
  }

  it("registers a real generated public key and stores its true thumbprint", async () => {
    const agentId = await freshAgent();

    // The same generation the Agents page performs.
    const { publicKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const publicJwk = publicEcJwk(await crypto.subtle.exportKey("jwk", publicKey));

    const agent = await mockApi.registerAgentKey(ORG, agentId, { public_jwk: publicJwk, alg: "ES256", kid: "k1" });
    const key = agent.keys.find((candidate) => candidate.kid === "k1");

    expect(key).toBeDefined();
    // The stored fingerprint must equal the independently computed thumbprint, not a placeholder.
    expect(key!.fingerprint).toBe(await jwkThumbprintHex(publicJwk));
    expect(key!.revoked_at).toBe(null);
    expect(key!.id).toMatch(/^akey_/);
  });

  it("rejects a JWK carrying a private component (MONACA_PRIVATE_KEY_SUBMITTED)", async () => {
    const agentId = await freshAgent();
    const { privateKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const privateJwk = await crypto.subtle.exportKey("jwk", privateKey);
    expect(privateJwk.d).toBeDefined();

    const failure = await mockApi
      .registerAgentKey(ORG, agentId, { public_jwk: privateJwk, alg: "ES256", kid: "leak" })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).code).toBe("MONACA_PRIVATE_KEY_SUBMITTED");
    expect((failure as ApiError).status).toBe(400);

    // And nothing was written.
    const agent = (await mockApi.listAgents(ORG)).items.find((candidate) => candidate.id === agentId);
    expect(agent?.keys).toEqual([]);
  });

  it("rejects a non-P-256 key", async () => {
    const agentId = await freshAgent();
    await expect(
      mockApi.registerAgentKey(ORG, agentId, {
        public_jwk: { kty: "RSA", n: "abc", e: "AQAB" },
        alg: "ES256",
        kid: "rsa",
      }),
    ).rejects.toThrow(/EC P-256/);
  });

  it("rejects a duplicate active kid but allows a new one", async () => {
    const agentId = await freshAgent();
    const { publicKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const jwk = publicEcJwk(await crypto.subtle.exportKey("jwk", publicKey));

    await mockApi.registerAgentKey(ORG, agentId, { public_jwk: jwk, alg: "ES256", kid: "k1" });
    await expect(
      mockApi.registerAgentKey(ORG, agentId, { public_jwk: jwk, alg: "ES256", kid: "k1" }),
    ).rejects.toThrow(/already registered/);

    const agent = await mockApi.registerAgentKey(ORG, agentId, { public_jwk: jwk, alg: "ES256", kid: "k2" });
    expect(agent.keys.map((key) => key.kid)).toEqual(["k1", "k2"]);
  });

  it("revoking a key is idempotent and stamps revoked_at", async () => {
    const agentId = await freshAgent();
    const { publicKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const agent = await mockApi.registerAgentKey(ORG, agentId, {
      public_jwk: publicEcJwk(await crypto.subtle.exportKey("jwk", publicKey)),
      alg: "ES256",
      kid: "k1",
    });
    const keyId = agent.keys[0]!.id;

    await mockApi.revokeAgentKey(ORG, agentId, keyId);
    await mockApi.revokeAgentKey(ORG, agentId, keyId); // second call must not throw

    const after = (await mockApi.listAgents(ORG)).items.find((candidate) => candidate.id === agentId);
    expect(after?.keys[0]?.revoked_at).not.toBe(null);
  });
});

describe("grants", () => {
  it("a new grant is visible and links agent to delegator", async () => {
    const agent = (await mockApi.listAgents(ORG)).items[0]!;
    const member = (await mockApi.listMembers(ORG)).items[0]!;

    const grant = await mockApi.createGrant(ORG, {
      agent_id: agent.id,
      account_id: member.account_id,
      scopes: ["tools:read"],
      resource: "http://localhost:8080/mcp/demo",
      expires_at: null,
    });

    expect(grant.id).toMatch(/^grt_/);
    expect(grant.revoked_at).toBe(null);

    const listed = (await mockApi.listGrants(ORG)).items.find((candidate) => candidate.id === grant.id);
    expect(listed?.scopes).toEqual(["tools:read"]);
  });

  it("revoking marks the grant rather than deleting it", async () => {
    const agent = (await mockApi.listAgents(ORG)).items[1]!;
    const member = (await mockApi.listMembers(ORG)).items[0]!;
    const grant = await mockApi.createGrant(ORG, {
      agent_id: agent.id,
      account_id: member.account_id,
      scopes: ["tools:read"],
      resource: "http://localhost:8080/mcp/demo",
      expires_at: null,
    });

    await mockApi.revokeGrant(ORG, grant.id);

    const listed = (await mockApi.listGrants(ORG)).items.find((candidate) => candidate.id === grant.id);
    expect(listed).toBeDefined();
    expect(listed?.revoked_at).not.toBe(null);
  });
});

describe("audit", () => {
  it("returns newest first with a typed id and every chain field", async () => {
    const page = await mockApi.listAudit(ORG, { limit: 10 });
    expect(page.items.length).toBeLessThanOrEqual(10);

    const seqs = page.items.map((event) => event.seq);
    expect(seqs).toEqual([...seqs].sort((a, b) => b - a));

    for (const event of page.items) {
      expect(event.id).toMatch(/^evt_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
      expect(event.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(event.prev_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(event.actor_chain.length).toBeGreaterThan(0);
      expect(typeof event.payload).toBe("object");
    }
  });

  it("filters by action", async () => {
    const page = await mockApi.listAudit(ORG, { action: "tool.invoked", limit: 200 });
    expect(page.items.length).toBeGreaterThan(0);
    for (const event of page.items) expect(event.action).toBe("tool.invoked");
  });

  it("filters by grant, so the account → grant → agent → token → tool story is queryable", async () => {
    const grant = (await mockApi.listGrants(ORG)).items.find((candidate) => candidate.revoked_at === null)!;
    const page = await mockApi.listAudit(ORG, { grant_id: grant.id, limit: 200 });

    expect(page.items.length).toBeGreaterThan(0);
    const actions = new Set(page.items.map((event) => event.action));
    // §12 step 5 asserts exactly this sequence is reachable for a grant.
    expect(actions.has("agent.token.issued")).toBe(true);
    expect(actions.has("tool.invoked")).toBe(true);
    for (const event of page.items) expect(event.grant_id).toBe(grant.id);
  });

  it("verify reports a valid chain over the whole fixture", async () => {
    const report = await mockApi.verifyAudit(ORG);
    expect(report.valid).toBe(true);
    expect(report.first_broken).toBe(null);
    expect(report.checked).toBe(report.head.seq);
    expect(report.head.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verify detects tampering with a payload", async () => {
    // A small hand-built chain, so the test exercises the verifier rather than the fixture size.
    const log: AuditLog = { events: [], head: { seq: 0, hash: GENESIS_HASH } };
    for (let index = 0; index < 4; index += 1) {
      await appendToChain(log, {
        id: newId("evt"),
        at: new Date(1_767_225_600_000 + index * 1000).toISOString(),
        action: "tool.invoked",
        actor_chain: [{ type: "account", id: newId("acc") }],
        subject: { type: "tool", id: "list_notes" },
        decision: "allow",
        grant_id: null,
        jti: null,
        payload: { rows: index },
      });
    }
    expect((await verifyLog(log)).valid).toBe(true);

    // Flip one byte of one payload. Everything downstream is now unreachable from genesis.
    const victim = log.events[2]!;
    victim.payload = { ...victim.payload, tampered: true };

    const report = await verifyLog(log);
    expect(report.valid).toBe(false);
    expect(report.first_broken?.seq).toBe(victim.seq);
    expect(report.first_broken?.reason).toBe("hash_mismatch");
    expect(report.checked).toBe(2); // the two good links before it
  });

  it("verify detects a rewritten prev_hash even when the hash column is recomputed", async () => {
    const log: AuditLog = { events: [], head: { seq: 0, hash: GENESIS_HASH } };
    for (let index = 0; index < 3; index += 1) {
      await appendToChain(log, {
        id: newId("evt"),
        at: new Date(1_767_225_600_000 + index * 1000).toISOString(),
        action: "grant.created",
        actor_chain: [{ type: "account", id: newId("acc") }],
        subject: { type: "grant", id: newId("grt") },
        decision: "info",
        grant_id: null,
        jti: null,
        payload: {},
      });
    }

    // Splice out a link: the third event now points at a hash that is not the second event's.
    log.events[2]!.prev_hash = log.events[0]!.hash;

    const report = await verifyLog(log);
    expect(report.valid).toBe(false);
    expect(report.first_broken?.reason).toBe("prev_hash_mismatch");
  });

  it("the canonical bytes exclude the chain fields", () => {
    // §8.2: seq/prev_hash/hash are not part of the hashed object. Adding them to the stored row
    // must not change the digest of the event body.
    const body = { id: "evt_x", at: "2026-01-01T00:00:00.000Z", action: "tool.invoked", payload: { a: 1 } };
    expect(canonicalize(body)).toBe(canonicalize({ ...body }));
    expect(canonicalize(body)).not.toBe(canonicalize({ ...body, seq: 1 }));
  });
});

describe("connectors", () => {
  async function freshConnectorId(): Promise<string> {
    return `provider-${Math.random().toString(36).slice(2, 8)}`;
  }

  it("lists the seeded connectors ordered by id, without secrets", async () => {
    const page = await mockApi.listConnectors();
    expect(page.next).toBe(null);
    const ids = page.items.map((connector) => connector.connector_id);
    expect(ids).toEqual([...ids].sort((left, right) => left.localeCompare(right)));
    expect(ids).toContain("github");
    expect(ids).toContain("google");

    for (const connector of page.items) {
      expect("client_secret" in connector).toBe(false);
      expect(Array.isArray(connector.scopes)).toBe(true);
    }
  });

  it("registers a connector, lowercasing its id, and appends connector.created", async () => {
    const rawId = await freshConnectorId();
    const connectorId = rawId.toUpperCase();
    const created = await mockApi.createConnector({
      connector_id: connectorId,
      display_name: "Provider",
      authorize_url: "https://provider.example/authorize",
      token_url: "https://provider.example/token",
      userinfo_url: "https://provider.example/userinfo",
      client_id: "client-1",
      client_secret: "shhh",
      scopes: ["openid", "openid", "profile"],
    });
    expect(created.connector_id).toBe(rawId);
    expect(created.scopes).toEqual(["openid", "profile"]);
    expect("client_secret" in created).toBe(false);

    const audit = await mockApi.listAudit(ORG, { action: "connector.created", limit: 200 });
    expect(audit.items.some((event) => event.payload["connector_id"] === rawId)).toBe(true);

    const duplicate = await mockApi
      .createConnector({
        connector_id: rawId,
        display_name: "Copy",
        authorize_url: "https://copy.example/authorize",
        token_url: "https://copy.example/token",
        userinfo_url: "https://copy.example/userinfo",
        client_id: "client-2",
        client_secret: "x",
        scopes: [],
      })
      .catch((error: unknown) => error);
    expect(duplicate).toBeInstanceOf(ApiError);
    expect((duplicate as ApiError).code).toBe("MONACA_CONNECTOR_EXISTS");
    expect((duplicate as ApiError).status).toBe(409);
  });

  it("refuses a relative endpoint, an empty secret and a scope with whitespace", async () => {
    const connectorId = await freshConnectorId();
    const valid = {
      connector_id: connectorId,
      display_name: "Provider",
      authorize_url: "https://provider.example/authorize",
      token_url: "https://provider.example/token",
      userinfo_url: "https://provider.example/userinfo",
      client_id: "client-1",
      client_secret: "shhh",
      scopes: [] as string[],
    };

    const relative = await mockApi
      .createConnector({ ...valid, authorize_url: "/authorize" })
      .catch((error: unknown) => error);
    expect((relative as ApiError).status).toBe(400);

    const noSecret = await mockApi
      .createConnector({ ...valid, client_secret: "" })
      .catch((error: unknown) => error);
    expect((noSecret as ApiError).status).toBe(400);

    const badScope = await mockApi
      .createConnector({ ...valid, scopes: ["two words"] })
      .catch((error: unknown) => error);
    expect((badScope as ApiError).status).toBe(400);

    const badId = await mockApi
      .createConnector({ ...valid, connector_id: "-provider" })
      .catch((error: unknown) => error);
    expect((badId as ApiError).status).toBe(400);
  });

  it("deletes a connector and refuses the second delete", async () => {
    const connectorId = await freshConnectorId();
    await mockApi.createConnector({
      connector_id: connectorId,
      display_name: "Ephemeral",
      authorize_url: "https://ephemeral.example/authorize",
      token_url: "https://ephemeral.example/token",
      userinfo_url: "https://ephemeral.example/userinfo",
      client_id: "client-1",
      client_secret: "shhh",
      scopes: [],
    });

    await mockApi.deleteConnector(connectorId);
    expect((await mockApi.listConnectors()).items.some((connector) => connector.connector_id === connectorId)).toBe(
      false,
    );

    const second = await mockApi.deleteConnector(connectorId).catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);

    const audit = await mockApi.listAudit(ORG, { action: "connector.deleted", limit: 200 });
    expect(audit.items.some((event) => event.payload["connector_id"] === connectorId)).toBe(true);
  });
});

describe("enterprise SSO", () => {
  async function freshSsoSuffix(): Promise<string> {
    return Math.random().toString(36).slice(2, 8);
  }

  it("lists the seeded provider with its domains and no secret", async () => {
    const page = await mockApi.listSsoConnectors();
    expect(page.next).toBe(null);
    const seeded = page.items.find((connector) => connector.connector_id === "partner-oidc");
    expect(seeded?.email_domains).toEqual(["partner.example"]);
    expect(seeded?.display_name).toBe("Partner OIDC");
    expect("client_secret" in (seeded ?? {})).toBe(false);
  });

  it("registers a provider, normalises its domains and appends sso_connector.created", async () => {
    const suffix = await freshSsoSuffix();
    const connectorId = `sso-${suffix}`;
    const domain = `sso-${suffix}.example.com`;
    const created = await mockApi.createSsoConnector({
      connector_id: connectorId.toUpperCase(),
      display_name: "Acme SSO",
      issuer: "https://sso.example",
      authorize_url: "https://sso.example/authorize",
      token_url: "https://sso.example/token",
      userinfo_url: "https://sso.example/userinfo",
      client_id: "sso-client",
      client_secret: "shhh",
      scopes: [],
      email_domains: [` ${domain.toUpperCase()} `],
    });
    expect(created.connector_id).toBe(connectorId);
    expect(created.email_domains).toEqual([domain]);
    expect(created.scopes).toEqual(["openid", "profile", "email"]);

    const audit = await mockApi.listAudit(ORG, { action: "sso_connector.created", limit: 200 });
    expect(audit.items.some((event) => event.payload["connector_id"] === connectorId)).toBe(true);

    const duplicate = await mockApi
      .createSsoConnector({
        connector_id: connectorId,
        display_name: "Copy",
        issuer: "https://sso.example",
        authorize_url: "https://sso.example/authorize",
        token_url: "https://sso.example/token",
        userinfo_url: "https://sso.example/userinfo",
        client_id: "sso-client",
        client_secret: "x",
        email_domains: [domain],
      })
      .catch((error: unknown) => error);
    expect((duplicate as ApiError).status).toBe(409);
    expect((duplicate as ApiError).code).toBe("MONACA_SSO_CONNECTOR_EXISTS");

    const claimed = await mockApi
      .createSsoConnector({
        connector_id: `claim-${suffix}`,
        display_name: "Claim",
        issuer: "https://sso.example",
        authorize_url: "https://sso.example/authorize",
        token_url: "https://sso.example/token",
        userinfo_url: "https://sso.example/userinfo",
        client_id: "sso-client",
        client_secret: "x",
        email_domains: [domain],
      })
      .catch((error: unknown) => error);
    expect((claimed as ApiError).status).toBe(409);
    expect((claimed as ApiError).code).toBe("MONACA_SSO_DOMAIN_TAKEN");

    await mockApi.deleteSsoConnector(connectorId);
  });

  it("refuses a relative issuer, no domains and a malformed domain", async () => {
    const suffix = await freshSsoSuffix();
    const valid = {
      connector_id: `sso-${suffix}`,
      display_name: "Acme SSO",
      issuer: "https://sso.example",
      authorize_url: "https://sso.example/authorize",
      token_url: "https://sso.example/token",
      userinfo_url: "https://sso.example/userinfo",
      client_id: "sso-client",
      client_secret: "shhh",
      email_domains: [`sso-${suffix}.example.com`],
    };

    const relative = await mockApi
      .createSsoConnector({ ...valid, issuer: "sso.example" })
      .catch((error: unknown) => error);
    expect((relative as ApiError).status).toBe(400);

    const noDomains = await mockApi
      .createSsoConnector({ ...valid, email_domains: [] })
      .catch((error: unknown) => error);
    expect((noDomains as ApiError).status).toBe(400);

    const badDomain = await mockApi
      .createSsoConnector({ ...valid, email_domains: ["not a domain"] })
      .catch((error: unknown) => error);
    expect((badDomain as ApiError).status).toBe(400);

    const noSecret = await mockApi
      .createSsoConnector({ ...valid, client_secret: "" })
      .catch((error: unknown) => error);
    expect((noSecret as ApiError).status).toBe(400);
  });

  it("deletes a provider, records sso_connector.deleted, and refuses the second delete", async () => {
    const suffix = await freshSsoSuffix();
    const connectorId = `gone-${suffix}`;
    await mockApi.createSsoConnector({
      connector_id: connectorId,
      display_name: "Ephemeral SSO",
      issuer: "https://gone.example",
      authorize_url: "https://gone.example/authorize",
      token_url: "https://gone.example/token",
      userinfo_url: "https://gone.example/userinfo",
      client_id: "sso-client",
      client_secret: "shhh",
      email_domains: [`gone-${suffix}.example.com`],
    });

    await mockApi.deleteSsoConnector(connectorId);
    expect((await mockApi.listSsoConnectors()).items.some((row) => row.connector_id === connectorId)).toBe(
      false,
    );

    const second = await mockApi.deleteSsoConnector(connectorId).catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);

    const audit = await mockApi.listAudit(ORG, { action: "sso_connector.deleted", limit: 200 });
    expect(audit.items.some((event) => event.payload["connector_id"] === connectorId)).toBe(true);
  });
});

describe("sign-in experience", () => {
  it("reads the seeded switches, all methods on", async () => {
    const experience = await mockApi.getSignInExperience();
    expect(experience.sign_up_enabled).toBe(true);
    expect(experience.password_sign_in_enabled).toBe(true);
    expect(experience.email_code_sign_in_enabled).toBe(true);
    expect(experience.mfa_enabled).toBe(true);
    expect(experience.mfa_policy).toBe("user_controlled");
    expect(experience.password_min_length).toBe(8);
    expect(experience.password_min_character_types).toBe(1);
    expect(experience.password_reject_user_info).toBe(true);
    expect(experience.password_reject_repetition_and_sequence).toBe(false);
    expect(experience.password_rejected_words).toEqual([]);
    expect(experience.session_ttl_secs).toBe(2_592_000);
    expect(experience.refresh_token_ttl_secs).toBe(2_592_000);
    expect(experience.branding).toEqual({
      display_name: null,
      logo_url: null,
      primary_color: null,
      terms_url: null,
      privacy_url: null,
      custom_css: null,
    });
    expect(Number.isNaN(Date.parse(experience.updated_at))).toBe(false);
  });

  it("applies a partial patch and appends sign_in_experience.updated", async () => {
    const before = await mockApi.getSignInExperience();
    const updated = await mockApi.updateSignInExperience({ sign_up_enabled: false });
    expect(updated.sign_up_enabled).toBe(false);
    expect(updated.password_sign_in_enabled).toBe(before.password_sign_in_enabled);
    expect(updated.email_code_sign_in_enabled).toBe(before.email_code_sign_in_enabled);
    expect(Date.parse(updated.updated_at)).toBeGreaterThan(Date.parse(before.updated_at));

    const audit = await mockApi.listAudit(ORG, { action: "sign_in_experience.updated", limit: 200 });
    const newest = audit.items[0];
    expect(newest?.subject.type).toBe("tenant");
    expect(newest?.decision).toBe("allow");
    expect(newest?.payload).toEqual({
      sign_up_enabled: false,
      password_sign_in_enabled: true,
      email_code_sign_in_enabled: true,
      passkey_sign_in_enabled: true,
      mfa_enabled: true,
      mfa_policy: "user_controlled",
      password_min_length: 8,
      password_min_character_types: 1,
      password_reject_user_info: true,
      password_reject_repetition_and_sequence: false,
      password_rejected_words: [],
      session_ttl_secs: 2_592_000,
      refresh_token_ttl_secs: 2_592_000,
      branding: {
        display_name: null,
        logo_url: null,
        primary_color: null,
        terms_url: null,
        privacy_url: null,
        custom_css: null,
      },
    });

    await mockApi.updateSignInExperience({ sign_up_enabled: true });
  });

  it("toggles passwordless passkey sign-in and records the new value", async () => {
    const off = await mockApi.updateSignInExperience({ passkey_sign_in_enabled: false });
    expect(off.passkey_sign_in_enabled).toBe(false);
    expect(off.password_sign_in_enabled).toBe(true);

    const read = await mockApi.getSignInExperience();
    expect(read.passkey_sign_in_enabled).toBe(false);

    const audit = await mockApi.listAudit(ORG, { action: "sign_in_experience.updated", limit: 200 });
    expect(audit.items[0]?.payload["passkey_sign_in_enabled"]).toBe(false);

    await mockApi.updateSignInExperience({ passkey_sign_in_enabled: true });
  });

  it("refuses an empty patch and any patch that leaves no first factor", async () => {
    const empty = await mockApi.updateSignInExperience({}).catch((error: unknown) => error);
    expect(empty).toBeInstanceOf(ApiError);
    expect((empty as ApiError).status).toBe(400);
    expect((empty as ApiError).code).toBe("MONACA_INVALID_REQUEST");

    // The server checks the *result* of the patch, not the patch alone.
    await mockApi.updateSignInExperience({ password_sign_in_enabled: false });
    const noFactor = await mockApi
      .updateSignInExperience({ email_code_sign_in_enabled: false })
      .catch((error: unknown) => error);
    expect(noFactor).toBeInstanceOf(ApiError);
    expect((noFactor as ApiError).status).toBe(400);

    // A refused patch changes nothing.
    const current = await mockApi.getSignInExperience();
    expect(current.password_sign_in_enabled).toBe(false);
    expect(current.email_code_sign_in_enabled).toBe(true);

    await mockApi.updateSignInExperience({ password_sign_in_enabled: true });
  });

  it("returns copies, so a caller cannot mutate the stored switches", async () => {
    const snapshot = await mockApi.getSignInExperience();
    snapshot.sign_up_enabled = false;
    expect((await mockApi.getSignInExperience()).sign_up_enabled).toBe(true);
  });

  it("sets the MFA policy and refuses a mandatory policy with MFA off", async () => {
    const mandatory = await mockApi.updateSignInExperience({ mfa_policy: "mandatory" });
    expect(mandatory.mfa_policy).toBe("mandatory");
    expect(mandatory.mfa_enabled).toBe(true);

    const impossible = await mockApi
      .updateSignInExperience({ mfa_enabled: false, mfa_policy: "mandatory" })
      .catch((error: unknown) => error);
    expect(impossible).toBeInstanceOf(ApiError);
    expect((impossible as ApiError).status).toBe(400);

    const off = await mockApi.updateSignInExperience({
      mfa_enabled: false,
      mfa_policy: "user_controlled",
    });
    expect(off.mfa_enabled).toBe(false);
    expect(off.mfa_policy).toBe("user_controlled");

    await mockApi.updateSignInExperience({ mfa_enabled: true });

    const audit = await mockApi.listAudit(ORG, {
      action: "sign_in_experience.updated",
      limit: 200,
    });
    expect(audit.items[0]?.payload).toMatchObject({ mfa_enabled: true, mfa_policy: "user_controlled" });
  });

  it("keeps the chain verifiable after the writes", async () => {
    const report = await mockApi.verifyAudit(ORG);
    expect(report.valid).toBe(true);
  });

  it("sets the minimum password length and refuses values outside 8–64", async () => {
    for (const value of [7, 65]) {
      const failure = await mockApi
        .updateSignInExperience({ password_min_length: value })
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ApiError);
      expect((failure as ApiError).status).toBe(400);
    }

    const raised = await mockApi.updateSignInExperience({ password_min_length: 12 });
    expect(raised.password_min_length).toBe(12);

    const audit = await mockApi.listAudit(ORG, {
      action: "sign_in_experience.updated",
      limit: 200,
    });
    expect(audit.items[0]?.payload).toMatchObject({ password_min_length: 12 });

    await mockApi.updateSignInExperience({ password_min_length: 8 });
  });

  it("sets the minimum character types and refuses values outside 1–4", async () => {
    for (const value of [0, 5]) {
      const failure = await mockApi
        .updateSignInExperience({ password_min_character_types: value })
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ApiError);
      expect((failure as ApiError).status).toBe(400);
    }

    const raised = await mockApi.updateSignInExperience({ password_min_character_types: 3 });
    expect(raised.password_min_character_types).toBe(3);

    const audit = await mockApi.listAudit(ORG, {
      action: "sign_in_experience.updated",
      limit: 200,
    });
    expect(audit.items[0]?.payload).toMatchObject({ password_min_character_types: 3 });

    await mockApi.updateSignInExperience({ password_min_character_types: 1 });
  });

  it("toggles the password rejection rules and records them", async () => {
    const flipped = await mockApi.updateSignInExperience({
      password_reject_user_info: false,
      password_reject_repetition_and_sequence: true,
    });
    expect(flipped.password_reject_user_info).toBe(false);
    expect(flipped.password_reject_repetition_and_sequence).toBe(true);

    const audit = await mockApi.listAudit(ORG, {
      action: "sign_in_experience.updated",
      limit: 200,
    });
    expect(audit.items[0]?.payload).toMatchObject({
      password_reject_user_info: false,
      password_reject_repetition_and_sequence: true,
    });

    await mockApi.updateSignInExperience({
      password_reject_user_info: true,
      password_reject_repetition_and_sequence: false,
    });
  });

  it("normalises the rejected word list and validates its shape", async () => {
    const short = await mockApi
      .updateSignInExperience({ password_rejected_words: ["ab"] })
      .catch((error: unknown) => error);
    expect(short).toBeInstanceOf(ApiError);
    expect((short as ApiError).status).toBe(400);

    const tooMany = await mockApi
      .updateSignInExperience({
        password_rejected_words: Array.from({ length: 101 }, (_, index) => `word-${index}`),
      })
      .catch((error: unknown) => error);
    expect(tooMany).toBeInstanceOf(ApiError);
    expect((tooMany as ApiError).status).toBe(400);

    const written = await mockApi.updateSignInExperience({
      password_rejected_words: [" Monaca ", "QWERTY", "monaca"],
    });
    expect(written.password_rejected_words).toEqual(["monaca", "qwerty"]);

    const audit = await mockApi.listAudit(ORG, {
      action: "sign_in_experience.updated",
      limit: 200,
    });
    expect(audit.items[0]?.payload).toMatchObject({
      password_rejected_words: ["monaca", "qwerty"],
    });

    await mockApi.updateSignInExperience({ password_rejected_words: [] });
  });

  it("sets and clears branding fields and validates their shape", async () => {
    const empty = await mockApi
      .updateSignInExperience({ branding: {} })
      .catch((error: unknown) => error);
    expect(empty).toBeInstanceOf(ApiError);
    expect((empty as ApiError).status).toBe(400);

    for (const branding of [
      { display_name: "x".repeat(65) },
      { logo_url: "logo.png" },
      { primary_color: "blue" },
    ]) {
      const failure = await mockApi
        .updateSignInExperience({ branding })
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ApiError);
      expect((failure as ApiError).status).toBe(400);
    }

    const branding = {
      display_name: "Acme Identity",
      logo_url: "https://cdn.example/logo.png",
      primary_color: "#0f6cbd",
      terms_url: "https://acme.example/terms",
      privacy_url: "https://acme.example/privacy",
    };
    const written = await mockApi.updateSignInExperience({ branding });
    expect(written.branding).toEqual({ ...branding, custom_css: null });

    const cleared = await mockApi.updateSignInExperience({
      branding: { logo_url: "" },
    });
    expect(cleared.branding.logo_url).toBeNull();
    expect(cleared.branding.display_name).toBe(branding.display_name);

    const audit = await mockApi.listAudit(ORG, {
      action: "sign_in_experience.updated",
      limit: 200,
    });
    expect(audit.items[0]?.payload).toMatchObject({ branding: cleared.branding });

    await mockApi.updateSignInExperience({
      branding: {
        display_name: "",
        logo_url: "",
        primary_color: "",
        terms_url: "",
        privacy_url: "",
        custom_css: "",
      },
    });
    const reset = await mockApi.getSignInExperience();
    expect(reset.branding).toEqual({
      display_name: null,
      logo_url: null,
      primary_color: null,
      terms_url: null,
      privacy_url: null,
      custom_css: null,
    });
  });

  it("round-trips custom CSS and refuses more than 20,000 characters", async () => {
    const css = ".mono-card { border-radius: 12px; }";
    const written = await mockApi.updateSignInExperience({ branding: { custom_css: css } });
    expect(written.branding.custom_css).toBe(css);

    const audit = await mockApi.listAudit(ORG, {
      action: "sign_in_experience.updated",
      limit: 200,
    });
    expect(audit.items[0]?.payload).toMatchObject({ branding: { custom_css: css } });

    const tooLong = await mockApi
      .updateSignInExperience({ branding: { custom_css: "x".repeat(20_001) } })
      .catch((error: unknown) => error);
    expect(tooLong).toBeInstanceOf(ApiError);
    expect((tooLong as ApiError).status).toBe(400);

    const cleared = await mockApi.updateSignInExperience({ branding: { custom_css: "" } });
    expect(cleared.branding.custom_css).toBeNull();
  });

  it("sets the session and refresh-token lifetimes and refuses values outside their ranges", async () => {
    for (const body of [
      { session_ttl_secs: 3_599 },
      { session_ttl_secs: 7_776_001 },
      { refresh_token_ttl_secs: 3_599 },
      { refresh_token_ttl_secs: 31_536_001 },
    ]) {
      const failure = await mockApi.updateSignInExperience(body).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ApiError);
      expect((failure as ApiError).status).toBe(400);
    }

    const tuned = await mockApi.updateSignInExperience({
      session_ttl_secs: 604_800,
      refresh_token_ttl_secs: 1_209_600,
    });
    expect(tuned.session_ttl_secs).toBe(604_800);
    expect(tuned.refresh_token_ttl_secs).toBe(1_209_600);

    const audit = await mockApi.listAudit(ORG, {
      action: "sign_in_experience.updated",
      limit: 200,
    });
    expect(audit.items[0]?.payload).toMatchObject({
      session_ttl_secs: 604_800,
      refresh_token_ttl_secs: 1_209_600,
    });

    await mockApi.updateSignInExperience({
      session_ttl_secs: 2_592_000,
      refresh_token_ttl_secs: 2_592_000,
    });
  });
});

describe("webhooks", () => {
  it("registers a subscription, validates it, and never lists the signing key", async () => {
    const relative = await mockApi
      .createWebhook({ url: "/hook", events: ["account.created"] })
      .catch((error: unknown) => error);
    expect(relative).toBeInstanceOf(ApiError);
    expect((relative as ApiError).status).toBe(400);

    const unknown = await mockApi
      .createWebhook({ url: "https://receiver.example/hook", events: ["account.no_such_action"] })
      .catch((error: unknown) => error);
    expect(unknown).toBeInstanceOf(ApiError);
    expect((unknown as ApiError).status).toBe(400);

    const created = await mockApi.createWebhook({
      url: "https://receiver.example/hook",
      events: ["account.created", "account.created"],
    });
    expect(created.id).toMatch(/^whk_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
    expect(created.secret).toMatch(/^whsec_[0-9a-f]{64}$/);
    expect(created.events).toEqual(["account.created"]);
    expect(created.enabled).toBe(true);

    const list = await mockApi.listWebhooks();
    const row = list.items.find((item) => item.id === created.id);
    expect(row).toBeDefined();
    expect(row as object).not.toHaveProperty("secret");

    const audit = await mockApi.listAudit(ORG, { action: "webhook.created", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({ webhook_id: created.id });

    await mockApi.deleteWebhook(created.id);
  });

  it("records deliveries for matching events, pauses them, and rotates the key", async () => {
    const created = await mockApi.createWebhook({
      url: `https://receiver.example/${Date.now().toString(36)}`,
      events: ["account.created"],
    });

    const account = await mockApi.createAccount({
      email: `hooked-${Date.now().toString(36)}@demo.localhost`,
      display_name: "Hooked",
      password: "pw-hooked-123",
    });
    expect(account.id).toMatch(/^acc_/);

    const delivered = await mockApi.listWebhookDeliveries(created.id);
    const first = delivered.items[0];
    expect(first?.event).toBe("account.created");
    expect(first?.success).toBe(true);
    expect(first?.status_code).toBe(200);
    expect(first?.attempts).toBe(1);
    expect(first?.id).toMatch(/^dlv_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);

    const paused = await mockApi.updateWebhook(created.id, { enabled: false });
    expect(paused.enabled).toBe(false);
    await mockApi.createAccount({
      email: `paused-${Date.now().toString(36)}@demo.localhost`,
      display_name: "Paused",
      password: "pw-paused-123",
    });
    expect((await mockApi.listWebhookDeliveries(created.id)).items).toHaveLength(1);

    const rotated = await mockApi.rotateWebhookSecret(created.id);
    expect(rotated.id).toBe(created.id);
    expect(rotated.secret).toMatch(/^whsec_[0-9a-f]{64}$/);
    expect(rotated.secret).not.toBe(created.secret);

    const audit = await mockApi.listAudit(ORG, { action: "webhook.updated", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({ webhook_id: created.id, enabled: false });

    await mockApi.deleteWebhook(created.id);
    const second = await mockApi
      .deleteWebhook(created.id)
      .catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);
  });
});

describe("users", () => {
  async function freshEmail(prefix: string): Promise<string> {
    return `${prefix}-${Math.random().toString(36).slice(2, 8)}@example.com`;
  }

  it("lists the tenant directory newest first with typed ids and its seeded tenant roles", async () => {
    const page = await mockApi.listAccounts();
    expect(page.next).toBe(null);
    expect(page.items.length).toBeGreaterThanOrEqual(5);

    const created = page.items.map((account) => account.created_at);
    expect(created).toEqual([...created].sort((left, right) => right.localeCompare(left)));

    for (const account of page.items) {
      expect(account.id).toMatch(/^acc_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
      expect(Array.isArray(account.roles)).toBe(true);
    }

    const admin = page.items.find((account) => account.email === "admin@demo.localhost");
    expect(admin?.roles.map((role) => role.name)).toEqual(["contributor"]);
    const intern = page.items.find((account) => account.email === "intern@demo.localhost");
    expect(intern?.roles.map((role) => role.name)).toEqual(["viewer"]);

    expect(page.items.some((account) => account.state === "disabled")).toBe(true);
  });

  it("searches by email or display name, case-insensitively", async () => {
    const byEmail = await mockApi.listAccounts({ query: "ADMIN@DEMO" });
    expect(byEmail.items.length).toBeGreaterThan(0);
    expect(byEmail.items.every((account) => account.email.toLowerCase().includes("admin@demo"))).toBe(true);

    const byName = await mockApi.listAccounts({ query: "zhang" });
    expect(byName.items.some((account) => account.display_name.includes("Zhang"))).toBe(true);

    const limited = await mockApi.listAccounts({ limit: 2 });
    expect(limited.items.length).toBe(2);
  });

  it("creates a user, refuses a duplicate email, and appends account.created", async () => {
    const email = await freshEmail("ada");
    const created = await mockApi.createAccount({
      email,
      display_name: "Ada Lovelace",
      password: "correct horse",
    });
    expect(created.email).toBe(email);
    expect(created.state).toBe("active");
    expect(created.roles).toEqual([]);

    // Newest first, so the row the administrator just made is at the top of the directory.
    const page = await mockApi.listAccounts();
    expect(page.items[0]?.id).toBe(created.id);

    const audit = await mockApi.listAudit(ORG, { action: "account.created", limit: 200 });
    expect(audit.items.some((event) => event.subject.id === created.id)).toBe(true);

    const duplicate = await mockApi
      .createAccount({ email, display_name: "Copy", password: "x" })
      .catch((error: unknown) => error);
    expect(duplicate).toBeInstanceOf(ApiError);
    expect((duplicate as ApiError).code).toBe("MONACA_EMAIL_TAKEN");
    expect((duplicate as ApiError).status).toBe(409);

    const invalid = await mockApi
      .createAccount({ email: "not-an-address", display_name: "", password: "" })
      .catch((error: unknown) => error);
    expect((invalid as ApiError).status).toBe(400);
  });

  it("suspends and reactivates an account, recording one event per real change", async () => {
    const email = await freshEmail("grace");
    const account = await mockApi.createAccount({
      email,
      display_name: "Grace Hopper",
      password: "x",
    });

    const suspended = await mockApi.updateAccount(account.id, { state: "disabled" });
    expect(suspended.state).toBe("disabled");

    // Repeating the current state is a no-op and must not write a second audit event.
    await mockApi.updateAccount(account.id, { state: "disabled" });
    const suspendedEvents = await mockApi.listAudit(ORG, { action: "account.suspended", limit: 200 });
    expect(suspendedEvents.items.filter((event) => event.subject.id === account.id)).toHaveLength(1);

    const reactivated = await mockApi.updateAccount(account.id, { state: "active" });
    expect(reactivated.state).toBe("active");
    const reactivatedEvents = await mockApi.listAudit(ORG, { action: "account.reactivated", limit: 200 });
    expect(reactivatedEvents.items.some((event) => event.subject.id === account.id)).toBe(true);

    const unknown = await mockApi
      .updateAccount(newId("acc"), { state: "disabled" })
      .catch((error: unknown) => error);
    expect((unknown as ApiError).status).toBe(404);

    const malformed = await mockApi
      .updateAccount("acc_not-a-typed-id", { state: "disabled" })
      .catch((error: unknown) => error);
    expect((malformed as ApiError).status).toBe(400);
  });

  it("edits the display name and username from the directory", async () => {
    const first = await mockApi.createAccount({
      email: await freshEmail("edited"),
      display_name: "Before Name",
      password: "x",
    });
    const second = await mockApi.createAccount({
      email: await freshEmail("other"),
      display_name: "Other",
      password: "x",
    });

    const before = await mockApi.getAccount(first.id);
    expect(before.username).toBeNull();

    const empty = await mockApi
      .updateAccount(first.id, {})
      .catch((error: unknown) => error);
    expect((empty as ApiError).status).toBe(400);

    const blank = await mockApi
      .updateAccount(first.id, { display_name: "   " })
      .catch((error: unknown) => error);
    expect((blank as ApiError).status).toBe(400);

    const badUsername = await mockApi
      .updateAccount(first.id, { username: "Bad Name" })
      .catch((error: unknown) => error);
    expect((badUsername as ApiError).status).toBe(400);

    const username = `ada-${Date.now().toString(36)}`;
    const updated = await mockApi.updateAccount(first.id, {
      display_name: "After Name",
      username: username.toUpperCase(),
    });
    expect(updated.display_name).toBe("After Name");
    expect(updated.username).toBe(username);
    expect((await mockApi.getAccount(first.id)).username).toBe(username);

    const taken = await mockApi
      .updateAccount(second.id, { username })
      .catch((error: unknown) => error);
    expect(taken).toBeInstanceOf(ApiError);
    expect((taken as ApiError).code).toBe("MONACA_USERNAME_TAKEN");
    expect((taken as ApiError).status).toBe(409);

    const audit = await mockApi.listAudit(ORG, { action: "account.updated", limit: 200 });
    const event = audit.items.find((item) => item.subject.id === first.id);
    expect(event?.payload).toMatchObject({
      fields: ["display_name", "username"],
      display_name: "After Name",
      username,
    });
  });
});

describe("members", () => {
  it("adding an existing member is refused, and the audit trail records the new one", async () => {
    const existing = (await mockApi.listMembers(ORG)).items[0]!;
    await expect(mockApi.addMember(ORG, { account_id: existing.account_id, role: "member" })).rejects.toThrow(
      /already a member/,
    );
  });

  it("adding an unknown account is a 404", async () => {
    const failure = await mockApi
      .addMember(ORG, { account_id: newId("acc"), role: "member" })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).status).toBe(404);
  });
});

describe("organization email domains", () => {
  async function freshDomain(): Promise<string> {
    return `team-${Math.random().toString(36).slice(2, 8)}.example.com`;
  }

  it("lists the seeded domain oldest first", async () => {
    const page = await mockApi.listOrgEmailDomains(ORG);
    expect(page.next).toBe(null);
    expect(page.items.map((entry) => entry.domain)).toEqual(["demo.localhost"]);
    expect(Number.isNaN(Date.parse(page.items[0]!.created_at))).toBe(false);
  });

  it("normalises a domain, registers it, and appends org.domain.added", async () => {
    const raw = await freshDomain();
    const created = await mockApi.addOrgEmailDomain(ORG, { domain: `  ${raw.toUpperCase()} ` });
    expect(created.domain).toBe(raw);

    const listed = await mockApi.listOrgEmailDomains(ORG);
    expect(listed.items.some((entry) => entry.domain === raw)).toBe(true);

    const audit = await mockApi.listAudit(ORG, { action: "org.domain.added", limit: 200 });
    const newest = audit.items[0];
    expect(newest?.payload).toMatchObject({ org: ORG, domain: raw });
    expect(newest?.subject.type).toBe("org");

    await mockApi.removeOrgEmailDomain(ORG, raw);
  });

  it("refuses a duplicate domain and a malformed DNS name", async () => {
    const duplicate = await mockApi
      .addOrgEmailDomain(ORG, { domain: "Demo.LocalHost" })
      .catch((error: unknown) => error);
    expect(duplicate).toBeInstanceOf(ApiError);
    expect((duplicate as ApiError).status).toBe(409);
    expect((duplicate as ApiError).code).toBe("MONACA_DOMAIN_EXISTS");

    for (const bad of ["a", "@", "x..y", "-x.example.com", "x.example.com."]) {
      const rejected = await mockApi
        .addOrgEmailDomain(ORG, { domain: bad })
        .catch((error: unknown) => error);
      expect(rejected).toBeInstanceOf(ApiError);
      expect((rejected as ApiError).status).toBe(400);
    }
  });

  it("removes a domain, refuses the second removal, and records org.domain.removed", async () => {
    const raw = await freshDomain();
    await mockApi.addOrgEmailDomain(ORG, { domain: raw });
    await mockApi.removeOrgEmailDomain(ORG, raw);

    expect((await mockApi.listOrgEmailDomains(ORG)).items.some((entry) => entry.domain === raw)).toBe(false);

    const second = await mockApi.removeOrgEmailDomain(ORG, raw).catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);

    const audit = await mockApi.listAudit(ORG, { action: "org.domain.removed", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({ org: ORG, domain: raw });
  });

  it("is org-scoped: an unknown slug is a 404 and does not touch the directory", async () => {
    const missing = await mockApi
      .listOrgEmailDomains("no-such-org")
      .catch((error: unknown) => error);
    expect(missing).toBeInstanceOf(ApiError);
    expect((missing as ApiError).status).toBe(404);

    const added = await mockApi
      .addOrgEmailDomain("no-such-org", { domain: await freshDomain() })
      .catch((error: unknown) => error);
    expect(added).toBeInstanceOf(ApiError);
    expect((added as ApiError).status).toBe(404);

    expect((await mockApi.listOrgEmailDomains(ORG)).items.map((entry) => entry.domain)).toEqual([
      "demo.localhost",
    ]);
  });
});

describe("organization invitations", () => {
  async function freshEmail(): Promise<string> {
    return `invitee-${Math.random().toString(36).slice(2, 8)}@demo.localhost`;
  }

  it("lists the seeded pending invitation with its role and expiry", async () => {
    const page = await mockApi.listOrgInvitations(ORG);
    expect(page.next).toBe(null);
    const seeded = page.items.find((entry) => entry.email === "new-teammate@demo.localhost");
    expect(seeded?.role).toBe("member");
    expect(seeded?.id.startsWith("inv_")).toBe(true);
    expect(Date.parse(seeded?.expires_at ?? "") > Date.now()).toBe(true);
  });

  it("normalises an address, invites it, and appends org.invitation.created", async () => {
    const raw = await freshEmail();
    const created = await mockApi.createOrgInvitation(ORG, {
      email: `  ${raw.toUpperCase()} `,
      role: "admin",
      expires_in_days: 3,
    });
    expect(created.email).toBe(raw);
    expect(created.role).toBe("admin");
    expect(created.id.startsWith("inv_")).toBe(true);
    expect(created.invited_by).toBe((await mockApi.getSession()).account_id);

    const listed = await mockApi.listOrgInvitations(ORG);
    expect(listed.items.some((entry) => entry.id === created.id)).toBe(true);

    const audit = await mockApi.listAudit(ORG, { action: "org.invitation.created", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({ org: ORG, email: raw, role: "admin" });
    expect(audit.items[0]?.subject.type).toBe("org");

    await mockApi.revokeOrgInvitation(ORG, created.id);
  });

  it("refuses a live duplicate and malformed addresses", async () => {
    const duplicate = await mockApi
      .createOrgInvitation(ORG, { email: "New-Teammate@Demo.LocalHost" })
      .catch((error: unknown) => error);
    expect(duplicate).toBeInstanceOf(ApiError);
    expect((duplicate as ApiError).status).toBe(409);
    expect((duplicate as ApiError).code).toBe("MONACA_INVITATION_EXISTS");

    for (const bad of ["", "teammate", "@example.com", "teammate@", "two@@at.com", "a b@c.d"]) {
      const rejected = await mockApi
        .createOrgInvitation(ORG, { email: bad })
        .catch((error: unknown) => error);
      expect(rejected).toBeInstanceOf(ApiError);
      expect((rejected as ApiError).status).toBe(400);
    }

    const badExpiry = await mockApi
      .createOrgInvitation(ORG, { email: await freshEmail(), expires_in_days: 0 })
      .catch((error: unknown) => error);
    expect(badExpiry).toBeInstanceOf(ApiError);
    expect((badExpiry as ApiError).status).toBe(400);
  });

  it("revokes an invitation, refuses the second revoke, and records org.invitation.revoked", async () => {
    const created = await mockApi.createOrgInvitation(ORG, { email: await freshEmail() });
    await mockApi.revokeOrgInvitation(ORG, created.id);

    expect((await mockApi.listOrgInvitations(ORG)).items.some((entry) => entry.id === created.id)).toBe(false);

    const second = await mockApi
      .revokeOrgInvitation(ORG, created.id)
      .catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);

    const audit = await mockApi.listAudit(ORG, { action: "org.invitation.revoked", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({ org: ORG, email: created.email, invitation: created.id });
    expect(audit.items[0]?.decision).toBe("deny");
  });

  it("is org-scoped: an unknown slug is a 404 for reads and writes", async () => {
    for (const call of [
      () => mockApi.listOrgInvitations("no-such-org"),
      () => mockApi.createOrgInvitation("no-such-org", { email: "someone@example.com" }),
      () => mockApi.revokeOrgInvitation("no-such-org", newId("inv")),
    ]) {
      const missing = await call().catch((error: unknown) => error);
      expect(missing).toBeInstanceOf(ApiError);
      expect((missing as ApiError).status).toBe(404);
    }
  });
});

describe("tenant roles", () => {
  async function freshRoleName(): Promise<string> {
    return `role-${Math.random().toString(36).slice(2, 8)}`;
  }

  async function accountByEmail(email: string) {
    const page = await mockApi.listAccounts();
    const account = page.items.find((candidate) => candidate.email === email);
    if (!account) throw new Error(`test account ${email} is missing`);
    return account;
  }

  it("lists the seeded roles by name with typed ids and their permissions", async () => {
    const page = await mockApi.listTenantRoles();
    expect(page.next).toBe(null);
    const names = page.items.map((role) => role.name);
    expect(names).toEqual([...names].sort((left, right) => left.localeCompare(right)));
    expect(names).toContain("contributor");
    expect(names).toContain("viewer");

    for (const role of page.items) {
      expect(role.id).toMatch(/^rol_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
      expect(Array.isArray(role.permissions)).toBe(true);
    }
  });

  it("creates a role, drops duplicate permissions, and appends role.created", async () => {
    const name = await freshRoleName();
    const created = await mockApi.createTenantRole({
      name: `  ${name}  `,
      description: "  A test role.  ",
      permissions: ["tools:read", "tools:read", "tools:write"],
    });
    expect(created.name).toBe(name);
    expect(created.description).toBe("A test role.");
    expect(created.permissions).toEqual(["tools:read", "tools:write"]);

    const listed = await mockApi.listTenantRoles();
    expect(listed.items.some((role) => role.id === created.id)).toBe(true);

    const audit = await mockApi.listAudit(ORG, { action: "role.created", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({ name });
    expect(audit.items[0]?.subject.type).toBe("tenant");

    await mockApi.deleteTenantRole(created.id);
  });

  it("refuses a duplicate name, an empty name, and an invalid permission", async () => {
    const duplicate = await mockApi
      .createTenantRole({ name: "viewer", description: "", permissions: [] })
      .catch((error: unknown) => error);
    expect(duplicate).toBeInstanceOf(ApiError);
    expect((duplicate as ApiError).status).toBe(409);
    expect((duplicate as ApiError).code).toBe("MONACA_ROLE_EXISTS");

    const empty = await mockApi
      .createTenantRole({ name: "   ", description: "", permissions: [] })
      .catch((error: unknown) => error);
    expect((empty as ApiError).status).toBe(400);

    const badPermission = await mockApi
      .createTenantRole({
        name: await freshRoleName(),
        description: "",
        permissions: ["two words"],
      })
      .catch((error: unknown) => error);
    expect((badPermission as ApiError).status).toBe(400);
  });

  it("assigns a role idempotently, reflects it on the directory row, and unassigns it", async () => {
    const account = await accountByEmail("sam.oduya@demo.localhost");
    const role = (await mockApi.listTenantRoles()).items.find((candidate) => candidate.name === "contributor");
    if (!role) throw new Error("the seeded contributor role is missing");

    await mockApi.assignAccountRole(account.id, role.id);
    await mockApi.assignAccountRole(account.id, role.id);
    const holder = await accountByEmail(account.email);
    expect(holder.roles.map((held) => held.name)).toEqual(["contributor"]);

    // An assignment is what the account row carries, so it is also what the UI reads.
    expect(holder.roles).toEqual([{ id: role.id, name: role.name }]);

    await mockApi.unassignAccountRole(account.id, role.id);
    const freed = await accountByEmail(account.email);
    expect(freed.roles).toEqual([]);
  });

  it("refuses an unknown account or role, and a missing assignment is a 404", async () => {
    const viewer = (await mockApi.listTenantRoles()).items.find((role) => role.name === "viewer")!;
    const account = await accountByEmail("priya.raman@demo.localhost");

    const unknownAccount = await mockApi
      .assignAccountRole(newId("acc"), viewer.id)
      .catch((error: unknown) => error);
    expect((unknownAccount as ApiError).status).toBe(404);

    const unknownRole = await mockApi
      .assignAccountRole(account.id, newId("rol"))
      .catch((error: unknown) => error);
    expect((unknownRole as ApiError).status).toBe(404);

    const missing = await mockApi
      .unassignAccountRole(account.id, viewer.id)
      .catch((error: unknown) => error);
    expect((missing as ApiError).status).toBe(404);
  });

  it("deleting a role removes every assignment and records role.deleted", async () => {
    const name = await freshRoleName();
    const role = await mockApi.createTenantRole({
      name,
      description: "",
      permissions: ["tools:read"],
    });
    const account = await accountByEmail("priya.raman@demo.localhost");
    await mockApi.assignAccountRole(account.id, role.id);

    await mockApi.deleteTenantRole(role.id);
    const freed = await accountByEmail(account.email);
    expect(freed.roles.some((held) => held.id === role.id)).toBe(false);

    const second = await mockApi.deleteTenantRole(role.id).catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);

    const audit = await mockApi.listAudit(ORG, { action: "role.deleted", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({ name });
  });
});

describe("account sessions", () => {
  async function accountByEmail(email: string) {
    const page = await mockApi.listAccounts();
    const account = page.items.find((candidate) => candidate.email === email);
    if (!account) throw new Error(`test account ${email} is missing`);
    return account;
  }

  it("lists live sessions newest activity first, and none for a suspended account", async () => {
    const admin = await accountByEmail("admin@demo.localhost");
    const page = await mockApi.listAccountSessions(admin.id);
    expect(page.next).toBe(null);
    expect(page.items).toHaveLength(2);
    for (const session of page.items) {
      expect(session.id).toMatch(/^ses_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
      expect(session.account_id).toBe(admin.id);
      expect(Number.isNaN(Date.parse(session.last_seen_at))).toBe(false);
    }
    const seen = page.items.map((session) => session.last_seen_at);
    expect(seen).toEqual([...seen].sort((left, right) => right.localeCompare(left)));

    const intern = await accountByEmail("intern@demo.localhost");
    expect((await mockApi.listAccountSessions(intern.id)).items).toEqual([]);
  });

  it("revokes one session, appends session.revoked, and refuses a second revoke", async () => {
    const admin = await accountByEmail("admin@demo.localhost");
    const target = (await mockApi.listAccountSessions(admin.id)).items[0]!;

    await mockApi.revokeAccountSession(admin.id, target.id);
    expect((await mockApi.listAccountSessions(admin.id)).items).toHaveLength(1);

    const audit = await mockApi.listAudit(ORG, { action: "session.revoked", limit: 200 });
    const newest = audit.items[0];
    expect(newest?.subject.type).toBe("session");
    expect(newest?.subject.id).toBe(target.id);
    expect(newest?.payload).toMatchObject({ account_id: admin.id });

    const second = await mockApi
      .revokeAccountSession(admin.id, target.id)
      .catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);

    // A session may only be revoked through the account that owns it.
    const sam = await accountByEmail("sam.oduya@demo.localhost");
    const foreign = (await mockApi.listAccountSessions(sam.id)).items[0]!;
    const wrongOwner = await mockApi
      .revokeAccountSession(admin.id, foreign.id)
      .catch((error: unknown) => error);
    expect(wrongOwner).toBeInstanceOf(ApiError);
    expect((wrongOwner as ApiError).status).toBe(404);
  });

  it("revokes every session at once and records the count", async () => {
    const sam = await accountByEmail("sam.oduya@demo.localhost");
    expect((await mockApi.listAccountSessions(sam.id)).items).toHaveLength(1);

    const result = await mockApi.revokeAccountSessions(sam.id);
    expect(result.revoked).toBe(1);
    expect((await mockApi.listAccountSessions(sam.id)).items).toEqual([]);

    const audit = await mockApi.listAudit(ORG, { action: "session.revoked_all", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({ revoked: 1 });

    // Repeating it is a valid no-op, not a 404.
    expect((await mockApi.revokeAccountSessions(sam.id)).revoked).toBe(0);
  });

  it("suspending an account revokes its sessions, and reactivating does not restore them", async () => {
    const wei = await accountByEmail("wei.zhang@demo.localhost");
    expect((await mockApi.listAccountSessions(wei.id)).items).toHaveLength(1);

    await mockApi.updateAccount(wei.id, { state: "disabled" });
    expect((await mockApi.listAccountSessions(wei.id)).items).toEqual([]);

    await mockApi.updateAccount(wei.id, { state: "active" });
    expect((await mockApi.listAccountSessions(wei.id)).items).toEqual([]);
  });

  it("an unknown account is a 404 and an unknown session id is a 400", async () => {
    const missing = await mockApi
      .listAccountSessions(newId("acc"))
      .catch((error: unknown) => error);
    expect((missing as ApiError).status).toBe(404);

    const admin = await accountByEmail("admin@demo.localhost");
    const malformed = await mockApi
      .revokeAccountSession(admin.id, "ses_not-a-typed-id")
      .catch((error: unknown) => error);
    expect((malformed as ApiError).status).toBe(400);
  });
});

describe("account security", () => {
  async function account(email: string): Promise<AccountWithRoles> {
    const page = await mockApi.listAccounts();
    const found = page.items.find((candidate) => candidate.email === email);
    if (!found) throw new Error(`${email} is missing from the fixture`);
    return found;
  }

  it("reports the seeded authenticator and passkey", async () => {
    const wei = await account("wei.zhang@demo.localhost");
    const security = await mockApi.getAccountSecurity(wei.id);
    expect(security.mfa.totp).toBe(true);
    expect(security.mfa.backup_codes).toBe(4);
    expect(security.passkeys).toHaveLength(1);
    expect(security.passkeys[0]?.id.startsWith("pky_")).toBe(true);
    expect(security.trusted_devices).toBe(1);
  });

  it("reports nothing enrolled for a fresh account", async () => {
    const sam = await account("sam.oduya@demo.localhost");
    const security = await mockApi.getAccountSecurity(sam.id);
    expect(security.mfa).toEqual({ totp: false, backup_codes: 0 });
    expect(security.passkeys).toEqual([]);
    expect(security.trusted_devices).toBe(0);
  });

  it("resets the authenticator and appends account.security_changed", async () => {
    const wei = await account("wei.zhang@demo.localhost");
    await mockApi.resetAccountMfa(wei.id);

    const security = await mockApi.getAccountSecurity(wei.id);
    expect(security.mfa).toEqual({ totp: false, backup_codes: 0 });
    // Passkeys are separate credentials and survive the reset.
    expect(security.passkeys).toHaveLength(1);

    const audit = await mockApi.listAudit(ORG, { action: "account.security_changed", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({ account_id: wei.id, kind: "mfa_reset" });
    expect(audit.items[0]?.decision).toBe("deny");
  });

  it("removes one passkey and refuses one it does not have", async () => {
    const wei = await account("wei.zhang@demo.localhost");
    const passkey = (await mockApi.getAccountSecurity(wei.id)).passkeys[0];
    if (!passkey) throw new Error("the seeded passkey is missing");

    await mockApi.deleteAccountPasskey(wei.id, passkey.id);
    expect((await mockApi.getAccountSecurity(wei.id)).passkeys).toEqual([]);

    const second = await mockApi
      .deleteAccountPasskey(wei.id, passkey.id)
      .catch((error: unknown) => error);
    expect(second).toBeInstanceOf(ApiError);
    expect((second as ApiError).status).toBe(404);

    const audit = await mockApi.listAudit(ORG, { action: "account.security_changed", limit: 200 });
    expect(audit.items[0]?.payload).toMatchObject({
      account_id: wei.id,
      kind: "passkey_removed",
      passkey: passkey.id,
    });
  });

  it("an unknown account is a 404 and a missing passkey is a 404", async () => {
    const missing = await mockApi.getAccountSecurity(newId("acc")).catch((error: unknown) => error);
    expect((missing as ApiError).status).toBe(404);

    const sam = await account("sam.oduya@demo.localhost");
    const noPasskey = await mockApi
      .deleteAccountPasskey(sam.id, newId("pky"))
      .catch((error: unknown) => error);
    expect((noPasskey as ApiError).status).toBe(404);
  });
});
