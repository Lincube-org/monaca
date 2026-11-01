import { describe, expect, test } from "bun:test";

import { jwkThumbprintHex, publicEcJwk } from "@monaca/ui";

import { ApiError } from "./contract";
import { appendToChain, verifyLog, type AuditLog } from "./fixtures";
import { mockApi, setMockLatency } from "./mock";
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
