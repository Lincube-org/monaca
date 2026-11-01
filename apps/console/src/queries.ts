import { useMutation, useQuery, useQueryClient, type UseQueryReturnType } from "@tanstack/vue-query";
import { computed, toValue, type MaybeRefOrGetter } from "vue";

import { api } from "@/api";
import { queryKeys } from "@/api/keys";
import type {
  AddMemberRequest,
  Agent,
  AuditEvent,
  AuditIntegrity,
  Client,
  ClientSecret,
  CreateAgentRequest,
  CreateClientRequest,
  CreateGrantRequest,
  CreateOrganizationRequest,
  CreatedClient,
  Grant,
  ListAuditQuery,
  Member,
  Organization,
  Page,
  RegisterAgentKeyRequest,
  SessionInfo,
  UpdateClientRequest,
  UpdateOrganizationRequest,
} from "@/api/types";

/**
 * The one place the console talks to the API.
 *
 * Pages import these hooks and never `api` directly, so every fetch has a cache key, a retry policy
 * and an invalidation rule in one file. `org` is passed as a getter rather than a string because the
 * header's org switcher can change it at any time — a captured string would keep a stale page
 * mounted against the wrong organization.
 */

const STALE = {
  /** Membership and grants change rarely; a minute of staleness is invisible and saves round trips. */
  slow: 60_000,
  /** Audit grows constantly, so it is refetched by focus rather than trusted for long. */
  fast: 10_000,
} as const;

type OrgRef = MaybeRefOrGetter<string>;

function orgValue(org: OrgRef): string {
  return toValue(org);
}

export function useSession(): UseQueryReturnType<SessionInfo, Error> {
  return useQuery({
    queryKey: queryKeys.session(),
    queryFn: () => api.getSession(),
    staleTime: STALE.slow,
    retry: false,
  });
}

export function useOrganizations(): UseQueryReturnType<Page<Organization>, Error> {
  return useQuery({
    queryKey: queryKeys.organizations(),
    queryFn: () => api.listOrganizations(),
    staleTime: STALE.slow,
  });
}

export function useCreateOrganization() {
  const client = useQueryClient();
  return useMutation<Organization, Error, CreateOrganizationRequest>({
    mutationFn: (body) => api.createOrganization(body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.organizations() });
      // A new org is not a membership yet, but the session's org list is what the header offers.
      void client.invalidateQueries({ queryKey: queryKeys.session() });
    },
  });
}

export function useUpdateOrganization() {
  const client = useQueryClient();
  return useMutation<Organization, Error, { organizationId: string; body: UpdateOrganizationRequest }>({
    mutationFn: ({ organizationId, body }) => api.updateOrganization(organizationId, body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.organizations() });
    },
  });
}

export function useClients(): UseQueryReturnType<Page<Client>, Error> {
  return useQuery({
    queryKey: queryKeys.clients(),
    queryFn: () => api.listClients(),
    staleTime: STALE.slow,
  });
}

export function useCreateClient() {
  const client = useQueryClient();
  return useMutation<CreatedClient, Error, CreateClientRequest>({
    mutationFn: (body) => api.createClient(body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.clients() });
      invalidateTenantAudit(client);
    },
  });
}

export function useUpdateClient() {
  const client = useQueryClient();
  return useMutation<Client, Error, { clientId: string; body: UpdateClientRequest }>({
    mutationFn: ({ clientId, body }) => api.updateClient(clientId, body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.clients() });
      invalidateTenantAudit(client);
    },
  });
}

export function useRotateClientSecret() {
  const client = useQueryClient();
  return useMutation<ClientSecret, Error, { clientId: string }>({
    mutationFn: ({ clientId }) => api.rotateClientSecret(clientId),
    onSuccess: () => invalidateTenantAudit(client),
  });
}

export function useDeleteClient() {
  const client = useQueryClient();
  return useMutation<void, Error, { clientId: string }>({
    mutationFn: ({ clientId }) => api.deleteClient(clientId),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.clients() });
      invalidateTenantAudit(client);
    },
  });
}

export function useMembers(org: OrgRef): UseQueryReturnType<Page<Member>, Error> {
  return useQuery({
    queryKey: computed(() => queryKeys.members(orgValue(org))),
    queryFn: () => api.listMembers(orgValue(org)),
    staleTime: STALE.slow,
  });
}

export function useAgents(org: OrgRef): UseQueryReturnType<Page<Agent>, Error> {
  return useQuery({
    queryKey: computed(() => queryKeys.agents(orgValue(org))),
    queryFn: () => api.listAgents(orgValue(org)),
    staleTime: STALE.slow,
  });
}

export function useGrants(org: OrgRef): UseQueryReturnType<Page<Grant>, Error> {
  return useQuery({
    queryKey: computed(() => queryKeys.grants(orgValue(org))),
    queryFn: () => api.listGrants(orgValue(org)),
    staleTime: STALE.slow,
  });
}

export function useAudit(
  org: OrgRef,
  query: MaybeRefOrGetter<ListAuditQuery> = {},
): UseQueryReturnType<Page<AuditEvent>, Error> {
  return useQuery({
    queryKey: computed(() => queryKeys.audit(orgValue(org), toValue(query))),
    queryFn: () => api.listAudit(orgValue(org), toValue(query)),
    staleTime: STALE.fast,
  });
}

/**
 * Chain verification is a mutation, not a query: it is expensive server-side, it is triggered by a
 * deliberate click, and its answer is a verdict about a moment rather than a cached fact. Modelling
 * it as a query would make it silently re-run on every window focus.
 */
export function useVerifyAudit(org: OrgRef) {
  return useMutation<AuditIntegrity, Error, void>({
    mutationFn: () => api.verifyAudit(orgValue(org)),
  });
}

export function useAddMember(org: OrgRef) {
  const client = useQueryClient();
  return useMutation<Member, Error, AddMemberRequest>({
    mutationFn: (body) => api.addMember(orgValue(org), body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.members(orgValue(org)) });
      invalidateAudit(client, orgValue(org));
    },
  });
}

export function useCreateAgent(org: OrgRef) {
  const client = useQueryClient();
  return useMutation<Agent, Error, CreateAgentRequest>({
    mutationFn: (body) => api.createAgent(orgValue(org), body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.agents(orgValue(org)) });
      invalidateAudit(client, orgValue(org));
    },
  });
}

export function useRegisterAgentKey(org: OrgRef) {
  const client = useQueryClient();
  return useMutation<Agent, Error, { agentId: string; body: RegisterAgentKeyRequest }>({
    mutationFn: ({ agentId, body }) => api.registerAgentKey(orgValue(org), agentId, body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.agents(orgValue(org)) });
      invalidateAudit(client, orgValue(org));
    },
  });
}

export function useRevokeAgentKey(org: OrgRef) {
  const client = useQueryClient();
  return useMutation<void, Error, { agentId: string; keyId: string }>({
    mutationFn: ({ agentId, keyId }) => api.revokeAgentKey(orgValue(org), agentId, keyId),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.agents(orgValue(org)) });
      invalidateAudit(client, orgValue(org));
    },
  });
}

export function useCreateGrant(org: OrgRef) {
  const client = useQueryClient();
  return useMutation<Grant, Error, CreateGrantRequest>({
    mutationFn: (body) => api.createGrant(orgValue(org), body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.grants(orgValue(org)) });
      invalidateAudit(client, orgValue(org));
    },
  });
}

export function useRevokeGrant(org: OrgRef) {
  const client = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (grantId) => api.revokeGrant(orgValue(org), grantId),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.grants(orgValue(org)) });
      invalidateAudit(client, orgValue(org));
    },
  });
}

/**
 * Every write also appends an audit event (§8.3), so a stale audit list is a stale *claim*. Refresh
 * the first page only — older pages are history and cannot change.
 */
function invalidateAudit(client: ReturnType<typeof useQueryClient>, org: string): void {
  void client.invalidateQueries({ queryKey: ["audit", org], exact: false });
}

/** Client writes are tenant-level, so every org's audit view may have gained an entry. */
function invalidateTenantAudit(client: ReturnType<typeof useQueryClient>): void {
  void client.invalidateQueries({ queryKey: ["audit"], exact: false });
}
