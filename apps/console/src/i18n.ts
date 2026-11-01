/**
 * Every user-visible string in the console, in one place.
 *
 * The app is English-only in M0, but no component holds a literal: strings live here so a locale
 * layer can be dropped in without touching a template, and so the vocabulary stays consistent —
 * "agent" is always an agent, "grant" always a grant, and an action keeps the same name from the
 * button that starts it to the toast that confirms it.
 *
 * Interpolation uses `{name}` placeholders resolved by `t()`.
 */
export const messages = {
  app: {
    name: "monaca",
    tagline: "Identity for agents",
    console: "Console",
  },
  nav: {
    overview: "Overview",
    organizations: "Organizations",
    members: "Members",
    agents: "Agents",
    grants: "Grants",
    audit: "Audit",
    settings: "Settings",
    primary: "Console",
    section: "Tenant",
    collapse: "Collapse sidebar",
    expand: "Expand sidebar",
  },
  org: {
    switcherLabel: "Tenant and organization",
    tenant: "Tenant",
    organization: "Organization",
    noOrgs: "No organizations",
    role: "Role",
  },
  theme: {
    toggle: "Switch theme",
    light: "Light",
    dark: "Dark",
    system: "System",
  },
  session: {
    signedInAs: "Signed in as",
    signOut: "Sign out",
    signOutFailed: "Could not sign out",
    reauthNeeded: "Your session expired",
    reauthHint: "Sign in again to keep working.",
    signIn: "Sign in",
    mocks: "Mock data",
    mocksHint: "The console is reading a local mock layer. No server is involved.",
  },
  common: {
    retry: "Retry",
    cancel: "Cancel",
    close: "Close",
    copy: "Copy",
    copied: "Copied",
    loading: "Loading",
    saving: "Saving",
    search: "Search",
    refresh: "Refresh",
    actions: "Actions",
    details: "Details",
    none: "None",
    never: "Never",
    unknown: "Unknown",
    of: "of",
    page: "Page",
    previous: "Previous",
    next: "Next",
    yes: "Yes",
    no: "No",
  },
  error: {
    title: "Something went wrong",
    loadFailed: "Could not load this page",
    loadFailedHint: "The request to the gateway failed. Check that it is running, then retry.",
    notFound: "Not found",
    notFoundHint: "That page does not exist in the console.",
    backToOverview: "Back to overview",
  },
  overview: {
    title: "Overview",
    subtitle: "Access activity in {org}",
    agents: "Active agents",
    grants: "Live grants",
    members: "Members",
    decisions24h: "Decisions, last 24h",
    recent: "Recent decisions",
    recentHint: "The newest audit entries in this organization.",
    viewAll: "Open audit",
    chain: "Audit chain",
    chainHint: "Every decision is appended to a per-org hash chain. Anyone can re-verify it.",
    chainHead: "Chain head",
    chainSeq: "Entries",
    chainVerified: "Verified",
    chainUnverified: "Not verified yet",
    chainBroken: "Verification failed",
    verifyNow: "Verify chain",
    verifying: "Verifying",
    allowRate: "Allowed",
    denied: "Denied",
    noEvents: "No decisions recorded yet",
  },
  organizations: {
    title: "Organizations",
    subtitle: "Every organization in tenant {tenant}",
    slug: "Slug",
    state: "State",
    created: "Created",
    stateActive: "Active",
    stateArchived: "Archived",
    defaultBadge: "Default",
    create: "New organization",
    createTitle: "Create an organization",
    createDescription:
      "Provisioning creates the org's schema, its role and its own audit chain. The slug cannot change later.",
    slugField: "Slug",
    slugHint: "2–31 lowercase letters, digits or dashes, such as acme-team.",
    createdToast: "Organization created",
    createdDescription: "{slug} is provisioned and ready for members.",
    createFailed: "Could not create the organization",
    archive: "Archive",
    archiveTitle: "Archive {slug}?",
    archiveDescription:
      "The slug stops resolving for sign-in and for its member, agent and grant endpoints. The schema and its audit chain are kept, and reactivating restores access.",
    archivedToast: "Organization archived",
    archivedDescription: "{slug} no longer accepts new sign-ins.",
    reactivate: "Reactivate",
    reactivatedToast: "Organization reactivated",
    reactivatedDescription: "{slug} is serving again.",
    actionFailed: "Could not update the organization",
    defaultHint: "The default organization cannot be archived.",
    empty: "No organizations",
    emptyHint: "Create an organization to give a group its own members and agents.",
    count: "{count} organizations",
  },
  members: {
    title: "Members",
    subtitle: "Accounts with access to {org}",
    account: "Account",
    email: "Email",
    role: "Role",
    joined: "Added",
    invite: "Add member",
    inviteTitle: "Add a member to {org}",
    inviteDescription: "The account must already exist in this tenant.",
    accountId: "Account ID",
    accountIdHint: "A typed account id, such as acc_01h455vb4pex5vsknk084sn02q.",
    roleOwner: "Owner",
    roleAdmin: "Admin",
    roleMember: "Member",
    added: "Member added",
    addedDescription: "{email} now has the {role} role.",
    addFailed: "Could not add the member",
    empty: "No members yet",
    emptyHint: "Add an account to give it access to this organization.",
    count: "{count} members",
  },
  agents: {
    title: "Agents",
    subtitle: "Non-human identities acting in {org}",
    name: "Name",
    description: "Description",
    owner: "Acts for",
    state: "State",
    keys: "Keys",
    created: "Created",
    register: "Register agent",
    registerTitle: "Register an agent",
    registerDescription:
      "The key pair is generated in this browser. The private key never leaves it — only the public key is uploaded.",
    registerName: "Agent name",
    registerNameHint: "Lowercase letters, digits and dashes. Used as the client id in logs.",
    registerDescriptionField: "Description",
    registerOwner: "Owner account",
    registerOwnerHint: "The account this agent acts for. Must be a member of this organization.",
    generate: "Generate key pair and register",
    generating: "Generating key",
    registering: "Registering",
    keyPair: "Key pair",
    keyPairHint: "ES256 (P-256). Generated with WebCrypto in this tab.",
    fingerprint: "JWK thumbprint",
    fingerprintHint: "RFC 7638 sha256 of the canonical public JWK. The server stores this value.",
    publicJwk: "Public key",
    privateJwk: "Private key",
    downloadPrivate: "Download private key",
    downloadPrivateHint:
      "This file is the agent's only credential. Download it now — it cannot be recovered, and it is never uploaded.",
    downloaded: "Private key downloaded",
    downloadFailed: "Could not download the key",
    done: "Done",
    registered: "Agent registered",
    registeredDescription: "{name} can now be granted scopes.",
    registerFailed: "Could not register the agent",
    empty: "No agents yet",
    emptyHint: "Register an agent to give a workload a delegable identity.",
    keyCount: "{count} keys",
    noKeys: "No keys",
    revokeKey: "Revoke key",
    revokeKeyTitle: "Revoke this key?",
    revokeKeyDescription: "Tokens signed with {kid} stop verifying immediately. This cannot be undone.",
    keyRevoked: "Key revoked",
    revokeFailed: "Could not revoke the key",
    stateActive: "Active",
    stateDisabled: "Disabled",
    count: "{count} agents",
  },
  grants: {
    title: "Grants",
    subtitle: "What an agent may do, and for whom",
    agent: "Agent",
    delegator: "Delegator",
    scopes: "Scopes",
    resource: "Resource",
    expires: "Expires",
    created: "Created",
    status: "Status",
    statusActive: "Active",
    statusRevoked: "Revoked",
    statusExpired: "Expired",
    revoke: "Revoke grant",
    revokeTitle: "Revoke this grant?",
    revokeDescription:
      "New tokens for {agent} stop being minted immediately. Tokens already issued stay valid until they expire.",
    revoked: "Grant revoked",
    revokeFailed: "Could not revoke the grant",
    empty: "No grants yet",
    emptyHint: "A grant lets an agent act for an account, within a fixed set of scopes.",
    count: "{count} grants",
    filterStatus: "Status",
    filterAll: "All",
  },
  audit: {
    title: "Audit",
    subtitle: "Every decision recorded in {org}",
    action: "Action",
    filterAction: "Action",
    filterGrant: "Grant",
    filterAll: "All actions",
    verify: "Verify chain",
    verifying: "Verifying",
    verified: "Chain verified",
    verifiedDescription: "{count} entries recomputed and matched.",
    broken: "Chain verification failed",
    brokenDescription: "First mismatch at entry {seq}: {reason}.",
    verifyFailed: "Could not verify the chain",
    empty: "No audit entries",
    emptyHint: "Entries appear here as soon as an agent requests a token or calls a tool.",
    count: "{count} entries",
    loadMore: "Load older entries",
    live: "Live",
  },
  settings: {
    title: "Settings",
    subtitle: "Console and tenant configuration",
    appearance: "Appearance",
    appearanceHint: "The console follows your system theme until you choose one.",
    theme: "Theme",
    identity: "Signed-in identity",
    tenant: "Tenant",
    account: "Account",
    organization: "Organization",
    tokenTtl: "Access token lifetime",
    tokenTtlHint: "Set by the server; the console does not choose it.",
    mockMode: "Mock data",
    mockModeHint:
      "VITE_USE_MOCKS is on, so every page renders a local fixture. Set it to false to talk to the gateway BFF.",
    diagnostics: "Diagnostics",
    gateway: "Gateway origin",
    buildMode: "Build mode",
    copyDiagnostics: "Copy diagnostics",
    diagnosticsCopied: "Diagnostics copied",
  },
} as const;

type Leaves<T, Prefix extends string = ""> = {
  [K in keyof T & string]: T[K] extends string
    ? `${Prefix}${K}`
    : Leaves<T[K], `${Prefix}${K}.`>;
}[keyof T & string];

/** Every dotted message key, so a typo is a compile error rather than a raw key on screen. */
export type MessageKey = Leaves<typeof messages>;

function lookup(key: string): string | undefined {
  let node: unknown = messages;
  for (const part of key.split(".")) {
    if (typeof node !== "object" || node === null) return undefined;
    node = (node as Record<string, unknown>)[part];
  }
  return typeof node === "string" ? node : undefined;
}

/** Resolve a message, substituting `{name}` placeholders. An unknown key renders as itself. */
export function t(key: MessageKey, params?: Record<string, string | number>): string {
  const template = lookup(key) ?? key;
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = params[name];
    return value === undefined ? match : String(value);
  });
}
