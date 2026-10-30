/**
 * Every user-visible string in the hosted sign-in page.
 *
 * Kept in one module so the page holds no literals and a locale layer can be added without touching
 * a template. The tone rules from the console apply here too, with one addition: this page is the
 * only place a stranger meets the product, so the copy explains what is happening rather than
 * assuming the reader knows what an "interaction" is.
 */
export const messages = {
  brand: {
    fallbackTenant: "monaca",
    poweredBy: "Monaca",
  },
  signIn: {
    title: "Sign in to continue",
    /** Shown above the form: who is asking, and for what. */
    request: "{client} wants to use your account",
    requestFallback: "An application wants to use your account",
    tenantLabel: "Tenant",
    organization: "Organization",
    scopes: "This will allow",
    expires: "This request expires",
    email: "Email",
    emailPlaceholder: "you@example.com",
    password: "Password",
    submit: "Sign in",
    submitting: "Signing in",
    cancel: "Cancel",
    cancelling: "Cancelling",
    showPassword: "Show password",
    hidePassword: "Hide password",
    /** The security note, kept short and factual rather than reassuring. */
    footnote: "Your password is sent only to this tenant's sign-in service.",
  },
  consent: {
    title: "Approve access",
    request: "{client} is asking to access your account",
    note: "You are signed in. Review what this application will be allowed to do.",
    allow: "Allow access",
    allowSubmitting: "Approving",
    deny: "Deny",
    denySubmitting: "Denying",
  },
  errors: {
    invalidCredentials: "That email and password combination is not recognised.",
    consentFailed: "Could not record your decision. Try again.",
    interactionNotFound: "This sign-in request no longer exists. Start again from the application.",
    interactionExpired: "This sign-in request has expired. Start again from the application.",
    interactionConsumed: "This sign-in request has already been used. Start again from the application.",
    invalidRequest: "The sign-in request is malformed.",
    network: "Could not reach the sign-in service. Check your connection and try again.",
    generic: "Sign-in failed.",
    emailRequired: "Enter your email address.",
    passwordRequired: "Enter your password.",
    missingInteraction: "This page needs a sign-in request id.",
    missingInteractionHint:
      "It is opened by an application as part of a sign-in flow, and cannot be used on its own.",
  },
  loading: {
    title: "Preparing sign-in",
    hint: "Checking the request with the sign-in service.",
  },
  done: {
    title: "Signed in",
    hint: "Redirecting you back to the application.",
  },
  cancelDone: {
    title: "Sign-in cancelled",
    hint: "Redirecting you back to the application.",
  },
} as const;

type Leaves<T, Prefix extends string = ""> = {
  [K in keyof T & string]: T[K] extends string ? `${Prefix}${K}` : Leaves<T[K], `${Prefix}${K}.`>;
}[keyof T & string];

export type MessageKey = Leaves<typeof messages>;

function lookup(key: string): string | undefined {
  let node: unknown = messages;
  for (const part of key.split(".")) {
    if (typeof node !== "object" || node === null) return undefined;
    node = (node as Record<string, unknown>)[part];
  }
  return typeof node === "string" ? node : undefined;
}

export function t(key: MessageKey, params?: Record<string, string | number>): string {
  const template = lookup(key) ?? key;
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = params[name];
    return value === undefined ? match : String(value);
  });
}
