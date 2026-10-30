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
  /** The way a visitor chooses between the four flows the page supports. */
  modes: {
    password: "Use a password",
    code: "Email me a sign-in code",
    signUp: "Create an account",
    reset: "Forgot your password?",
  },
  mfa: {
    title: "Two-step verification",
    note: "Open your authenticator app and enter the six-digit code it shows for {client}.",
    noteFallback: "Open your authenticator app and enter the six-digit code it shows.",
    code: "Six-digit code",
    codePlaceholder: "123456",
    verify: "Verify and continue",
    verifying: "Checking the code",
    useBackupCode: "Use a backup code instead",
    useTotp: "Use your authenticator app instead",
    backupCode: "Backup code",
    backupCodePlaceholder: "xxxxx-xxxxx",
    backupNote:
      "Enter one of the single-use codes you saved when you turned on two-step verification.",
    usePasskey: "Use a passkey instead",
  },
  /** Passkeys, the passwordless factor: a device-bound credential instead of a typed secret. */
  passkey: {
    signIn: "Sign in with a passkey",
    signingIn: "Waiting for your passkey",
    or: "or",
    mfaNote: "Confirm with the screen lock or security key you registered for this account.",
  },
  account: {
    title: "Account security",
    signedInAs: "Signed in as",
    mfaTitle: "Two-step verification",
    mfaOn: "An authenticator app is enrolled. Your password alone is no longer enough to sign in.",
    mfaOff: "No authenticator app is enrolled. A password is enough to sign in.",
    enable: "Set up an authenticator app",
    enabling: "Preparing the secret",
    disable: "Remove the authenticator app",
    disabling: "Removing",
    scan: "Add this secret to your authenticator app, then enter the six-digit code it shows. The setup expires in ten minutes.",
    secret: "Secret",
    code: "Six-digit code",
    verify: "Turn on two-step verification",
    verifying: "Checking the code",
    enabled: "Two-step verification is on.",
    disabled: "Two-step verification is off.",
    sessionRequired: "Sign in to manage your account security.",
    loadFailed: "Could not load your account.",
    refresh: "Start again",
    profileTitle: "Profile",
    displayNameLabel: "Display name",
    displayNamePlaceholder: "How your name appears to applications",
    saveProfile: "Save name",
    savingProfile: "Saving",
    profileSaved: "Your name was updated.",
    passwordTitle: "Password",
    currentPassword: "Current password",
    newPassword: "New password",
    passwordHint: "At least 8 characters.",
    changePassword: "Change password",
    changingPassword: "Changing",
    passwordChanged: "Your password was changed. Other browsers were signed out.",
    noPassword: "This account signs in without a password.",
    sessionsTitle: "Signed-in devices",
    sessionsNote: "Browsers currently signed in to your account.",
    currentSession: "This browser",
    lastSeen: "Last active",
    sessionStarted: "Signed in",
    revoke: "Sign out",
    revoking: "Signing out",
    revokeOthers: "Sign out other browsers",
    revokingOthers: "Signing out others",
    otherSessionsRevoked: "Every other browser was signed out.",
    sessionRevoked: "That browser was signed out.",
    sessionsEmpty: "No signed-in devices.",
    backupTitle: "Backup codes",
    backupNote: "Single-use codes for when you cannot reach your authenticator app.",
    backupRemaining: "{remaining} of 10 unused.",
    backupShownOnce: "Save these codes now. They are shown only once.",
    backupGenerate: "Generate backup codes",
    backupGenerating: "Generating",
    backupDisable: "Remove backup codes",
    backupDisabling: "Removing",
    backupGenerated: "Ten backup codes were generated. Store them somewhere safe.",
    backupRemoved: "Backup codes were removed.",
    passkeysTitle: "Passkeys",
    passkeysNote:
      "Sign in with this device's screen lock or a security key instead of a password. Up to 10.",
    passkeyEmpty: "No passkeys yet.",
    passkeyAdd: "Add a passkey",
    passkeyAdding: "Waiting for your device",
    passkeyNameLabel: "Name (optional)",
    passkeyNamePlaceholder: "e.g. This laptop",
    passkeyRename: "Rename",
    passkeyDelete: "Remove",
    passkeySaving: "Saving",
    passkeyRemoving: "Removing",
    passkeyCreated: "Your passkey was added.",
    passkeyRenamed: "The passkey was renamed.",
    passkeyDeleted: "The passkey was removed.",
    passkeyNoName: "Unnamed passkey",
    passkeyNeverUsed: "Never used",
    passkeyLastUsed: "Last used {when}",
    passkeyLimit: "You can add at most 10 passkeys.",
  },
  emailCode: {
    title: "Sign in with an email code",
    note: "We will email a six-digit code. It works once and expires in ten minutes.",
    send: "Email me a code",
    sending: "Sending the code",
    sent: "If that address can receive mail, a code is on its way.",
    code: "Six-digit code",
    codePlaceholder: "123456",
    verify: "Sign in",
    verifying: "Checking the code",
    changeEmail: "Use a different email",
  },
  signUp: {
    title: "Create an account",
    note: "We will email a six-digit code to confirm the address before the account is created.",
    continue: "Continue",
    sending: "Sending the code",
    displayName: "Name",
    displayNamePlaceholder: "Your name",
    password: "Password",
    passwordHint: "At least 8 characters.",
    submit: "Create account",
    submitting: "Creating the account",
    changeEmail: "Use a different email",
  },
  reset: {
    title: "Reset your password",
    note: "We will email a six-digit code. Anyone signed in to this account is signed out after the reset.",
    send: "Email me a reset code",
    sending: "Sending the code",
    password: "New password",
    passwordHint: "At least 8 characters.",
    submit: "Set a new password",
    submitting: "Setting the password",
    changeEmail: "Use a different email",
  },
  errors: {
    invalidCredentials: "That email and password combination is not recognised.",
    accountExists: "An account with that email already exists. Sign in instead.",
    weakPassword: "Use a password of at least 8 characters.",
    invalidCode: "That code is not valid or has expired. Request a new one.",
    tooManyAttempts: "Too many attempts. Wait a moment, then request a new code.",
    consentFailed: "Could not record your decision. Try again.",
    interactionNotFound: "This sign-in request no longer exists. Start again from the application.",
    interactionExpired: "This sign-in request has expired. Start again from the application.",
    interactionConsumed: "This sign-in request has already been used. Start again from the application.",
    invalidRequest: "The sign-in request is malformed.",
    network: "Could not reach the sign-in service. Check your connection and try again.",
    generic: "Sign-in failed.",
    emailRequired: "Enter your email address.",
    passwordRequired: "Enter your password.",
    codeRequired: "Enter the code from the email.",
    displayNameRequired: "Enter a name.",
    displayNameTooLong: "Use at most 80 characters.",
    currentPasswordRequired: "Enter your current password.",
    newPasswordRequired: "Enter a new password.",
    currentPasswordInvalid: "That current password is not correct.",
    mfaCodeRequired: "Enter the six-digit code from your authenticator app.",
    backupCodeRequired: "Enter a ten-character backup code.",
    mfaInvalidCode: "That code is not valid. Check your authenticator app and try again.",
    mfaInvalidBackupCode: "That backup code is not valid or has already been used.",
    mfaTooManyAttempts: "Too many wrong codes. Start the sign-in again from the application.",
    passkeyUnsupported: "This browser cannot use passkeys.",
    passkeyFailed: "The passkey could not be verified. Try again, or use another method.",
    passkeyRejected: "That passkey was not accepted. Try again, or use another method.",
    passkeyNameRequired: "Enter a name for this passkey, or cancel.",
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
