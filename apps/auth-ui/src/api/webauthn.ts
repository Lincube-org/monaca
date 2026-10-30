/**
 * The browser half of a WebAuthn ceremony (docs/contracts/m0.md §6.1 `passkey`).
 *
 * The server speaks the spec's *JSON* serialisation — base64url strings — while
 * `navigator.credentials` wants binary buffers. This module is the only place that translates
 * between the two, so a page never touches a raw byte array and the wire format stays one shape.
 *
 * The two ceremonies differ only in which credential method runs: `create` for registration and
 * `get` for assertion. Both return a `PublicKeyCredential` whose response fields are exported back
 * to base64url for the server to verify.
 */

/** Why a ceremony did not produce a credential; the page decides what to say. */
export type PasskeyFailure =
  /** The visitor dismissed the system prompt, or it timed out. Not an error worth shouting about. */
  | "cancelled"
  /** This browser or origin cannot run a ceremony at all. */
  | "unavailable"
  /** The authenticator refused or something else went wrong. */
  | "failed";

export class PasskeyError extends Error {
  readonly reason: PasskeyFailure;

  constructor(message: string, reason: PasskeyFailure) {
    super(message);
    this.name = "PasskeyError";
    this.reason = reason;
  }
}

/** A `PublicKeyCredentialDescriptor` in the JSON form the server sends. */
export interface CredentialDescriptorJSON {
  type: "public-key";
  id: string;
  transports?: string[];
}

/** `PublicKeyCredentialCreationOptions` with base64url strings, as the server sends it. */
export interface CreationOptionsJSON {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  excludeCredentials?: CredentialDescriptorJSON[];
}

/** `PublicKeyCredentialRequestOptions` with base64url strings, as the server sends it. */
export interface RequestOptionsJSON {
  challenge: string;
  rpId?: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: CredentialDescriptorJSON[];
}

/**
 * A `PublicKeyCredential` reduced to what the server reads.
 *
 * `name` is only meaningful at registration; the assertion shape leaves it off. Optional response
 * members are omitted rather than sent as `undefined`, which JSON would drop anyway.
 */
export interface CeremonyJSON {
  rawId: string;
  name?: string;
  response: {
    clientDataJSON: string;
    attestationObject?: string;
    authenticatorData?: string;
    signature?: string;
    userHandle?: string | null;
    transports?: string[];
  };
}

/** Whether this browser can run a ceremony here at all. */
export function passkeysSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    window.isSecureContext &&
    typeof window.PublicKeyCredential === "function" &&
    typeof navigator.credentials?.create === "function"
  );
}

/**
 * base64url (padding optional) → bytes.
 *
 * The buffer is allocated explicitly so the result is `Uint8Array<ArrayBuffer>`, which is what
 * `BufferSource` accepts; a plain `new Uint8Array(n)` is typed as possibly shared memory.
 */
export function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const normalised = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalised + "=".repeat((4 - (normalised.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** bytes → base64url without padding, which is what the server decodes. */
export function encodeBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function descriptor(entry: CredentialDescriptorJSON): PublicKeyCredentialDescriptor {
  return {
    type: "public-key",
    id: decodeBase64Url(entry.id),
    ...(entry.transports === undefined
      ? {}
      : { transports: entry.transports as AuthenticatorTransport[] }),
  };
}

/**
 * Map a rejected `navigator.credentials` call to a reason the page understands.
 *
 * `NotAllowedError` is the spec's catch-all for "the user said no, or the prompt timed out", so it
 * is a cancellation rather than a failure — the visitor closed the sheet and should not be shown
 * a red banner for it.
 */
function ceremonyFailure(error: unknown): PasskeyError {
  const name = error instanceof DOMException ? error.name : "";
  switch (name) {
    case "NotAllowedError":
    case "AbortError":
      return new PasskeyError("the passkey prompt was dismissed", "cancelled");
    case "NotSupportedError":
    case "SecurityError":
      return new PasskeyError("this browser cannot use a passkey here", "unavailable");
    default:
      return new PasskeyError(error instanceof Error ? error.message : String(error), "failed");
  }
}

/** Run `navigator.credentials.create` and export the attestation as the server expects it. */
export async function createPasskey(
  options: CreationOptionsJSON,
  name?: string,
): Promise<CeremonyJSON> {
  if (!passkeysSupported()) {
    throw new PasskeyError("passkeys are not available in this browser", "unavailable");
  }

  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.create({
      publicKey: {
        challenge: decodeBase64Url(options.challenge),
        rp: options.rp,
        user: {
          id: decodeBase64Url(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName,
        },
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout,
        attestation: options.attestation,
        authenticatorSelection: options.authenticatorSelection,
        excludeCredentials: (options.excludeCredentials ?? []).map(descriptor),
      },
    })) as PublicKeyCredential | null;
  } catch (error) {
    throw ceremonyFailure(error);
  }
  if (credential === null) {
    throw new PasskeyError("the browser returned no credential", "failed");
  }

  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    rawId: encodeBase64Url(credential.rawId),
    name,
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      attestationObject: encodeBase64Url(response.attestationObject),
      transports: typeof response.getTransports === "function" ? response.getTransports() : [],
    },
  };
}

/** Run `navigator.credentials.get` and export the assertion as the server expects it. */
export async function getPasskeyAssertion(options: RequestOptionsJSON): Promise<CeremonyJSON> {
  if (!passkeysSupported()) {
    throw new PasskeyError("passkeys are not available in this browser", "unavailable");
  }

  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.get({
      publicKey: {
        challenge: decodeBase64Url(options.challenge),
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification,
        allowCredentials: (options.allowCredentials ?? []).map(descriptor),
      },
    })) as PublicKeyCredential | null;
  } catch (error) {
    throw ceremonyFailure(error);
  }
  if (credential === null) {
    throw new PasskeyError("the browser returned no credential", "failed");
  }

  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    rawId: encodeBase64Url(credential.rawId),
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      authenticatorData: encodeBase64Url(response.authenticatorData),
      signature: encodeBase64Url(response.signature),
      userHandle:
        response.userHandle === null ? null : encodeBase64Url(response.userHandle),
    },
  };
}
