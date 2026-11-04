// Typed client for the Monaca HTTP contract. `src/schema.gen.ts` is generated from
// `spec/openapi.json` by `bun run generate`; do not edit it by hand.
import createClient from "openapi-fetch";
import type { paths } from "./schema.gen.ts";

export type { paths } from "./schema.gen.ts";

/** Options for {@link createMonacaClient}. */
export interface MonacaClientOptions {
  /** The public origin, e.g. `http://localhost:8080`. */
  baseUrl: string;
  /** A bearer token for the management API (`monaca:admin`). */
  token?: string;
}

/**
 * A typed `openapi-fetch` client.
 *
 * The generated `paths` type is the contract: a path or method that is not in
 * `spec/openapi.json` does not compile, and a registered operation carries its request and
 * response types.
 */
export function createMonacaClient(options: MonacaClientOptions) {
  return createClient<paths>({
    baseUrl: options.baseUrl,
    headers: options.token === undefined ? {} : { authorization: `Bearer ${options.token}` },
  });
}
