/**
 * Typed IDs, encode-only, for the mock layer.
 *
 * The contract (docs/contracts/m0.md §5.2) fixes the format: `<prefix>_<suffix>` where the suffix is
 * the TypeID v0.3 encoding of the UUIDv7 — the UUID read as a 128-bit big-endian integer, two zero
 * bits prepended, then 26 symbols of 5 bits each in lowercase Crockford base32
 * `0123456789abcdefghjkmnpqrstvwxyz` (no `i l o u`).
 *
 * Only encoding is implemented here: the console renders ids the server produced and never has to
 * parse one back, so a decoder would be dead code. The authoritative implementation (with the
 * contract's test vectors) belongs to the Rust `monaca-types` crate and to whatever TS package ends
 * up owning shared kernel types — see open_issues. The test alongside this file pins the three
 * published vectors so a future move is a copy, not a re-derivation.
 */
export const ID_PREFIXES = [
  "ten",
  "org",
  "acc",
  "agt",
  "akey",
  "grt",
  "cli",
  "rol",
  "res",
  "ses",
  "evt",
  "dlg",
  "apr",
  "int",
  "key",
] as const;

export type IdPrefix = (typeof ID_PREFIXES)[number];

const ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";

/** Encode a UUIDv7 (canonical hyphenated form) as a 26-symbol TypeID suffix. */
export function encodeTypeIdSuffix(uuid: string): string {
  const hex = uuid.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
    throw new Error(`not a 32-hex-digit UUID: ${uuid}`);
  }

  let value = BigInt(`0x${hex}`);
  // 130 bits = 26 symbols x 5 bits. The two leading zero bits are the padding TypeID defines.
  const symbols = new Array<string>(26);
  for (let index = 25; index >= 0; index -= 1) {
    const symbol = ALPHABET[Number(value & 0x1fn)];
    if (symbol === undefined) throw new Error("base32 index out of range");
    symbols[index] = symbol;
    value >>= 5n;
  }
  return symbols.join("");
}

export function typedId(prefix: IdPrefix, uuid: string): string {
  return `${prefix}_${encodeTypeIdSuffix(uuid)}`;
}

/**
 * A UUIDv7: 48-bit big-endian millisecond timestamp, version nibble 7, variant bits `10`, then
 * randomness. Generated here rather than taken from `crypto.randomUUID`, which produces v4 and
 * would make every mock id fail the contract's "non-v7 version nibble is an error" rule.
 */
export function uuidv7(now: number = Date.now()): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  const ms = BigInt(now);
  bytes[0] = Number((ms >> 40n) & 0xffn);
  bytes[1] = Number((ms >> 32n) & 0xffn);
  bytes[2] = Number((ms >> 24n) & 0xffn);
  bytes[3] = Number((ms >> 16n) & 0xffn);
  bytes[4] = Number((ms >> 8n) & 0xffn);
  bytes[5] = Number(ms & 0xffn);

  bytes[6] = (bytes[6]! & 0x0f) | 0x70; // version 7
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // RFC 4122 variant

  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function newId(prefix: IdPrefix, now?: number): string {
  return typedId(prefix, uuidv7(now));
}

/** The typed prefix of an id, or `null` when the string is not a typed id. */
export function idPrefix(id: string): string | null {
  const separator = id.indexOf("_");
  return separator > 0 ? id.slice(0, separator) : null;
}
