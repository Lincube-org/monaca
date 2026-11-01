/**
 * The tenant's password policy, mirrored for the two hosted forms (§6.1).
 *
 * The server is authoritative; this module only lets the page refuse a password it already knows
 * would be rejected, so a visitor is not sent round-trip for a mistake the form can see.
 */

/** Lowercase, uppercase, digit, symbol: the four classes the server counts. */
export function characterTypes(password: string): number {
  let lower = false;
  let upper = false;
  let digit = false;
  let symbol = false;
  for (const character of password) {
    if (character >= "a" && character <= "z") lower = true;
    else if (character >= "A" && character <= "Z") upper = true;
    else if (character >= "0" && character <= "9") digit = true;
    else symbol = true;
  }
  return Number(lower) + Number(upper) + Number(digit) + Number(symbol);
}

/** Whether the password satisfies the tenant's length and character-type minimums. */
export function passwordMeetsPolicy(
  password: string,
  minLength: number,
  minCharacterTypes: number,
): boolean {
  return (
    [...password].length >= minLength && characterTypes(password) >= Math.max(1, minCharacterTypes)
  );
}
