/**
 * The first `{{name}}` a mail template cannot render, or `undefined` when every one is known.
 *
 * The server refuses such a write rather than mailing a literal `{{cod}}`, so an administrator
 * learns about the typo from the form instead of from a user who never received a code. The mock
 * and the editor share this check so both answer the same question about the same text.
 *
 * An unclosed `{{` has no name to return; the text after it is returned instead, which is still
 * refused and still points at the offending fragment.
 */
export function unknownPlaceholder(
  text: string,
  allowed: readonly string[],
): string | undefined {
  let rest = text;
  for (;;) {
    const start = rest.indexOf("{{");
    if (start < 0) return undefined;
    const after = rest.slice(start + 2);
    const end = after.indexOf("}}");
    if (end < 0) return after.trim();
    const name = after.slice(0, end).trim();
    if (!allowed.includes(name)) return name;
    rest = after.slice(end + 2);
  }
}
