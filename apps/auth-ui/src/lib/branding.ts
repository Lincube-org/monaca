/**
 * Tenant branding → CSS variables.
 *
 * The design tokens derive `--brand`, `--brand-ink`, `--brand-soft` and `--brand-on` from an OKLCH
 * hue, which a tenant-supplied `#rrggbb` cannot produce directly. This helper writes the four
 * concrete values instead, so overriding them on the sign-in page's container is enough: Tailwind's
 * `bg-brand`, `text-brand-ink` and friends resolve `var(--brand*)` at the element that inherits
 * them.
 */

/** `#rrggbb` (either case) → its three channels, or `null` for anything else. */
export function parseHexColor(value: string | null | undefined): [number, number, number] | null {
  if (!value) return null;
  const match = /^#([0-9a-fA-F]{6})$/.exec(value.trim());
  if (!match) return null;
  const hex = match[1]!;
  return [
    Number.parseInt(hex.slice(0, 2), 16),
    Number.parseInt(hex.slice(2, 4), 16),
    Number.parseInt(hex.slice(4, 6), 16),
  ];
}

function hex([r, g, b]: [number, number, number]): string {
  return `#${[r, g, b]
    .map((channel) => Math.round(channel).toString(16).padStart(2, "0"))
    .join("")}`;
}

/** Mix `weight` of `to` into `from`; 0 keeps `from`, 1 returns `to`. */
function mix(
  from: [number, number, number],
  to: [number, number, number],
  weight: number,
): [number, number, number] {
  return [
    from[0] + (to[0] - from[0]) * weight,
    from[1] + (to[1] - from[1]) * weight,
    from[2] + (to[2] - from[2]) * weight,
  ];
}

/** Rec. 709 relative luminance, used to pick readable text on the brand fill. */
function luminance([r, g, b]: [number, number, number]): number {
  const linear = (channel: number) => {
    const value = channel / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.05) / 1.05) ** 2.4;
  };
  return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);
}

/**
 * The four brand variables for a tenant colour, or an empty object when the value is not a usable
 * hex colour — a malformed value must never make the page unreadable.
 */
export function brandStyle(value: string | null | undefined): Record<string, string> {
  const rgb = parseHexColor(value);
  if (!rgb) return {};
  const on = luminance(rgb) > 0.45 ? "#101418" : "#ffffff";
  return {
    "--brand": hex(rgb),
    "--brand-on": on,
    "--brand-ink": hex(mix(rgb, [0, 0, 0], 0.25)),
    "--brand-soft": hex(mix(rgb, [255, 255, 255], 0.9)),
  };
}
