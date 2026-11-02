import { describe, expect, test } from "bun:test";

import { brandStyle, parseHexColor, supportMailto, usableUrl } from "./branding";

describe("parseHexColor", () => {
  test("accepts six-digit hex in either case", () => {
    expect(parseHexColor("#0F6CBD")).toEqual([15, 108, 189]);
    expect(parseHexColor(" #ffffff ")).toEqual([255, 255, 255]);
  });

  test("rejects everything else", () => {
    expect(parseHexColor(null)).toBeNull();
    expect(parseHexColor("")).toBeNull();
    expect(parseHexColor("blue")).toBeNull();
    expect(parseHexColor("#abc")).toBeNull();
    expect(parseHexColor("#0f6cbdff")).toBeNull();
  });
});

describe("brandStyle", () => {
  test("a dark colour keeps white text and derives ink and soft variants", () => {
    const style = brandStyle("#0f6cbd");
    expect(style["--brand"]).toBe("#0f6cbd");
    expect(style["--brand-on"]).toBe("#ffffff");
    expect(style["--brand-ink"]).toBe("#0b518e");
    expect(style["--brand-soft"]).toBe("#e7f0f8");
  });

  test("a light colour switches to dark text", () => {
    expect(brandStyle("#f5d90a")["--brand-on"]).toBe("#101418");
  });

  test("an unset or malformed value yields no overrides, so the built-in look stays", () => {
    expect(brandStyle(null)).toEqual({});
    expect(brandStyle("blue")).toEqual({});
  });
});

describe("usableUrl", () => {
  test("passes an absolute http(s) URL through, trimmed", () => {
    expect(usableUrl(" https://cdn.example.com/logo.svg ")).toBe("https://cdn.example.com/logo.svg");
    expect(usableUrl("http://example.com/favicon.ico")).toBe("http://example.com/favicon.ico");
  });

  test("rejects a missing, relative or non-http URL so the built-in asset stays", () => {
    expect(usableUrl(null)).toBeNull();
    expect(usableUrl(undefined)).toBeNull();
    expect(usableUrl("")).toBeNull();
    expect(usableUrl("/logo.svg")).toBeNull();
    expect(usableUrl("javascript:alert(1)")).toBeNull();
    expect(usableUrl("data:image/svg+xml,<svg/>")).toBeNull();
  });
});

describe("supportMailto", () => {
  test("turns a plausible address into a mailto link", () => {
    expect(supportMailto("help@example.com")).toBe("mailto:help@example.com");
    expect(supportMailto(" Help+login@Example.COM ")).toBe("mailto:Help+login@Example.COM");
  });

  test("rejects anything that is not one address, so no broken link is shown", () => {
    expect(supportMailto(null)).toBeNull();
    expect(supportMailto("")).toBeNull();
    expect(supportMailto("help")).toBeNull();
    expect(supportMailto("a@b@c")).toBeNull();
    expect(supportMailto("help me@example.com")).toBeNull();
  });
});
