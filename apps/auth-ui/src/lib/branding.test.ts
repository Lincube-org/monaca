import { describe, expect, test } from "bun:test";

import { brandStyle, parseHexColor } from "./branding";

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
