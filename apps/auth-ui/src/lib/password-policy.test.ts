import { describe, expect, test } from "bun:test";

import { characterTypes, passwordMeetsPolicy } from "./password-policy";

describe("characterTypes", () => {
  test("counts the four classes", () => {
    expect(characterTypes("abcdefgh")).toBe(1);
    expect(characterTypes("Abcdefgh")).toBe(2);
    expect(characterTypes("Abcdefg1")).toBe(3);
    expect(characterTypes("Abcdef1!")).toBe(4);
  });

  test("a symbol-only password is one class", () => {
    expect(characterTypes("!!!!!!!!")).toBe(1);
  });

  test("non-ASCII characters count as symbols, like the server", () => {
    expect(characterTypes("密码密码密码")).toBe(1);
  });
});

describe("passwordMeetsPolicy", () => {
  test("requires both the length and the character types", () => {
    expect(passwordMeetsPolicy("lowercase1!", 8, 3)).toBe(true);
    expect(passwordMeetsPolicy("lowercase", 8, 2)).toBe(false);
    expect(passwordMeetsPolicy("Ab1!", 8, 4)).toBe(false);
    expect(passwordMeetsPolicy("Abcdefg1", 12, 3)).toBe(false);
  });

  test("a policy of one class accepts any long-enough password", () => {
    expect(passwordMeetsPolicy("abcdefgh", 8, 1)).toBe(true);
  });

  test("length counts code points, not UTF-16 units", () => {
    expect(passwordMeetsPolicy("密码密码密码密码", 8, 1)).toBe(true);
    expect(passwordMeetsPolicy("密码密码", 8, 1)).toBe(false);
  });
});
