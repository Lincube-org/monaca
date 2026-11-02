import { afterEach, describe, expect, test } from "bun:test";

import { applyPhraseOverrides, clearPhraseOverrides, t } from "./i18n";

afterEach(() => clearPhraseOverrides());

describe("tenant phrase overrides", () => {
  test("replace known copy and keep interpolation working", () => {
    applyPhraseOverrides("de", {
      "signIn.title": "Bei {client} anmelden",
      "errors.generic": "Anmeldung fehlgeschlagen.",
    });
    expect(t("signIn.title", { client: "Notes" })).toBe("Bei Notes anmelden");
    expect(t("errors.generic")).toBe("Anmeldung fehlgeschlagen.");
    // A phrase the tenant did not translate stays in the built-in copy.
    expect(t("signIn.submit")).toBe("Sign in");
  });

  test("ignore keys the built-in dictionary does not have", () => {
    applyPhraseOverrides("fr", {
      "signIn.notARealKey": "Bonjour",
      "signIn.title": "Connexion",
    });
    expect(t("signIn.title")).toBe("Connexion");
    // An unknown key has no built-in text to replace, so it cannot leak into a page.
    expect(t("signIn.notARealKey" as never)).toBe("signIn.notARealKey");
  });

  test("fall back once the tenant copy is cleared", () => {
    applyPhraseOverrides("de", { "signIn.submit": "Anmelden" });
    expect(t("signIn.submit")).toBe("Anmelden");
    clearPhraseOverrides();
    expect(t("signIn.submit")).toBe("Sign in");
  });
});
