import { describe, expect, it } from "vitest";

import { builtinLanguage, builtinTranslate, MESSAGES } from "./messages.js";

describe("the built-in strings", () => {
  it("are complete in every language, with the same placeholders", () => {
    const keys = Object.keys(MESSAGES.en).sort();
    const holes = (s: string) => [...s.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort();
    for (const [lang, table] of Object.entries(MESSAGES)) {
      expect(Object.keys(table).sort(), lang).toEqual(keys);
      for (const key of keys) expect(holes((table as Record<string, string>)[key]!), `${lang} ${key}`).toEqual(holes((MESSAGES.en as Record<string, string>)[key]!));
    }
  });

  it("are picked by the locale's language, English otherwise", () => {
    expect(builtinLanguage("de-AT")).toBe("de");
    expect(builtinLanguage("es_ES")).toBe("es");
    expect(builtinLanguage("NL")).toBe("nl");
    expect(builtinLanguage("fr-CA")).toBe("fr");
    expect(builtinLanguage("it")).toBe("en");
    // Not a key of the object's prototype.
    expect(builtinLanguage("constructor")).toBe("en");
    expect(builtinTranslate("de")("archive_members", { count: 1 })).toBe("1 Datei");
    expect(builtinTranslate("nl")("archive_members", { count: 3 })).toBe("3 bestanden");
    expect(builtinTranslate("es")("zoom_in")).toBe("Ampliar");
  });
});
