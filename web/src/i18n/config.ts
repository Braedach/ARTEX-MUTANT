// Supported locales and the default. ARTEX-MUTANT is English-only — the
// upstream multi-language UI (Korean/Chinese/Spanish/Japanese) was dropped
// along with its message files, since this is now a single-maintainer
// internal build rather than a product serving those user bases. Kept as a
// list of one, rather than removing the locale abstraction outright, so the
// mechanism itself doesn't need ripping out of every call site tonight.
export const LOCALES = ["en"] as const;
export type Locale = (typeof LOCALES)[number];

export const DEFAULT_LOCALE: Locale = "en";

// Shown in the (now single-option) language selector.
export const LOCALE_LABELS: Record<Locale, string> = {
  en: "English",
};

// Key used to persist the chosen display language. The screen reads the
// localStorage value. The same value is also written to a cookie, but
// nothing currently reads it (kept for if the server ever needs to know the
// language).
export const LOCALE_COOKIE = "artex_locale";
export const LOCALE_STORAGE_KEY = "artex_locale";

// Narrows an arbitrary string to a supported locale.
export function isLocale(raw: unknown): raw is Locale {
  return typeof raw === "string" && (LOCALES as readonly string[]).includes(raw);
}

// Determines the active locale at build time. Must stay compatible with
// static export (next.config's output: "export"), so it only reads env vars,
// never dynamic APIs like cookies()/headers(). Falls back to the default if
// NEXT_PUBLIC_LOCALE is empty or unsupported. This value is only used for the
// initial HTML of server prerendering; the actual user-facing display
// language is overridden client-side via the cookie.
export function resolveLocale(): Locale {
  const raw = process.env.NEXT_PUBLIC_LOCALE;
  return isLocale(raw) ? raw : DEFAULT_LOCALE;
}
