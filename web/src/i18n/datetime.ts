import { DEFAULT_LOCALE, isLocale, LOCALE_STORAGE_KEY, type Locale, resolveLocale } from "@/i18n/config";
import { getLocalStorageValue } from "@/lib/local-storage.client";

// BCP47 locale tag used for date/time formatting. Follows the display
// language (locale-store) rather than a hardcoded string, so use this
// function instead of hardcoding one. Reflects the build's default locale
// during server rendering (no window), and the user's chosen value on the
// client. Also safe to use in an Intl formatter read once at module load.
const DATE_LOCALE: Record<Locale, string> = {
  en: "en-US",
};

export function getDateLocale(): string {
  if (typeof window === "undefined") return DATE_LOCALE[DEFAULT_LOCALE];
  const raw = getLocalStorageValue(LOCALE_STORAGE_KEY);
  const loc: Locale = isLocale(raw) ? raw : resolveLocale();
  return DATE_LOCALE[loc];
}
