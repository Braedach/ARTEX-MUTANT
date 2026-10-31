import { getRequestConfig } from "next-intl/server";

import { type Locale, resolveLocale } from "./config";

// Per-locale message loader. Kept as an explicit import map (rather than a
// dynamic path) so the bundler doesn't pull the whole messages/ directory in
// as a context module. English-only since ARTEX-MUTANT dropped the other
// locales' message files — see config.ts's own comment.
const loaders: Record<Locale, () => Promise<{ default: Record<string, unknown> }>> = {
  en: () => import("../../messages/en.json"),
};

// next-intl request config. This setup doesn't use i18n path routing
// (segments/middleware), so the locale is decided directly here.
// requestLocale is not referenced, so this doesn't force dynamic rendering.
// This only sets the default language for server components/prerendering;
// runtime switching is handled by the client's IntlRuntimeProvider.
export default getRequestConfig(async () => {
  const locale = resolveLocale();
  const messages = (await loaders[locale]()).default;
  return { locale, messages };
});
