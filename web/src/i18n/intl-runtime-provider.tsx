"use client";

import type { ReactNode } from "react";
import * as React from "react";

import { NextIntlClientProvider } from "next-intl";

import enMessages from "../../messages/en.json";
import type { Locale } from "./config";
import { useActiveLocale } from "./locale-store";

// English-only message bundle (ARTEX-MUTANT dropped the other locales'
// message files, see config.ts). Kept as a map rather than a single import
// so a future added locale only needs a new entry here and in config.ts.
const MESSAGES: Record<Locale, Record<string, unknown>> = {
  en: enMessages as Record<string, unknown>,
};

// Time zone of the running environment (browser or prerender server).
const TIME_ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;

// Provider responsible for runtime language switching. Replaces the root
// layout's NextIntlClientProvider so it can supply messages for the user's
// actively chosen locale (cookie/localStorage).
export function IntlRuntimeProvider({ children }: Readonly<{ children: ReactNode }>) {
  const locale = useActiveLocale();

  // Keep <html lang> in sync when the language changes, overriding the root
  // layout's server-set initial value with the client's chosen one so screen
  // readers and browser translation behave correctly.
  React.useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  // Unlike the root layout's provider, this one doesn't inherit the server
  // request config, so timeZone must be passed explicitly - omitting it
  // makes next-intl log an ENVIRONMENT_FALLBACK error during prerendering.
  return (
    <NextIntlClientProvider locale={locale} messages={MESSAGES[locale]} timeZone={TIME_ZONE}>
      {children}
    </NextIntlClientProvider>
  );
}
