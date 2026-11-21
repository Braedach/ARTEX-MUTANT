"use client";

import { useEffect, useState } from "react";

import { auth, type Session } from "@/lib/auth";

// The signed-in session with its role and permissions. null until the server answers.
export function useSession(): Session | null {
  const [session, setSession] = useState<Session | null>(null);

  useEffect(() => {
    let cancelled = false;
    void auth.session().then((s) => {
      if (!cancelled) setSession(s);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return session;
}
