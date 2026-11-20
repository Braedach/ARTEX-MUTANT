"use client";

import { useEffect, useState } from "react";

import { auth, type CurrentUser, userFromSession } from "@/lib/auth";

const FALLBACK: CurrentUser = { id: "1", name: "ARTEX", username: "artex", email: "", avatar: "", role: "operator" };

export function useCurrentUser(): CurrentUser {
  const [user, setUser] = useState<CurrentUser>(FALLBACK);

  useEffect(() => {
    let cancelled = false;
    void auth.session().then((session) => {
      if (!cancelled && session.authenticated) setUser(userFromSession(session));
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return user;
}
