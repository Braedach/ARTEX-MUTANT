// Session handling for the web UI.
//
// The login token is an HttpOnly cookie that the server sets and clears. Page script
// never sees it, so nothing here stores, reads or sends a token: the browser attaches
// the cookie to same-origin requests (fetch and EventSource) by itself, and the UI
// learns whether it is signed in by asking the server.

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export type Role = "viewer" | "analyst" | "operator" | "admin";

export interface Session {
  authenticated: boolean;
  username?: string;
  role?: Role;
  permissions?: string[];
  mustChangePassword?: boolean;
}

// True when the session holds the permission. Permissions are the server's resource:action
// strings (see docs/multiuser-design.md); the server enforces them, this only decides what
// to show. An item with no requirement is always visible.
export function can(session: Pick<Session, "permissions"> | null | undefined, permission?: string): boolean {
  if (!permission) return true;
  return session?.permissions?.includes(permission) === true;
}

const LEGACY_TOKEN_KEY = "artex_token";

const isMock = () => process.env.NEXT_PUBLIC_MOCK === "1";

// Earlier versions kept the JWT in localStorage and in a cookie written by script, where
// any script on the page could read it. Remove those copies. If the cookie is still the
// script-written one, deleting it signs the user out once; if it is already the server's
// HttpOnly cookie the browser ignores the script's delete, so nothing changes.
export function purgeLegacyToken(): void {
  if (typeof window === "undefined") return;
  try {
    if (window.localStorage.getItem(LEGACY_TOKEN_KEY) === null) return;
    window.localStorage.removeItem(LEGACY_TOKEN_KEY);
    document.cookie = `${LEGACY_TOKEN_KEY}=; path=/; max-age=0`;
  } catch {
    // Storage can be blocked (private mode); there is nothing stored to remove then.
  }
}

export const auth = {
  // Asks the server whether the browser holds a valid session. A network failure
  // reads as "not signed in", the same outcome a 401 used to have.
  async session(): Promise<Session> {
    if (isMock()) return { authenticated: true, username: "ARTEX", role: "admin", permissions: MOCK_ADMIN_PERMISSIONS };
    purgeLegacyToken();
    try {
      const r = await fetch("/api/auth/session", { credentials: "same-origin", cache: "no-store" });
      if (!r.ok) return { authenticated: false };
      const body = (await r.json()) as Partial<Session> & { must_change_password?: boolean };
      if (body.authenticated !== true) return { authenticated: false };
      return {
        authenticated: true,
        username: body.username,
        role: body.role,
        permissions: body.permissions ?? [],
        mustChangePassword: body.must_change_password === true,
      };
    } catch {
      return { authenticated: false };
    }
  },

  // Ends the browser session. Only the server can clear an HttpOnly cookie, so this
  // must reach it; a failure is swallowed so the caller can still leave the page, and
  // the cookie then simply expires on its own.
  async logout(): Promise<void> {
    if (isMock()) return;
    try {
      await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    } catch {
      // The session cookie expires with the token.
    }
    purgeLegacyToken();
  },
};

const MOCK_ADMIN_PERMISSIONS = [
  "task:read",
  "finding:read",
  "report:read",
  "usage:read",
  "evidence:read",
  "finding:triage",
  "export:run",
  "chat:read",
  "workspace:read",
  "task:write",
  "chat:use",
  "workspace:write",
  "finding:write",
  "intercept:decide",
  "logs:read",
  "config:read",
  "config:write",
  "secrets:read",
  "llm:admin",
  "system:admin",
  "user:manage",
  "audit:read",
];

// Display name and role for the signed-in user.
export function userFromSession(session: Session): CurrentUser {
  const username = session.username ?? "ARTEX";
  return { id: "1", name: username, username, email: "", avatar: "", role: session.role ?? "viewer" };
}
