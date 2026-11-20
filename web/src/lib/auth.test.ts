import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { auth, purgeLegacyToken, userFromSession } from "./auth";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("auth.session", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    window.localStorage.clear();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("reports an authenticated session from the server", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ authenticated: true, username: "ARTEX" }));
    await expect(auth.session()).resolves.toEqual({ authenticated: true, username: "ARTEX" });
  });

  it("asks the server with same-origin credentials, no stored token and no Authorization header", async () => {
    window.localStorage.setItem("artex_token", "LEGACY-TOKEN");
    fetchMock.mockResolvedValue(jsonResponse({ authenticated: false }));
    await auth.session();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/auth/session");
    expect(init.credentials).toBe("same-origin");
    expect(init.cache).toBe("no-store");
    expect(JSON.stringify(init)).not.toContain("LEGACY-TOKEN");
    expect(JSON.stringify(init.headers ?? {})).not.toMatch(/authorization/i);
  });

  it.each([
    ["not signed in", () => fetchMock.mockResolvedValue(jsonResponse({ authenticated: false }))],
    ["a server error", () => fetchMock.mockResolvedValue(jsonResponse({ error: "x" }, 500))],
    ["a network failure", () => fetchMock.mockRejectedValue(new TypeError("offline"))],
    ["a malformed body", () => fetchMock.mockResolvedValue(new Response("not json", { status: 200 }))],
    ["a truthy but non-boolean flag", () => fetchMock.mockResolvedValue(jsonResponse({ authenticated: "yes" }))],
  ])("reads %s as not signed in", async (_name, arrange) => {
    arrange();
    await expect(auth.session()).resolves.toMatchObject({ authenticated: false });
  });

  it("is signed in without a server in the mock demo", async () => {
    vi.stubEnv("NEXT_PUBLIC_MOCK", "1");
    await expect(auth.session()).resolves.toEqual({ authenticated: true, username: "ARTEX" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("auth.logout", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    window.localStorage.clear();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("posts to the server, which is the only thing able to clear an HttpOnly cookie", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ ok: true }));
    await auth.logout();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/auth/logout");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("same-origin");
  });

  it("still lets the caller leave the page when the request fails", async () => {
    fetchMock.mockRejectedValue(new TypeError("offline"));
    await expect(auth.logout()).resolves.toBeUndefined();
  });

  it("removes any leftover legacy token", async () => {
    window.localStorage.setItem("artex_token", "LEGACY-TOKEN");
    fetchMock.mockResolvedValue(jsonResponse({ ok: true }));
    await auth.logout();
    expect(window.localStorage.getItem("artex_token")).toBeNull();
  });
});

describe("purgeLegacyToken", () => {
  beforeEach(() => window.localStorage.clear());

  it("removes the localStorage copy of the old token", () => {
    window.localStorage.setItem("artex_token", "LEGACY-TOKEN");
    purgeLegacyToken();
    expect(window.localStorage.getItem("artex_token")).toBeNull();
  });

  it("expires the script-written cookie", () => {
    const writes: string[] = [];
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    Object.defineProperty(document, "cookie", {
      configurable: true,
      get: () => "",
      set: (v: string) => void writes.push(v),
    });
    try {
      window.localStorage.setItem("artex_token", "LEGACY-TOKEN");
      purgeLegacyToken();
    } finally {
      delete (document as unknown as Record<string, unknown>).cookie;
      if (desc) Object.defineProperty(Document.prototype, "cookie", desc);
    }
    expect(writes).toEqual(["artex_token=; path=/; max-age=0"]);
  });

  it("does nothing, and so never signs a modern session out, when no legacy token exists", () => {
    const writes: string[] = [];
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    Object.defineProperty(document, "cookie", {
      configurable: true,
      get: () => "",
      set: (v: string) => void writes.push(v),
    });
    try {
      purgeLegacyToken();
    } finally {
      delete (document as unknown as Record<string, unknown>).cookie;
      if (desc) Object.defineProperty(Document.prototype, "cookie", desc);
    }
    expect(writes).toEqual([]);
  });

  it("survives blocked storage", () => {
    const spy = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(() => purgeLegacyToken()).not.toThrow();
    spy.mockRestore();
  });
});

describe("userFromSession", () => {
  it("uses the server-supplied name and falls back to the single admin account", () => {
    expect(userFromSession({ authenticated: true, username: "ARTEX" }).name).toBe("ARTEX");
    expect(userFromSession({ authenticated: true }).name).toBe("ARTEX");
    expect(userFromSession({ authenticated: true }).role).toBe("operator");
  });
});
