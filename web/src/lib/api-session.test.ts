import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, api, http, openEventSource, sseUrl } from "./api";

const LEGACY = "LEGACY-TOKEN-MUST-NEVER-BE-SENT";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function headersOf(init: RequestInit | undefined): Record<string, string> {
  return (init?.headers ?? {}) as Record<string, string>;
}

describe("requests no longer carry a script-readable token", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    window.localStorage.setItem("artex_token", LEGACY);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    window.localStorage.clear();
  });

  it("http() sends same-origin credentials and no Authorization header", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ ok: true }));
    await http("/tasks");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/tasks");
    expect(init.credentials).toBe("same-origin");
    expect(JSON.stringify(headersOf(init))).not.toMatch(/authorization/i);
    expect(JSON.stringify(init)).not.toContain(LEGACY);
  });

  it("keeps Content-Type for bodies", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ ok: true }));
    await http("/x", { method: "POST", body: "{}" });
    expect(headersOf(fetchMock.mock.calls[0][1] as RequestInit)["Content-Type"]).toBe("application/json");
  });

  it("uploads, downloads and exports do not read or send a stored token", async () => {
    fetchMock.mockImplementation(async () => jsonResponse({ uploaded: 1, attachments: [] }));
    const file = new File(["x"], "x.txt");
    await api.workspaceUpload("/", [file]);
    await api.chatUpload("task", "1", [file]);
    await api.report("t1").catch(() => undefined);
    await api.interceptGetToolConfig().catch(() => undefined);
    await api.interceptSetToolConfig(["bash"]).catch(() => undefined);
    expect(fetchMock).toHaveBeenCalled();
    for (const call of fetchMock.mock.calls) {
      const init = call[1] as RequestInit | undefined;
      expect(JSON.stringify(init ?? {})).not.toContain(LEGACY);
      expect(JSON.stringify(headersOf(init))).not.toMatch(/authorization/i);
    }
  });
});

describe("401 handling", () => {
  const fetchMock = vi.fn();
  let location: { href: string };
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    location = { href: "/function/tasks" };
    vi.stubGlobal("location", location);
    Object.defineProperty(window, "location", { value: location, writable: true, configurable: true });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("on an expired session asks the server to clear the HttpOnly cookie, then goes to /login", async () => {
    fetchMock.mockImplementation(async (url: string) =>
      url === "/api/auth/logout" ? jsonResponse({ ok: true }) : jsonResponse({ error: "unauthorized" }, 401),
    );
    await expect(http("/tasks")).rejects.toThrow();
    const urls = fetchMock.mock.calls.map((c) => c[0]);
    expect(urls).toEqual(["/api/tasks", "/api/auth/logout"]);
    expect((fetchMock.mock.calls[1][1] as RequestInit).method).toBe("POST");
    expect(location.href).toBe("/login");
  });

  it("still reaches /login when the logout request itself fails", async () => {
    fetchMock.mockImplementation(async (url: string) => {
      if (url === "/api/auth/logout") throw new TypeError("offline");
      return jsonResponse({ error: "unauthorized" }, 401);
    });
    await expect(http("/tasks")).rejects.toThrow();
    expect(location.href).toBe("/login");
  });

  it("does not bounce the login form on a wrong password", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ error: "bad credentials" }, 401));
    await expect(api.login("ARTEX", "nope")).rejects.toMatchObject({ status: 401, message: "bad credentials" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(location.href).toBe("/function/tasks");
  });

  it("surfaces a wrong setup token to the setup form the same way", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ error: "invalid setup token" }, 401));
    await expect(api.initPassword("a-long-enough-password", "bad")).rejects.toBeInstanceOf(ApiError);
    expect(location.href).toBe("/function/tasks");
  });
});

describe("event streams", () => {
  const created: { url: string; init?: EventSourceInit }[] = [];
  beforeEach(() => {
    created.length = 0;
    window.localStorage.setItem("artex_token", LEGACY);
    class FakeEventSource {
      constructor(url: string, init?: EventSourceInit) {
        created.push({ url, init });
      }
    }
    vi.stubGlobal("EventSource", FakeEventSource);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    window.localStorage.clear();
  });

  it("never puts a token in the URL", () => {
    vi.stubEnv("NEXT_PUBLIC_SSE_BASE", "");
    expect(sseUrl("/api/logs/stream?since=0")).toBe("/api/logs/stream?since=0");
    expect(sseUrl("/api/update/stream")).not.toMatch(/token=/);
    expect(sseUrl("/api/x")).not.toContain(LEGACY);
  });

  it("opens streams with credentials so the HttpOnly cookie is sent", () => {
    vi.stubEnv("NEXT_PUBLIC_SSE_BASE", "");
    openEventSource("/api/logs/stream?since=0");
    expect(created).toHaveLength(1);
    expect(created[0].url).toBe("/api/logs/stream?since=0");
    expect(created[0].init).toEqual({ withCredentials: true });
    expect(created[0].url).not.toContain(LEGACY);
  });

  it("honours an explicit stream base for the dev setup", () => {
    vi.stubEnv("NEXT_PUBLIC_SSE_BASE", "http://localhost:8787");
    expect(sseUrl("/api/logs/stream")).toBe("http://localhost:8787/api/logs/stream");
  });
});
