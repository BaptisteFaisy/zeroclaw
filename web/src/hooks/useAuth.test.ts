import assert from "node:assert/strict";
import test, { afterEach, beforeEach } from "node:test";
import { createElement } from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import type { OidcSession } from "../lib/auth.ts";
import type { AuthState } from "./useAuth.ts";

// The auth provider's state machine against a mocked gateway: sign-in off,
// pairing, a signed-in session through expiry and re-auth, sign-out across
// tabs.

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length(): number { return this.values.size; }
  clear(): void { this.values.clear(); }
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  key(index: number): string | null { return [...this.values.keys()][index] ?? null; }
  removeItem(key: string): void { this.values.delete(key); }
  setItem(key: string, value: string): void { this.values.set(key, value); }
}

const storage = new MemoryStorage();
let reloads = 0;
let assigned: string[] = [];
let opened: string[] = [];
let popupBlocked = false;
const fakeWindow = Object.assign(new EventTarget(), {
  location: {
    protocol: "https:",
    host: "zc.example",
    hostname: "zc.example",
    port: "",
    pathname: "/agent/main",
    search: "",
    reload: () => {
      reloads += 1;
    },
    assign: (url: string) => {
      assigned.push(url);
    },
  },
  open: (url: string) => {
    opened.push(url);
    return popupBlocked ? null : {};
  },
});
const fakeDocument = Object.assign(new EventTarget(), { visibilityState: "visible" });
Object.assign(globalThis, { window: fakeWindow, document: fakeDocument, localStorage: storage });
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT =
  true;

interface Recorded {
  url: string;
  method: string;
  headers: Headers;
}
let requests: Recorded[] = [];
let health = { require_pairing: true, paired: true };
let providers: string[] = [];
let sessionResponse: () => Response = () => new Response("", { status: 401 });

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

globalThis.fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  const method = (init?.method ?? "GET").toUpperCase();
  requests.push({ url, method, headers: new Headers(init?.headers) });
  if (url.endsWith("/health")) return json(200, health);
  if (url.endsWith("/api/auth/methods")) {
    return json(200, {
      pairing_required: true,
      oidc: providers.map((alias) => ({ alias, provider: `oidc.${alias}` })),
    });
  }
  if (url.endsWith("/api/auth/session")) return sessionResponse();
  if (url.endsWith("/auth/sign-out")) return new Response(null, { status: 204 });
  return json(404, {});
};

const auth = await import("../lib/auth.ts");
const { AuthProvider, useAuth } = await import("./useAuth.ts");

function session(overrides: Partial<OidcSession> = {}): OidcSession {
  return {
    kind: "oidc",
    provider: "oidc.corp",
    principal_id: "principal-a",
    display_name: "Ada",
    admin: true,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    csrf_token: "csrf-1",
    features: { chat: true, operator_pages: true },
    ...overrides,
  };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 30));

let latest: AuthState | null = null;
function Probe() {
  latest = useAuth();
  return null;
}
const state = (): AuthState => {
  assert.ok(latest, "provider not mounted");
  return latest;
};

let renderer: ReactTestRenderer | null = null;
async function mount(): Promise<void> {
  await act(async () => {
    renderer = create(createElement(AuthProvider, null, createElement(Probe)));
  });
  await act(settle);
}

async function fire(name: keyof typeof auth.AUTH_EVENTS): Promise<void> {
  await act(async () => {
    fakeWindow.dispatchEvent(new Event(auth.AUTH_EVENTS[name]));
  });
  await act(settle);
}

/** Post on the auth channel as another tab (or the re-auth window) would. */
async function broadcast(message: { type: string }): Promise<void> {
  const other = new BroadcastChannel("zeroclaw-auth");
  other.postMessage(message);
  other.close();
  await act(settle);
}

beforeEach(() => {
  storage.clear();
  auth.setOidcSession(null);
  requests = [];
  reloads = 0;
  assigned = [];
  opened = [];
  popupBlocked = false;
  health = { require_pairing: true, paired: true };
  providers = [];
  sessionResponse = () => new Response("", { status: 401 });
  latest = null;
});

afterEach(async () => {
  await act(async () => {
    renderer?.unmount();
  });
  renderer = null;
});

// ---------------------------------------------------------------------------
// Unchanged paths
// ---------------------------------------------------------------------------

test("sign-in off: the pairing screen, no provider, no session lookup", async () => {
  await mount();
  const s = state();
  assert.equal(s.loading, false);
  assert.equal(s.isAuthenticated, false);
  assert.equal(s.requiresPairing, true);
  assert.equal(s.mode, "pairing");
  assert.deepEqual(s.providers, []);
  assert.equal(s.signOutNotice, null);
  assert.ok(!requests.some((r) => r.url.endsWith("/api/auth/session")));
});

test("a paired browser starts authenticated without asking the gateway", async () => {
  storage.setItem("zeroclaw_token", "tok");
  await mount();
  assert.equal(state().isAuthenticated, true);
  assert.equal(state().mode, "pairing");
  assert.equal(requests.length, 0);
});

test("a gateway without pairing is open", async () => {
  health = { require_pairing: false, paired: false };
  await mount();
  assert.equal(state().isAuthenticated, true);
  assert.equal(state().requiresPairing, false);
});

// ---------------------------------------------------------------------------
// Signed in
// ---------------------------------------------------------------------------

async function mountSignedIn(s: OidcSession = session()): Promise<void> {
  providers = ["corp"];
  sessionResponse = () => json(200, s);
  await mount();
  assert.equal(state().mode, "oidc");
  assert.equal(state().isAuthenticated, true);
}

test("providers and a live cookie session: signed in", async () => {
  await mountSignedIn();
  assert.equal(state().session?.principal_id, "principal-a");
  assert.deepEqual(state().providers, [{ alias: "corp", provider: "oidc.corp" }]);
  assert.equal(auth.getAuthMode(), "oidc");
});

test("expiry keeps the page, and re-auth as the same account resumes it", async () => {
  await mountSignedIn();
  let resumed = 0;
  const onResumed = () => {
    resumed += 1;
  };
  fakeWindow.addEventListener(auth.AUTH_EVENTS.resumed, onResumed);

  await fire("reauth");
  assert.equal(state().reauthRequired, true);
  assert.equal(state().isAuthenticated, true);

  // Requests made after expiry are refused as unknown sessions; that is still
  // the expiry, not a sign-out.
  await fire("unauthorized");
  assert.equal(state().reauthRequired, true);
  assert.equal(state().isAuthenticated, true);

  sessionResponse = () => json(200, session({ csrf_token: "csrf-2" }));
  await broadcast({ type: "signed-in" });
  fakeWindow.removeEventListener(auth.AUTH_EVENTS.resumed, onResumed);

  assert.equal(state().reauthRequired, false);
  assert.equal(state().isAuthenticated, true);
  assert.equal(state().session?.csrf_token, "csrf-2");
  assert.equal(auth.getOidcSession()?.csrf_token, "csrf-2");
  assert.equal(resumed, 1);
  assert.equal(reloads, 0);
});

test("re-auth as a different account reloads the page", async () => {
  await mountSignedIn();
  await fire("reauth");
  sessionResponse = () => json(200, session({ principal_id: "principal-b", csrf_token: "csrf-b" }));
  await broadcast({ type: "signed-in" });
  assert.equal(reloads, 1);
  assert.equal(state().session?.principal_id, "principal-a");
});

test("a refused session while not expired signs out with a notice", async () => {
  await mountSignedIn();
  await fire("unauthorized");
  assert.equal(state().isAuthenticated, false);
  assert.equal(state().mode, "pairing");
  assert.deepEqual(state().signOutNotice, { kind: "session-ended" });
  assert.equal(auth.getOidcSession(), null);
  assert.deepEqual(state().providers, [{ alias: "corp", provider: "oidc.corp" }]);
});

test("sign-out ends the session, tells other tabs, and names the provider", async () => {
  await mountSignedIn();
  const heard: unknown[] = [];
  const otherTab = new BroadcastChannel("zeroclaw-auth");
  otherTab.onmessage = (event: MessageEvent) => heard.push(event.data);

  await act(async () => {
    await state().signOut();
  });
  await act(settle);
  otherTab.close();

  const signOut = requests.find((r) => r.url.endsWith("/auth/sign-out"));
  assert.equal(signOut?.method, "POST");
  assert.equal(signOut?.headers.get(auth.CSRF_HEADER), "csrf-1");
  assert.equal(signOut?.headers.has("Authorization"), false);
  assert.equal(state().isAuthenticated, false);
  assert.deepEqual(state().signOutNotice, { kind: "signed-out", provider: "corp" });
  assert.deepEqual(heard, [{ type: "signed-out" }]);
});

test("sign-out in another tab signs this tab out too", async () => {
  await mountSignedIn();
  await broadcast({ type: "signed-out" });
  assert.equal(state().isAuthenticated, false);
  assert.deepEqual(state().signOutNotice, { kind: "signed-out", provider: "corp" });
});

test("a signed-out tab picks up a sign-in from another tab", async () => {
  providers = ["corp"];
  await mount();
  assert.equal(state().isAuthenticated, false);
  sessionResponse = () => json(200, session());
  await broadcast({ type: "signed-in" });
  assert.equal(state().isAuthenticated, true);
  assert.equal(state().mode, "oidc");
  assert.equal(reloads, 0);
});

test("lost access re-checks the session", async () => {
  await mountSignedIn();
  sessionResponse = () => json(401, { error: "gone", reason: "session_invalid" });
  await fire("accessLost");
  assert.equal(state().isAuthenticated, false);
  assert.deepEqual(state().signOutNotice, { kind: "session-ended" });
});

// ---------------------------------------------------------------------------
// Expiry timing and the re-auth window
// ---------------------------------------------------------------------------

test("the banner shows in the last two minutes", async () => {
  await mountSignedIn(session({ expires_at: Math.floor(Date.now() / 1000) + 60 }));
  assert.equal(state().expiryWarning, true);
  assert.equal(state().reauthRequired, false);
});

test("a session past its deadline asks for re-auth on the server's clock", async () => {
  const s = session({ expires_at: Math.floor(Date.now() / 1000) + 600 });
  providers = ["corp"];
  // The server's clock is an hour ahead of this browser: ten minutes left by
  // the browser's clock is already fifty minutes past the deadline.
  sessionResponse = () =>
    new Response(JSON.stringify(s), {
      status: 200,
      headers: { Date: new Date(Date.now() + 3_600_000).toUTCString() },
    });
  await mount();
  assert.equal(state().reauthRequired, true);
});

test("re-auth opens the provider's popup; a blocked popup can continue in the tab", async () => {
  await mountSignedIn();
  await fire("reauth");
  let attempt = "";
  await act(async () => {
    attempt = state().reauthenticate();
  });
  assert.equal(attempt, "opened");
  assert.deepEqual(opened, ["/auth/sign-in/corp?popup=1"]);
  assert.equal(state().reauthPending, true);

  popupBlocked = true;
  await act(async () => {
    attempt = state().reauthenticate();
  });
  assert.equal(attempt, "blocked");
  await act(async () => {
    state().continueReauthHere();
  });
  assert.deepEqual(assigned, ["/auth/sign-in/corp?return=%2Fagent%2Fmain"]);
});

test("sign-in from the screen returns to the current page", async () => {
  providers = ["corp"];
  await mount();
  await act(async () => {
    state().signIn("corp");
  });
  assert.deepEqual(assigned, ["/auth/sign-in/corp?return=%2Fagent%2Fmain"]);
});
