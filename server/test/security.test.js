import assert from "node:assert/strict";
import test from "node:test";

import { buildApp } from "../src/app.js";
import { validatePassword } from "../src/auth.js";

function securityRepository() {
  let csrfToken = "";
  const user = {
    id: "22222222-2222-4222-8222-222222222222",
    email: "admin@example.com",
    fullName: "MVA Administrator",
    globalRole: "system_admin",
    status: "active",
  };
  return {
    health: async () => ({ database: "mva_test", checked_at: "2026-07-22T00:00:00Z" }),
    setupStatus: async () => ({ setupRequired: true }),
    bootstrapAdmin: async () => user,
    markLogin: async () => {},
    createSession: async (session) => { csrfToken = session.csrfToken; },
    getSession: async () => ({ sessionId: "session-1", csrfToken, user }),
    deleteSession: async () => {},
    listCustomersForUser: async () => [],
    getUserForLogin: async () => null,
    audit: async () => {},
  };
}

test("API responses set anti-caching and browser hardening headers", async (context) => {
  const app = await buildApp({ repository: securityRepository(), allowedOrigins: ["https://mva.example"] });
  context.after(() => app.close());

  const response = await app.inject({ method: "GET", url: "/api/v1/auth/setup-status" });
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(response.headers["x-content-type-options"], "nosniff");
  assert.equal(response.headers["x-frame-options"], "DENY");
  assert.equal(response.headers["referrer-policy"], "no-referrer");
});

test("CORS allows the configured origin and rejects an untrusted origin", async (context) => {
  const app = await buildApp({ repository: securityRepository(), allowedOrigins: ["https://mva.example"] });
  context.after(() => app.close());

  const allowed = await app.inject({ method: "GET", url: "/health", headers: { origin: "https://mva.example" } });
  assert.equal(allowed.statusCode, 200);
  assert.equal(allowed.headers["access-control-allow-origin"], "https://mva.example");
  assert.equal(allowed.headers["access-control-allow-credentials"], "true");

  const blocked = await app.inject({ method: "GET", url: "/health", headers: { origin: "https://attacker.example" } });
  assert.equal(blocked.statusCode, 403);
  assert.equal(blocked.headers["access-control-allow-origin"], undefined);
  assert.equal(blocked.json().error, "Origin is not allowed.");
});

test("production sessions use Secure, HttpOnly, and SameSite Strict cookies", async (context) => {
  const app = await buildApp({ repository: securityRepository(), allowedOrigins: ["https://mva.example"], secureCookies: true });
  context.after(() => app.close());

  const response = await app.inject({
    method: "POST",
    url: "/api/v1/auth/bootstrap",
    payload: { email: "admin@example.com", fullName: "MVA Administrator", password: "Correct horse battery staple 2026" },
  });
  assert.equal(response.statusCode, 201);
  const cookie = response.headers["set-cookie"];
  assert.match(cookie, /mva_session=/);
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Strict/i);
  assert.match(cookie, /Secure/i);
});

test("repeated invalid sign-ins are throttled without disclosing account existence", async (context) => {
  const app = await buildApp({ repository: securityRepository(), allowedOrigins: ["https://mva.example"] });
  context.after(() => app.close());

  for (let attempt = 0; attempt < 8; attempt += 1) {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { email: "unknown@example.com", password: "Incorrect password 2026" },
    });
    assert.equal(response.statusCode, 401);
    assert.equal(response.json().error, "Email or password is incorrect.");
  }

  const throttled = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email: "unknown@example.com", password: "Incorrect password 2026" },
  });
  assert.equal(throttled.statusCode, 429);
  assert.equal(throttled.json().error, "Too many sign-in attempts. Try again later.");
});

test("password policy rejects short, oversized, and email-derived passwords", () => {
  assert.throws(() => validatePassword("short", "analyst@example.com"), /at least 12/);
  assert.throws(() => validatePassword("analyst-password-2026", "analyst@example.com"), /email username/);
  assert.throws(() => validatePassword("x".repeat(129), "analyst@example.com"), /cannot exceed 128/);
  assert.equal(validatePassword("Correct horse battery staple 2026", "analyst@example.com"), "Correct horse battery staple 2026");
});
