import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import Fastify from "fastify";
import { Readable } from "node:stream";

import {
  constantTimeEqual,
  createSessionSecrets,
  hashOpaqueToken,
  hashPassword,
  normalizeEmail,
  validateAccountInput,
  validatePassword,
  verifyPassword,
} from "./auth.js";
import { findingCsvFilename, findingCsvLines } from "./csv.js";
import {
  ASSET_TYPES,
  badRequest,
  normalizeAiRemediationPayload,
  normalizeAssetIds,
  normalizeAssetOnboardingTool,
  normalizeAssetPayloads,
  normalizeCreatePayload,
  normalizeCustomerPayload,
  normalizeTeamPayload,
  normalizeThreatIntelImportPayload,
  normalizeThreatIntelQuery,
} from "./validation.js";

const SESSION_COOKIE = "mva_session";
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_ATTEMPT_LIMIT = 8;

export async function buildApp({
  repository,
  llmClient = unavailableLlmClient(),
  allowedOrigins = [],
  secureCookies = false,
  trustProxy = false,
}) {
  const app = Fastify({ logger: true, bodyLimit: 32 * 1024 * 1024, trustProxy });
  const loginAttempts = new Map();
  const dummyPasswordHash = await hashPassword("MVA-Invalid-Account-Verification-Only!2026");

  await app.register(cookie);
  await app.register(cors, {
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes("*") || allowedOrigins.includes(origin)) callback(null, true);
      else callback(badRequest("Origin is not allowed.", 403), false);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-MVA-CSRF"],
    exposedHeaders: ["Content-Disposition"],
  });

  app.addHook("onSend", async (request, reply, payload) => {
    if (request.url.startsWith("/api/")) {
      reply.header("Cache-Control", "no-store");
      reply.header("X-Content-Type-Options", "nosniff");
      reply.header("X-Frame-Options", "DENY");
      reply.header("Referrer-Policy", "no-referrer");
    }
    return payload;
  });

  const authenticate = async (request) => {
    const rawToken = request.cookies?.[SESSION_COOKIE];
    if (!rawToken) throw badRequest("Authentication is required.", 401);
    const session = await repository.getSession(hashOpaqueToken(rawToken));
    if (!session) throw badRequest("Your session has expired. Sign in again.", 401);
    request.auth = session;
  };

  const requireWrite = async (request) => {
    await authenticate(request);
    const csrf = request.headers["x-mva-csrf"];
    if (!csrf || !constantTimeEqual(csrf, request.auth.csrfToken)) throw badRequest("The request security token is invalid. Refresh and try again.", 403);
  };

  const requireAdmin = async (request) => {
    await requireWrite(request);
    if (request.auth.user.globalRole !== "system_admin") throw badRequest("System administrator access is required.", 403);
  };

  const createAuthenticatedSession = async (request, reply, user) => {
    const secrets = createSessionSecrets();
    await repository.createSession({
      userId: user.id,
      tokenHash: secrets.tokenHash,
      csrfToken: secrets.csrfToken,
      userAgent: String(request.headers["user-agent"] ?? ""),
      ipAddress: request.ip,
      expiresAt: new Date(Date.now() + SESSION_DURATION_MS),
    });
    reply.setCookie(SESSION_COOKIE, secrets.token, {
      path: "/",
      httpOnly: true,
      sameSite: "strict",
      secure: secureCookies,
    });
    return { user, csrfToken: secrets.csrfToken, customers: await repository.listCustomersForUser(user) };
  };

  app.get("/health", async () => {
    const database = await repository.health();
    return { ok: true, service: "mva-postgres-api", database: database.database, checkedAt: database.checked_at };
  });

  app.get("/api/v1/auth/setup-status", async () => ({ ok: true, ...(await repository.setupStatus()) }));

  app.post("/api/v1/auth/bootstrap", async (request, reply) => {
    const account = validateAccountInput(request.body);
    const user = await repository.bootstrapAdmin({
      email: account.email,
      fullName: account.fullName,
      passwordHash: await hashPassword(account.password),
      ipAddress: request.ip,
    });
    await repository.markLogin(user.id);
    return reply.code(201).send({ ok: true, ...(await createAuthenticatedSession(request, reply, user)) });
  });

  app.post("/api/v1/auth/login", async (request, reply) => {
    const email = normalizeEmail(request.body?.email);
    enforceLoginRate(loginAttempts, `${request.ip}:${email}`);
    const userRecord = await repository.getUserForLogin(email);
    const passwordMatches = await verifyPassword(String(request.body?.password ?? ""), userRecord?.password_hash ?? dummyPasswordHash);
    const valid = userRecord?.status === "active" && passwordMatches;
    if (!valid) {
      registerLoginFailure(loginAttempts, `${request.ip}:${email}`);
      throw badRequest("Email or password is incorrect.", 401);
    }
    loginAttempts.delete(`${request.ip}:${email}`);
    await repository.markLogin(userRecord.id);
    const user = {
      id: userRecord.id,
      email: userRecord.email,
      fullName: userRecord.full_name,
      globalRole: userRecord.global_role,
      status: userRecord.status,
      createdAt: userRecord.created_at,
      lastLoginAt: new Date(),
    };
    await repository.audit(user.id, null, "auth.login", {}, request.ip);
    return { ok: true, ...(await createAuthenticatedSession(request, reply, user)) };
  });

  app.get("/api/v1/auth/me", { preHandler: authenticate }, async (request) => ({
    ok: true,
    user: request.auth.user,
    csrfToken: request.auth.csrfToken,
    customers: await repository.listCustomersForUser(request.auth.user),
  }));

  app.get("/api/v1/llm/status", { preHandler: authenticate }, async () => ({
    ok: true,
    llm: llmClient.status(),
  }));

  app.post("/api/v1/auth/logout", { preHandler: requireWrite }, async (request, reply) => {
    const tokenHash = hashOpaqueToken(request.cookies[SESSION_COOKIE]);
    await repository.deleteSession(tokenHash);
    reply.clearCookie(SESSION_COOKIE, { path: "/", sameSite: "strict", secure: secureCookies });
    reply.header("Clear-Site-Data", '"cache", "cookies", "storage"');
    return { ok: true };
  });

  app.get("/api/v1/customers", { preHandler: authenticate }, async (request) => ({
    ok: true,
    customers: await repository.listCustomersForUser(request.auth.user),
  }));

  app.post("/api/v1/customers", { preHandler: requireAdmin }, async (request, reply) => {
    const customer = await repository.createCustomer(request.auth.user.id, normalizeCustomerPayload(request.body), request.ip);
    return reply.code(201).send({ ok: true, customer });
  });

  app.put("/api/v1/customers/:customerId", { preHandler: requireAdmin }, async (request) => ({
    ok: true,
    customer: await repository.updateCustomer(request.auth.user.id, request.params.customerId, normalizeCustomerPayload(request.body), request.ip),
  }));

  app.delete("/api/v1/customers/:customerId", { preHandler: requireAdmin }, async (request) => ({
    ok: true,
    deleted: await repository.deleteCustomer(request.auth.user.id, request.params.customerId, String(request.body?.confirmation ?? ""), request.ip),
  }));

  app.get("/api/v1/customers/:customerId/dashboard", { preHandler: authenticate }, async (request) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId);
    const { teamId, assetId } = normalizeDashboardFilters(request.query);
    return { ok: true, dashboard: await repository.getCustomerDashboard(request.params.customerId, access.assetTypes, teamId, assetId) };
  });

  app.get("/api/v1/customers/:customerId/scan-asset-coverage", { preHandler: authenticate }, async (request) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId);
    return { ok: true, coverage: await repository.getCustomerScanAssetCoverage(request.params.customerId, access.assetTypes) };
  });

  app.get("/api/v1/customers/:customerId/findings.csv", { preHandler: authenticate }, async (request, reply) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId);
    const { teamId, assetId } = normalizeDashboardFilters(request.query);
    const exported = await repository.getCustomerFindingExport(request.params.customerId, access.assetTypes, teamId, assetId);
    reply.header("Content-Type", "text/csv; charset=utf-8");
    reply.header("Content-Disposition", `attachment; filename="${findingCsvFilename(exported.customer.slug, exported.reportPeriod)}"`);
    return reply.send(Readable.from(findingCsvLines(exported.rows)));
  });

  app.get("/api/v1/customers/:customerId/assets", { preHandler: authenticate }, async (request) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId);
    const requested = Number(request.query?.limit ?? 500);
    const limit = Number.isInteger(requested) ? Math.min(100_000, Math.max(1, requested)) : 500;
    return { ok: true, assets: await repository.listCustomerAssets(request.params.customerId, limit, access.assetTypes) };
  });

  app.get("/api/v1/customers/:customerId/teams", { preHandler: authenticate }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId);
    return { ok: true, teams: await repository.listCustomerTeams(request.params.customerId) };
  });

  app.post("/api/v1/customers/:customerId/llm/test", { preHandler: requireWrite }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const result = await llmClient.test();
    await repository.audit(request.auth.user.id, request.params.customerId, "llm.tested", { model: result.model }, request.ip);
    return { ok: true, llm: result };
  });

  app.post("/api/v1/customers/:customerId/ai/remediation", { preHandler: requireWrite }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const payload = normalizeAiRemediationPayload(request.body);
    const generated = await llmClient.chat({
      messages: [
        {
          role: "system",
          content: "You are the MVA Remediation Guide engine. Return customer-ready Markdown only. Never invent commands, versions, KB identifiers, CVEs, links, or validation evidence. Clearly label unknown values.",
        },
        { role: "user", content: payload.prompt },
      ],
      temperature: 0.1,
      maxTokens: 12_000,
    });
    await repository.audit(request.auth.user.id, request.params.customerId, "llm.remediation_generated", {
      model: generated.model,
      targetPeriod: payload.targetPeriod,
      sourceLabel: payload.sourceLabel,
    }, request.ip);
    return { ok: true, markdown: generated.content, model: generated.model, targetPeriod: payload.targetPeriod };
  });

  app.post("/api/v1/customers/:customerId/threat-intel/imports", { preHandler: requireWrite }, async (request, reply) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const imported = await repository.createThreatIntelImport(
      request.params.customerId,
      request.auth.user.id,
      normalizeThreatIntelImportPayload(request.body),
    );
    return reply.code(imported.existing ? 200 : 201).send({ ok: true, import: imported });
  });

  app.post("/api/v1/customers/:customerId/threat-intel/imports/:importId/chunks", { preHandler: requireWrite }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    return {
      ok: true,
      ...(await repository.ingestThreatIntelChunk(request.params.customerId, request.params.importId, request.body)),
    };
  });

  app.post("/api/v1/customers/:customerId/threat-intel/imports/:importId/finalize", { preHandler: requireWrite }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const imported = await repository.finalizeThreatIntelImport(request.params.customerId, request.params.importId);
    await repository.audit(request.auth.user.id, request.params.customerId, "threat_intel.imported", {
      importId: imported.id,
      records: imported.receivedRecords,
      sourceLabel: imported.sourceLabel,
    }, request.ip);
    return { ok: true, import: imported };
  });

  app.get("/api/v1/customers/:customerId/threat-intel", { preHandler: authenticate }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId);
    const rawQuery = String(request.query?.q ?? "").trim();
    const query = rawQuery ? normalizeThreatIntelQuery(rawQuery) : "";
    const limit = Math.min(500, Math.max(1, Number(request.query?.limit) || 100));
    return { ok: true, records: await repository.searchThreatIntel(request.params.customerId, query, limit) };
  });

  app.post("/api/v1/customers/:customerId/threat-intel/enrich", { preHandler: requireWrite }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const query = normalizeThreatIntelQuery(request.body?.query);
    const records = await repository.searchThreatIntel(request.params.customerId, query, 30);
    const generated = await llmClient.chat({
      messages: [
        {
          role: "system",
          content: "You are a defensive vulnerability intelligence analyst operating on private scanner evidence. Return one valid JSON object only. Never invent CVEs, affected versions, patches, exploit status, commands, or links. Use Unknown when evidence is absent.",
        },
        { role: "user", content: threatIntelPrompt(query, records) },
      ],
      json: true,
      temperature: 0,
      maxTokens: 4096,
    });
    const saved = await repository.saveThreatIntelEnrichment(request.auth.user.id, request.params.customerId, {
      query,
      model: generated.model,
      evidenceCount: records.length,
      responseText: generated.content,
    });
    await repository.audit(request.auth.user.id, request.params.customerId, "threat_intel.enriched", {
      query,
      model: generated.model,
      evidenceCount: records.length,
      enrichmentId: saved.id,
    }, request.ip);
    return { ok: true, content: generated.content, model: generated.model, evidenceCount: records.length, records };
  });

  app.post("/api/v1/customers/:customerId/teams", { preHandler: requireWrite }, async (request, reply) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const team = await repository.createCustomerTeam(request.auth.user.id, request.params.customerId, normalizeTeamPayload(request.body), request.ip);
    return reply.code(201).send({ ok: true, team });
  });

  app.put("/api/v1/customers/:customerId/teams/:teamId", { preHandler: requireWrite }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    return { ok: true, team: await repository.updateCustomerTeam(request.auth.user.id, request.params.customerId, request.params.teamId, normalizeTeamPayload(request.body), request.ip) };
  });

  app.post("/api/v1/customers/:customerId/assets", { preHandler: requireWrite }, async (request) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const assets = normalizeAssetPayloads(request.body);
    assertAssetTypeAccess(assets, access.assetTypes);
    const result = await repository.upsertCustomerAssets(request.auth.user.id, request.params.customerId, assets, request.ip);
    return { ok: true, ...result };
  });

  app.delete("/api/v1/customers/:customerId/assets", { preHandler: requireWrite }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const assetIds = normalizeAssetIds(request.body);
    return { ok: true, ...(await repository.deleteCustomerAssets(request.auth.user.id, request.params.customerId, assetIds, request.ip)) };
  });

  app.patch("/api/v1/customers/:customerId/assets/:assetId", { preHandler: requireWrite }, async (request) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const hasAssetType = Object.hasOwn(request.body ?? {}, "assetType");
    const hasTeamId = Object.hasOwn(request.body ?? {}, "teamId");
    const hasOnboardingTool = Object.hasOwn(request.body ?? {}, "onboardingTool");
    const hasPlatform = Object.hasOwn(request.body ?? {}, "platform");
    const hasIpAddress = Object.hasOwn(request.body ?? {}, "ipAddress");
    const hasDnsName = Object.hasOwn(request.body ?? {}, "dnsName");
    const hasHostName = Object.hasOwn(request.body ?? {}, "hostName");
    const assetType = hasAssetType && ASSET_TYPES.includes(request.body?.assetType) ? request.body.assetType : undefined;
    if (hasAssetType && !assetType) throw badRequest("Select a valid asset category.");
    if (assetType && access.assetTypes.length && !access.assetTypes.includes(assetType)) throw badRequest("This asset category is outside your account scope.", 403);
    const rawTeamId = request.body?.teamId;
    if (hasTeamId && rawTeamId && !/^[0-9a-f-]{36}$/i.test(String(rawTeamId))) throw badRequest("Select a valid responsible team.");
    const onboardingTool = hasOnboardingTool ? normalizeAssetOnboardingTool(request.body?.onboardingTool) : undefined;
    const platform = hasPlatform ? cleanAssetField(request.body?.platform, 2000) : undefined;
    const ipAddress = hasIpAddress ? cleanAssetField(request.body?.ipAddress, 500) : undefined;
    const dnsName = hasDnsName ? cleanAssetField(request.body?.dnsName, 1000).toLowerCase() : undefined;
    const hostName = hasHostName ? cleanAssetField(request.body?.hostName, 1000).toLowerCase() : undefined;
    return {
      ok: true,
      asset: await repository.updateCustomerAsset(request.auth.user.id, request.params.customerId, request.params.assetId, {
        inScope: typeof request.body?.inScope === "boolean" ? request.body.inScope : undefined,
        assetType,
        teamId: rawTeamId ? String(rawTeamId) : null,
        hasTeamId,
        onboardingTool,
        hasOnboardingTool,
        platform,
        hasPlatform,
        ipAddress,
        hasIpAddress,
        dnsName,
        hasDnsName,
        hostName,
        hasHostName,
      }, request.ip),
    };
  });

  app.get("/api/v1/admin/users", { preHandler: authenticate }, async (request) => {
    if (request.auth.user.globalRole !== "system_admin") throw badRequest("System administrator access is required.", 403);
    return { ok: true, users: await repository.listUsers() };
  });

  app.post("/api/v1/admin/users", { preHandler: requireAdmin }, async (request, reply) => {
    const account = validateAccountInput(request.body);
    const globalRole = request.body?.globalRole === "system_admin" ? "system_admin" : "customer_user";
    const memberships = normalizeMemberships(request.body?.memberships);
    if (globalRole === "customer_user" && !memberships.length) throw badRequest("Assign a customer user to at least one customer.");
    const user = await repository.createUser(request.auth.user.id, {
      email: account.email,
      fullName: account.fullName,
      passwordHash: await hashPassword(account.password),
      globalRole,
      memberships,
    }, request.ip);
    return reply.code(201).send({ ok: true, user });
  });

  app.post("/api/v1/customers/:customerId/scan-runs", { preHandler: requireWrite }, async (request, reply) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const metadata = normalizeCreatePayload({ ...request.body, customerName: access.customer.name });
    const run = await repository.createScanRun(request.params.customerId, request.auth.user.id, metadata);
    return reply.code(run.existing ? 200 : 201).send({ ok: true, run });
  });

  app.post("/api/v1/customers/:customerId/scan-runs/:id/chunks", { preHandler: requireWrite }, async (request) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const result = await repository.ingestChunk(request.params.customerId, request.params.id, request.body, access.assetTypes);
    return { ok: true, ...result };
  });

  app.post("/api/v1/customers/:customerId/scan-runs/:id/finalize", { preHandler: requireWrite }, async (request) => {
    await repository.assertCustomerAccess(request.auth.user, request.params.customerId, ["owner", "analyst"]);
    const run = await repository.finalizeScanRun(request.params.customerId, request.params.id);
    await repository.audit(request.auth.user.id, request.params.customerId, "scan.finalized", { scanRunId: request.params.id }, request.ip);
    return { ok: true, run };
  });

  app.get("/api/v1/customers/:customerId/scan-runs", { preHandler: authenticate }, async (request) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId);
    const requested = Number(request.query?.limit ?? 20);
    const limit = Number.isInteger(requested) ? Math.min(100, Math.max(1, requested)) : 20;
    return { ok: true, runs: await repository.listScanRuns(request.params.customerId, limit, access.assetTypes) };
  });

  app.get("/api/v1/customers/:customerId/scan-runs/:id", { preHandler: authenticate }, async (request) => {
    const access = await repository.assertCustomerAccess(request.auth.user, request.params.customerId);
    return { ok: true, run: await repository.getScanRun(request.params.customerId, request.params.id, access.assetTypes) };
  });

  app.setErrorHandler((error, request, reply) => {
    const statusCode = Number(error.statusCode) >= 400 && Number(error.statusCode) < 600 ? Number(error.statusCode) : 500;
    if (statusCode >= 500) request.log.error(error);
    else request.log.warn({ statusCode, message: error.message }, "Request rejected");
    reply.code(statusCode).send({ ok: false, error: statusCode === 500 ? "The MVA platform request failed." : error.message });
  });

  return app;
}

function normalizeMemberships(value) {
  const rows = Array.isArray(value) ? value : [];
  const validRoles = new Set(["owner", "analyst", "viewer"]);
  return [...new Map(rows.map((row) => {
    const customerId = String(row?.customerId ?? "").trim();
    const role = validRoles.has(row?.role) ? row.role : "viewer";
    const assetTypes = [...new Set((Array.isArray(row?.assetTypes) ? row.assetTypes : []).filter((assetType) => ASSET_TYPES.includes(assetType)))];
    return [customerId, { customerId, role, assetTypes }];
  }).filter(([customerId]) => /^[0-9a-f-]{36}$/i.test(customerId))).values()];
}

function normalizeDashboardFilters(query = {}) {
  const teamId = query?.teamId ? String(query.teamId) : null;
  const assetId = query?.assetId ? String(query.assetId) : null;
  if (teamId && !/^[0-9a-f-]{36}$/i.test(teamId)) throw badRequest("Select a valid responsible team.");
  if (assetId && !/^[0-9a-f-]{36}$/i.test(assetId)) throw badRequest("Select a valid asset.");
  return { teamId, assetId };
}

function assertAssetTypeAccess(assets, assetTypes) {
  if (!assetTypes?.length) return;
  const blocked = assets.find((asset) => !assetTypes.includes(asset.assetType));
  if (blocked) throw badRequest(`This account is limited to ${assetTypes.join(", ")} assets and cannot modify ${blocked.assetType} inventory.`, 403);
}

function cleanAssetField(value, maxLength) {
  return String(value ?? "").replace(/\u0000/g, "").trim().slice(0, maxLength);
}

function threatIntelPrompt(query, records) {
  const evidence = records.map((record) => ({
    cve: record.cve,
    vulnerabilityName: record.vulnerabilityName,
    sourceTool: record.sourceTool,
    sourceVulnerabilityId: record.sourceVulnerabilityId,
    severity: record.severity,
    patchPriority: record.patchPriority,
    exploitAvailable: record.exploitAvailable,
    vulnerabilityConfidence: record.vulnerabilityConfidence,
    exploitEvidence: record.exploitEvidence,
    description: record.description,
    remediation: record.remediation,
    kbLinks: record.kbLinks,
    product: record.product,
    platformDetails: record.platformDetails,
    firstObserved: record.firstObserved,
    lastObserved: record.lastObserved,
  }));
  return `Investigate: ${query}

Return JSON keys:
summary, highestSeverity, cvss, cves, affectedProducts, affectedVersions, exploitAvailable, exploitEvidence, attackPath, patches, remediationSteps, detectionSteps, references.

Rules:
- Treat the supplied scanner evidence as the primary source.
- Distinguish confirmed facts from model inference.
- Use only HTTPS references present in the evidence.
- Do not provide exploit payloads or offensive execution steps.
- Use "Unknown" or an empty array where evidence is insufficient.

Tenant scanner evidence:
${JSON.stringify(evidence, null, 2)}`;
}

function unavailableLlmClient() {
  const status = () => ({ configured: false, provider: "Local Ollama", model: "", baseUrl: "" });
  const unavailable = async () => {
    throw badRequest("The local Ollama client is not configured on the MVA API.", 503);
  };
  return { status, test: unavailable, chat: unavailable };
}

function enforceLoginRate(store, key) {
  const state = store.get(key);
  if (!state || state.resetAt <= Date.now()) {
    store.delete(key);
    return;
  }
  if (state.count >= LOGIN_ATTEMPT_LIMIT) throw badRequest("Too many sign-in attempts. Try again later.", 429);
}

function registerLoginFailure(store, key) {
  const current = store.get(key);
  if (!current || current.resetAt <= Date.now()) store.set(key, { count: 1, resetAt: Date.now() + LOGIN_WINDOW_MS });
  else store.set(key, { ...current, count: current.count + 1 });
}
