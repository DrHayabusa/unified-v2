import { readFileSync } from "node:fs";

import { buildApp } from "./app.js";
import { LiteLLMClient } from "./liteLlmClient.js";
import { PostgresRepository } from "./repository.js";

const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || "0.0.0.0";
const connectionString = databaseConnectionString();
const allowedOrigins = String(process.env.CORS_ORIGINS || "http://127.0.0.1:8800,http://127.0.0.1:8801,http://127.0.0.1:8802,http://127.0.0.1:8820")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const secureCookies = String(process.env.COOKIE_SECURE || "false").toLowerCase() === "true";
const trustProxy = parseTrustProxy(process.env.TRUST_PROXY);

const repository = new PostgresRepository({ connectionString });
const llmClient = new LiteLLMClient();
await repository.migrate();
const app = await buildApp({ repository, llmClient, allowedOrigins, secureCookies, trustProxy });
let shuttingDown = false;

const shutdown = async (signal) => {
  if (shuttingDown) return;
  shuttingDown = true;
  app.log.info({ signal }, "Stopping MVA PostgreSQL API");
  await app.close();
  await repository.close();
  process.exit(0);
};

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

await app.listen({ port, host });

function parseTrustProxy(value) {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!normalized || normalized === "false" || normalized === "0") return false;
  if (normalized === "true") return true;
  if (/^\d+$/.test(normalized)) return Number(normalized);
  throw new Error("TRUST_PROXY must be false, true, or a non-negative proxy hop count.");
}

function databaseConnectionString() {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
  const user = process.env.DATABASE_USER || "mva";
  const password = readSecret(process.env.DATABASE_PASSWORD_FILE) || process.env.MVA_POSTGRES_PASSWORD || "mva_local_only";
  const databaseHost = process.env.DATABASE_HOST || "127.0.0.1";
  const databasePort = process.env.DATABASE_PORT || "55432";
  const databaseName = process.env.DATABASE_NAME || "mva";
  return `postgresql://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${databaseHost}:${databasePort}/${encodeURIComponent(databaseName)}`;
}

function readSecret(filePath) {
  if (!filePath) return "";
  try {
    return readFileSync(filePath, "utf8").trim();
  } catch (error) {
    throw new Error(`Could not read database secret file ${filePath}: ${error.message}`);
  }
}
