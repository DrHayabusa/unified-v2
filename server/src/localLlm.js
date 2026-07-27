import { readFileSync } from "node:fs";

import { badRequest } from "./validation.js";

const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;

export class OllamaClient {
  constructor({
    baseUrl = process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434",
    model = process.env.OLLAMA_MODEL || "gemma3:12b",
    timeoutMs = Number(process.env.OLLAMA_TIMEOUT_MS || DEFAULT_TIMEOUT_MS),
    apiKeyFile = process.env.OLLAMA_API_KEY_FILE || "",
    apiKey = readSecret(apiKeyFile) || process.env.OLLAMA_API_KEY || "",
    authHeader = process.env.OLLAMA_AUTH_HEADER || "Authorization",
    authScheme = process.env.OLLAMA_AUTH_SCHEME ?? "Bearer",
    fetchImpl = fetch,
  } = {}) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.model = String(model || "").trim();
    this.timeoutMs = Number.isFinite(timeoutMs) ? Math.min(30 * 60 * 1000, Math.max(5_000, timeoutMs)) : DEFAULT_TIMEOUT_MS;
    this.apiKey = normalizeApiKey(apiKey);
    this.authHeader = normalizeAuthHeader(authHeader);
    this.authScheme = normalizeAuthScheme(authScheme);
    this.fetchImpl = fetchImpl;
  }

  status() {
    return {
      configured: Boolean(this.baseUrl && this.model),
      provider: "Local Ollama",
      model: this.model,
      baseUrl: this.baseUrl,
      authenticationConfigured: Boolean(this.apiKey),
      authenticationHeader: this.apiKey ? this.authHeader : "",
    };
  }

  async test() {
    const payload = await this.#request("/api/tags", { method: "GET" }, 20_000);
    const installedModels = (payload.models ?? []).map((item) => item.name || item.model).filter(Boolean);
    const modelInstalled = installedModels.some((name) => name === this.model || name.split(":")[0] === this.model.split(":")[0]);
    if (!modelInstalled) {
      throw badRequest(`Ollama is reachable, but ${this.model} is not installed. Run: ollama pull ${this.model}`, 503);
    }
    return { ...this.status(), reachable: true, modelInstalled, installedModels };
  }

  async chat({ messages, json = false, temperature = 0.1, maxTokens = 8192 }) {
    if (!this.baseUrl || !this.model) throw badRequest("The local Ollama model is not configured on the MVA API.", 503);
    const payload = await this.#request("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: this.model,
        messages,
        stream: false,
        ...(json ? { format: "json" } : {}),
        options: {
          temperature,
          num_predict: Math.min(32_768, Math.max(16, Number(maxTokens) || 8192)),
        },
      }),
    });
    const content = String(payload?.message?.content ?? payload?.response ?? "").trim();
    if (!content) throw badRequest("The local Ollama model returned no content.", 502);
    return { content, model: payload.model || this.model, doneReason: payload.done_reason || "" };
  }

  async #request(path, options, timeoutMs = this.timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers = new Headers(options.headers || {});
      if (this.apiKey) {
        headers.set(this.authHeader, this.authScheme ? `${this.authScheme} ${this.apiKey}` : this.apiKey);
      }
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, { ...options, headers, signal: controller.signal });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = payload?.error || payload?.message || `Ollama returned HTTP ${response.status}.`;
        throw badRequest(String(detail).slice(0, 1000), response.status >= 400 && response.status < 600 ? response.status : 502);
      }
      return payload;
    } catch (error) {
      if (error.name === "AbortError") throw badRequest("The local Ollama request timed out.", 504);
      if (error instanceof TypeError || /fetch failed|ECONNREFUSED|ENOTFOUND/i.test(error.message || "")) {
        throw badRequest("The MVA API cannot reach Ollama. Start Ollama and verify OLLAMA_BASE_URL.", 503);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}

function normalizeBaseUrl(value) {
  const text = String(value || "").trim().replace(/\/+$/, "");
  if (!text) return "";
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new Error("OLLAMA_BASE_URL must be a valid HTTP or HTTPS URL.");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error("OLLAMA_BASE_URL must use HTTP(S) without embedded credentials.");
  }
  return text;
}

function readSecret(filePath) {
  const normalizedPath = String(filePath || "").trim();
  if (!normalizedPath) return "";
  try {
    return readFileSync(normalizedPath, "utf8").trim();
  } catch (error) {
    throw new Error(`Could not read the Ollama API-key secret file: ${error.message}`);
  }
}

function normalizeApiKey(value) {
  const key = String(value || "").trim();
  if (/[\r\n]/.test(key)) throw new Error("OLLAMA_API_KEY must not contain line breaks.");
  if (key.length > 8192) throw new Error("OLLAMA_API_KEY is too long.");
  return key;
}

function normalizeAuthHeader(value) {
  const header = String(value || "Authorization").trim();
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(header)) {
    throw new Error("OLLAMA_AUTH_HEADER must be a valid HTTP header name.");
  }
  return header;
}

function normalizeAuthScheme(value) {
  const scheme = String(value ?? "Bearer").trim();
  if (scheme && !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(scheme)) {
    throw new Error("OLLAMA_AUTH_SCHEME must be empty or a valid authentication scheme.");
  }
  return scheme;
}
