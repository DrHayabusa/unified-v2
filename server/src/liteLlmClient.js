import { badRequest } from "./validation.js";

const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
const DEFAULT_READ_TIMEOUT_MS = 10 * 60 * 1000;

export class LiteLLMClient {
  constructor({
    baseUrl = process.env.LITELLM_URL || "http://127.0.0.1:4000",
    apiKey = process.env.LITELLM_API_KEY,
    model = process.env.LITELLM_MODEL,
    connectTimeoutMs = Number(process.env.LITELLM_CONNECT_TIMEOUT_MS || DEFAULT_CONNECT_TIMEOUT_MS),
    readTimeoutMs = Number(process.env.LITELLM_READ_TIMEOUT_MS || DEFAULT_READ_TIMEOUT_MS),
    fetchImpl = fetch,
  } = {}) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.apiKey = normalizeApiKey(apiKey);
    this.model = normalizeModel(model);
    this.connectTimeoutMs = boundedTimeout(connectTimeoutMs, DEFAULT_CONNECT_TIMEOUT_MS);
    this.readTimeoutMs = boundedTimeout(readTimeoutMs, DEFAULT_READ_TIMEOUT_MS);
    this.fetchImpl = fetchImpl;
  }

  status() {
    return {
      configured: Boolean(this.baseUrl && this.model && this.apiKey),
      provider: "LiteLLM Proxy",
      model: this.model,
      baseUrl: this.baseUrl,
      authenticationConfigured: true,
      authenticationHeader: "Authorization",
    };
  }

  async test() {
    const payload = await this.#request("/v1/models", { method: "GET" }, 20_000);
    const installedModels = (payload.data ?? [])
      .map((item) => item?.id)
      .filter((modelId) => typeof modelId === "string" && modelId.trim());
    const modelInstalled = installedModels.includes(this.model);
    if (!modelInstalled) {
      throw badRequest(
        `LiteLLM is reachable, but model alias '${this.model}' is not available through /v1/models.`,
        503,
      );
    }
    return {
      ...this.status(),
      reachable: true,
      modelInstalled,
      installedModels,
    };
  }

  async chat({ messages, json = false, temperature = 0.1, maxTokens = 8192 }) {
    const payload = await this.#request("/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: this.model,
        messages,
        temperature,
        max_tokens: Math.min(32_768, Math.max(16, Number(maxTokens) || 8192)),
        ...(json ? { response_format: { type: "json_object" } } : {}),
      }),
    });
    const choice = payload?.choices?.[0];
    const content = messageContent(choice?.message?.content);
    if (!content) {
      throw badRequest("The LiteLLM model returned no content.", 502);
    }
    return {
      content,
      model: payload.model || this.model,
      doneReason: choice?.finish_reason || "",
    };
  }

  async #request(path, options, readTimeoutMs = this.readTimeoutMs) {
    const controller = new AbortController();
    let phase = "connect";
    let timer = setTimeout(() => controller.abort(), this.connectTimeoutMs);
    try {
      const headers = new Headers(options.headers || {});
      headers.set("Accept", "application/json");
      headers.set("Authorization", `Bearer ${this.apiKey}`);
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...options,
        headers,
        signal: controller.signal,
      });

      clearTimeout(timer);
      phase = "read";
      timer = setTimeout(() => controller.abort(), boundedTimeout(readTimeoutMs, this.readTimeoutMs));
      const responseText = await response.text();
      const payload = parsePayload(responseText);
      if (!response.ok) {
        const detail = payload?.error?.message
          || payload?.error
          || payload?.message
          || `LiteLLM returned HTTP ${response.status}.`;
        throw badRequest(
          String(detail).slice(0, 1000),
          response.status >= 400 && response.status < 600 ? response.status : 502,
        );
      }
      if (!payload || typeof payload !== "object") {
        throw badRequest("LiteLLM returned an invalid JSON response.", 502);
      }
      return payload;
    } catch (error) {
      if (error.name === "AbortError") {
        throw badRequest(
          phase === "connect"
            ? "The LiteLLM connection timed out."
            : "The LiteLLM response timed out.",
          504,
        );
      }
      if (
        error instanceof TypeError
        || /fetch failed|ECONNREFUSED|ECONNRESET|ENOTFOUND|EHOSTUNREACH/i.test(error.message || "")
      ) {
        throw badRequest(
          "The MVA API cannot reach LiteLLM. Verify LITELLM_URL and the API-to-proxy network route.",
          503,
        );
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}

function normalizeBaseUrl(value) {
  const text = String(value || "").trim().replace(/\/+$/, "");
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new Error("LITELLM_URL must be a valid HTTP or HTTPS URL.");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error("LITELLM_URL must use HTTP(S) without embedded credentials.");
  }
  return text;
}

function normalizeApiKey(value) {
  const key = String(value || "").trim();
  if (!key) throw new Error("LITELLM_API_KEY is required.");
  if (/[\r\n]/.test(key)) throw new Error("LITELLM_API_KEY must not contain line breaks.");
  if (key.length > 8192) throw new Error("LITELLM_API_KEY is too long.");
  return key;
}

function normalizeModel(value) {
  const model = String(value || "").trim();
  if (!model) throw new Error("LITELLM_MODEL is required.");
  if (/[\r\n]/.test(model) || model.length > 500) {
    throw new Error("LITELLM_MODEL must be a valid model alias.");
  }
  return model;
}

function boundedTimeout(value, fallback) {
  const timeout = Number(value);
  if (!Number.isFinite(timeout)) return fallback;
  return Math.min(30 * 60 * 1000, Math.max(1_000, timeout));
}

function parsePayload(value) {
  if (!value) return {};
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function messageContent(value) {
  if (typeof value === "string") return value.trim();
  if (!Array.isArray(value)) return "";
  return value
    .map((part) => (typeof part === "string" ? part : part?.text || ""))
    .join("")
    .trim();
}
