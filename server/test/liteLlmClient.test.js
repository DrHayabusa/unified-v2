import assert from "node:assert/strict";
import test from "node:test";

import { LiteLLMClient } from "../src/liteLlmClient.js";

function jsonResponse(payload, { status = 200 } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(payload),
  };
}

test("LiteLLM client requires a server-side API key and model alias", () => {
  assert.throws(
    () => new LiteLLMClient({ apiKey: "", model: "mva-model" }),
    /LITELLM_API_KEY is required/,
  );
  assert.throws(
    () => new LiteLLMClient({ apiKey: "test-key", model: "" }),
    /LITELLM_MODEL is required/,
  );
});

test("LiteLLM client authenticates model discovery without exposing its API key", async () => {
  const requests = [];
  const apiKey = "litellm-test-credential";
  const client = new LiteLLMClient({
    baseUrl: "http://litellm.internal:4000/",
    apiKey,
    model: "mva-remediation",
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return jsonResponse({
        object: "list",
        data: [
          { id: "mva-remediation", object: "model" },
          { id: "mva-intelligence", object: "model" },
        ],
      });
    },
  });

  const result = await client.test();
  assert.equal(result.reachable, true);
  assert.equal(result.modelInstalled, true);
  assert.equal(result.model, "mva-remediation");
  assert.equal(result.provider, "LiteLLM Proxy");
  assert.equal(result.authenticationConfigured, true);
  assert.equal(JSON.stringify(result).includes(apiKey), false);
  assert.equal(requests[0].url, "http://litellm.internal:4000/v1/models");
  assert.equal(requests[0].options.method, "GET");
  assert.equal(requests[0].options.headers.get("Authorization"), `Bearer ${apiKey}`);
});

test("LiteLLM client sends OpenAI-compatible JSON chat and preserves the app contract", async () => {
  let captured;
  const client = new LiteLLMClient({
    baseUrl: "http://127.0.0.1:4000",
    apiKey: "chat-test-credential",
    model: "mva-remediation",
    fetchImpl: async (url, options) => {
      captured = { url, options, body: JSON.parse(options.body) };
      return jsonResponse({
        model: "mva-remediation",
        choices: [{
          index: 0,
          message: { role: "assistant", content: "{\"summary\":\"Validated\"}" },
          finish_reason: "stop",
        }],
      });
    },
  });

  const result = await client.chat({
    messages: [{ role: "user", content: "Use scanner evidence only." }],
    json: true,
    temperature: 0,
    maxTokens: 100_000,
  });

  assert.equal(captured.url, "http://127.0.0.1:4000/v1/chat/completions");
  assert.equal(captured.options.headers.get("Authorization"), "Bearer chat-test-credential");
  assert.equal(captured.options.headers.get("Content-Type"), "application/json");
  assert.equal(captured.body.model, "mva-remediation");
  assert.equal(captured.body.stream, undefined);
  assert.equal(captured.body.temperature, 0);
  assert.equal(captured.body.max_tokens, 32_768);
  assert.deepEqual(captured.body.response_format, { type: "json_object" });
  assert.equal(result.content, "{\"summary\":\"Validated\"}");
  assert.equal(result.model, "mva-remediation");
  assert.equal(result.doneReason, "stop");
});

test("LiteLLM client omits response_format for Markdown remediation output", async () => {
  let body;
  const client = new LiteLLMClient({
    apiKey: "chat-test-credential",
    model: "mva-remediation",
    fetchImpl: async (_url, options) => {
      body = JSON.parse(options.body);
      return jsonResponse({
        choices: [{ message: { content: "# Remediation Guide" }, finish_reason: "stop" }],
      });
    },
  });

  const result = await client.chat({
    messages: [{ role: "user", content: "Generate Markdown." }],
  });

  assert.equal(body.response_format, undefined);
  assert.equal(result.content, "# Remediation Guide");
});

test("LiteLLM client reports missing aliases, proxy errors, and network failures clearly", async () => {
  const missing = new LiteLLMClient({
    apiKey: "test-key",
    model: "mva-remediation",
    fetchImpl: async () => jsonResponse({ data: [{ id: "another-model" }] }),
  });
  await assert.rejects(missing.test(), /model alias 'mva-remediation' is not available/);

  const unauthorized = new LiteLLMClient({
    apiKey: "invalid-key",
    model: "mva-remediation",
    fetchImpl: async () => jsonResponse(
      { error: { message: "Authentication failed" } },
      { status: 401 },
    ),
  });
  await assert.rejects(unauthorized.test(), /Authentication failed/);

  const unreachable = new LiteLLMClient({
    apiKey: "test-key",
    model: "mva-remediation",
    fetchImpl: async () => {
      throw new TypeError("fetch failed");
    },
  });
  await assert.rejects(unreachable.test(), /cannot reach LiteLLM/);
});

test("LiteLLM client bounds connection and response-body waits", async () => {
  const abortError = () => Object.assign(new Error("aborted"), { name: "AbortError" });
  const connecting = new LiteLLMClient({
    apiKey: "test-key",
    model: "mva-remediation",
    connectTimeoutMs: 1_000,
    fetchImpl: async (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(abortError()), { once: true });
    }),
  });
  await assert.rejects(connecting.test(), /connection timed out/);

  const reading = new LiteLLMClient({
    apiKey: "test-key",
    model: "mva-remediation",
    readTimeoutMs: 1_000,
    fetchImpl: async (_url, options) => ({
      ok: true,
      status: 200,
      text: async () => new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(abortError()), { once: true });
      }),
    }),
  });
  await assert.rejects(
    reading.chat({ messages: [{ role: "user", content: "Timeout validation" }] }),
    /response timed out/,
  );
});
