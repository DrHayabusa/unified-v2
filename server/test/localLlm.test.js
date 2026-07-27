import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { OllamaClient } from "../src/localLlm.js";

function jsonResponse(payload, { status = 200 } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  };
}

test("Ollama client authenticates model discovery without exposing its API key in status", async () => {
  const requests = [];
  const apiKey = "local-model-test-credential";
  const client = new OllamaClient({
    baseUrl: "http://ollama.internal:11434/",
    model: "gemma3:12b",
    apiKey,
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return jsonResponse({ models: [{ name: "gemma3:12b" }, { name: "nomic-embed-text:latest" }] });
    },
  });

  const result = await client.test();
  assert.equal(result.reachable, true);
  assert.equal(result.modelInstalled, true);
  assert.equal(result.model, "gemma3:12b");
  assert.equal(result.authenticationConfigured, true);
  assert.equal(result.authenticationHeader, "Authorization");
  assert.equal(JSON.stringify(result).includes(apiKey), false);
  assert.equal(requests[0].url, "http://ollama.internal:11434/api/tags");
  assert.equal(requests[0].options.method, "GET");
  assert.equal(requests[0].options.headers.get("Authorization"), `Bearer ${apiKey}`);
});

test("Ollama client authenticates bounded non-streaming chat requests and returns model content", async () => {
  let captured;
  const client = new OllamaClient({
    baseUrl: "http://127.0.0.1:11434",
    model: "gemma3:12b",
    apiKey: "chat-test-credential",
    fetchImpl: async (url, options) => {
      captured = { url, options, body: JSON.parse(options.body) };
      return jsonResponse({ model: "gemma3:12b", message: { content: "{\"summary\":\"Validated\"}" }, done_reason: "stop" });
    },
  });

  const result = await client.chat({
    messages: [{ role: "user", content: "Use scanner evidence only." }],
    json: true,
    temperature: 0,
    maxTokens: 100_000,
  });
  assert.equal(captured.url, "http://127.0.0.1:11434/api/chat");
  assert.equal(captured.body.stream, false);
  assert.equal(captured.body.format, "json");
  assert.equal(captured.body.options.num_predict, 32_768);
  assert.equal(captured.options.headers.get("Authorization"), "Bearer chat-test-credential");
  assert.equal(result.content, "{\"summary\":\"Validated\"}");
});

test("Ollama client loads a custom authentication header from a secret file", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "mva-ollama-auth-"));
  const secretFile = join(directory, "ollama_api_key");
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  writeFileSync(secretFile, "private-gateway-test-key\n", { mode: 0o600 });

  let captured;
  const client = new OllamaClient({
    apiKeyFile: secretFile,
    authHeader: "X-API-Key",
    authScheme: "",
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return jsonResponse({ models: [{ name: "gemma3:12b" }] });
    },
  });

  const result = await client.test();
  assert.equal(captured.options.headers.get("X-API-Key"), "private-gateway-test-key");
  assert.equal(result.authenticationConfigured, true);
  assert.equal(JSON.stringify(result).includes("private-gateway-test-key"), false);
});

test("Ollama client reports missing models and unreachable local services clearly", async () => {
  const missing = new OllamaClient({
    model: "gemma3:12b",
    fetchImpl: async () => jsonResponse({ models: [{ name: "llama3.2:latest" }] }),
  });
  await assert.rejects(missing.test(), /ollama pull gemma3:12b/);

  const unreachable = new OllamaClient({
    fetchImpl: async () => {
      throw new TypeError("fetch failed");
    },
  });
  await assert.rejects(unreachable.test(), /cannot reach Ollama/);
});
