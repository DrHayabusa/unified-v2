import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

import { badRequest } from "./validation.js";

const scrypt = promisify(scryptCallback);
const SCRYPT_N = 2 ** 15;
const SCRYPT_R = 8;
const SCRYPT_P = 3;
const SCRYPT_KEY_LENGTH = 64;
const SCRYPT_MAX_MEMORY = 64 * 1024 * 1024;

export function normalizeEmail(value) {
  return String(value ?? "").trim().toLowerCase().slice(0, 254);
}

export function validateAccountInput(payload = {}, { requirePassword = true } = {}) {
  const email = normalizeEmail(payload.email);
  const fullName = String(payload.fullName ?? "").replace(/\u0000/g, "").trim().slice(0, 180);
  const password = String(payload.password ?? "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw badRequest("Enter a valid email address.");
  if (fullName.length < 2) throw badRequest("Enter the user's full name.");
  if (requirePassword) validatePassword(password, email);
  return { email, fullName, password };
}

export function validatePassword(password, email = "") {
  if (typeof password !== "string" || password.length < 12) throw badRequest("Password must contain at least 12 characters.");
  if (password.length > 128) throw badRequest("Password cannot exceed 128 characters.");
  if (email && password.toLowerCase().includes(email.split("@")[0])) throw badRequest("Password must not contain the email username.");
  return password;
}

export async function hashPassword(password) {
  validatePassword(password);
  const salt = randomBytes(16);
  const derived = await derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P);
  return ["scrypt", SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.toString("base64url"), derived.toString("base64url")].join("$");
}

export async function verifyPassword(password, encodedHash) {
  try {
    const [algorithm, nText, rText, pText, saltText, hashText] = String(encodedHash ?? "").split("$");
    if (algorithm !== "scrypt") return false;
    const expected = Buffer.from(hashText, "base64url");
    const actual = await derive(password, Buffer.from(saltText, "base64url"), Number(nText), Number(rText), Number(pText));
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

export function createSessionSecrets() {
  const token = randomBytes(32).toString("base64url");
  return {
    token,
    tokenHash: hashOpaqueToken(token),
    csrfToken: randomBytes(24).toString("base64url"),
  };
}

export function hashOpaqueToken(token) {
  return createHash("sha256").update(String(token ?? "")).digest("base64url");
}

export function constantTimeEqual(left, right) {
  const first = Buffer.from(String(left ?? ""));
  const second = Buffer.from(String(right ?? ""));
  return first.length === second.length && timingSafeEqual(first, second);
}

async function derive(password, salt, N, r, p) {
  if (!Number.isInteger(N) || N < 2 ** 14 || !Number.isInteger(r) || !Number.isInteger(p)) throw new Error("Unsupported password hash parameters.");
  return scrypt(password, salt, SCRYPT_KEY_LENGTH, { N, r, p, maxmem: SCRYPT_MAX_MEMORY });
}
