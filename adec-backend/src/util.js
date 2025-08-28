import crypto from "crypto";
import * as sodium from "libsodium-wrappers";
import fetch from "node-fetch";

export async function initCrypto() {
  await sodium.ready;
}

export function sha256(bufOrStr) {
  const b = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(String(bufOrStr));
  return crypto.createHash("sha256").update(b).digest("hex");
}

export function nowIso() {
  return new Date().toISOString();
}

export function pickIp(req) {
  return (
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    ""
  );
}

export function makeId() {
  // 24-char url-safe id
  return crypto.randomBytes(18).toString("base64url");
}

export function getEncKey() {
  const keyB64 = process.env.APP_CRYPTO_KEY_B64 || "";
  if (!keyB64) return null;
  const buf = Buffer.from(keyB64, "base64");
  if (buf.length !== 32) throw new Error("APP_CRYPTO_KEY_B64 must be 32 bytes (base64)");
  return buf;
}

export function encryptPII(plaintext) {
  const key = getEncKey();
  if (!plaintext) return { ct: null, nonce: null, alg: null };
  if (!key) return { ct: plaintext, nonce: null, alg: "plain" };

  const nonce = crypto.randomBytes(24);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    Buffer.from(String(plaintext), "utf8"),
    null,
    null,
    nonce,
    key
  );
  return { ct: Buffer.from(ct).toString("base64"), nonce: nonce.toString("base64"), alg: "xchacha20poly1305" };
}

export function decryptPII({ ct, nonce, alg }) {
  const key = getEncKey();
  if (!ct) return null;
  if (!key || alg === "plain") return ct;

  const m = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    Buffer.from(ct, "base64"),
    null,
    Buffer.from(nonce, "base64"),
    key
  );
  return Buffer.from(m).toString("utf8");
}

export async function verifyRecaptcha(token, remoteip) {
  const secret = process.env.RECAPTCHA_SECRET;
  if (!secret) {
    // If unset, accept only in non-production
    return process.env.NODE_ENV !== "production";
  }
  try {
    const res = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret, response: token, remoteip })
    });
    const data = await res.json();
    const score = typeof data.score === "number" ? data.score : 0.5; // v2 doesn't return score
    return !!(data.success && score >= 0.3);
  } catch {
    return false;
  }
}

