/**
 * Auth0 (OIDC) bearer-token authorizer for the tenant-scoped Read API.
 *
 * Verifies an RS256 JWT and extracts the tenant (client_id) + role a viewer is scoped to.
 * It is the `authorize` strategy read-api.js injects: the Read API stays DENY-BY-DEFAULT,
 * and this only ever GRANTS a caller their own tenant — cross-tenant is still blocked by
 * read-api.js (path client_id must equal the returned client_id).
 *
 * FAIL-CLOSED and hardened against the usual JWT pitfalls:
 *   * the algorithm is PINNED (RS256) — an `alg:none` or `HS256` header is rejected before
 *     any verification, so a public key can never be abused as an HMAC secret;
 *   * `exp` is required and enforced (+ `nbf`, small clock tolerance);
 *   * optional `iss` / `aud` are enforced when configured;
 *   * a tampered token, unknown key, missing/late/early time, or missing client claim all
 *     return null (deny).
 *
 * The org model is NOT hardcoded: the claim carrying client_id (and role) is configuration
 * (`clientClaim` / `roleClaim`) — a plain or namespaced claim name (e.g.
 * "https://asp.ironcityit.com/client_id"). Signing keys come from an injected `getKey`
 * (a JWKS resolver in prod, a static key in tests). No external dependency — Node's crypto
 * verifies RS256 and imports JWK public keys directly.
 */

"use strict";

const crypto = require("crypto");

function b64urlToBuf(str) {
  const s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(s + "=".repeat((4 - (s.length % 4)) % 4), "base64");
}
function b64urlJson(str) {
  try {
    return JSON.parse(b64urlToBuf(str).toString("utf8"));
  } catch {
    return null;
  }
}
// Namespaced Auth0 claims are flat keys ("https://ns/client_id"); also allow dotted paths.
function getClaim(payload, pathName) {
  if (!pathName) return undefined;
  if (Object.prototype.hasOwnProperty.call(payload, pathName)) return payload[pathName];
  return String(pathName).split(".").reduce((o, k) => (o == null ? undefined : o[k]), payload);
}
function bearer(req) {
  const h =
    (req.get && req.get("authorization")) ||
    (req.headers && (req.headers.authorization || req.headers.Authorization)) ||
    "";
  const m = /^Bearer\s+(.+)$/i.exec(String(h).trim());
  return m ? m[1] : "";
}

/**
 * @param {object} opts
 * @param {(kid:string, alg:string)=>Promise<crypto.KeyObject|object|string|null>} opts.getKey
 * @param {string}  opts.clientClaim   REQUIRED claim carrying the tenant id
 * @param {string} [opts.roleClaim]    claim carrying the role (default role: "viewer")
 * @param {string} [opts.issuer]       expected iss
 * @param {string} [opts.audience]     expected aud
 * @param {string} [opts.alg]          pinned algorithm (default RS256)
 * @param {number}[opts.clockToleranceSec]
 * @returns {(req)=>Promise<{client_id,role,subject}|null>}
 */
function createBearerVerifier(opts = {}) {
  const getKey = opts.getKey;
  if (typeof getKey !== "function") throw new Error("createBearerVerifier: getKey(kid) is required");
  if (!opts.clientClaim) throw new Error("createBearerVerifier: clientClaim is required");
  const alg = opts.alg || "RS256";
  const { issuer, audience, roleClaim, clientClaim } = opts;
  const tol = Number.isFinite(opts.clockToleranceSec) ? opts.clockToleranceSec : 30;

  return async function authorize(req) {
    try {
      const token = bearer(req);
      if (!token) return null;
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      const [h64, p64, s64] = parts;

      const header = b64urlJson(h64);
      if (!header || header.alg !== alg) return null; // pin alg — rejects none/HS256/confusion
      const payload = b64urlJson(p64);
      if (!payload) return null;

      let material;
      try {
        material = await getKey(header.kid, alg);
      } catch {
        return null;
      }
      if (!material) return null;
      let pubKey;
      try {
        pubKey =
          material instanceof crypto.KeyObject
            ? material
            : crypto.createPublicKey(
                material && typeof material === "object" && material.kty
                  ? { key: material, format: "jwk" }
                  : material
              );
      } catch {
        return null;
      }
      if (pubKey.asymmetricKeyType !== "rsa") return null; // RS256 needs an RSA key

      const ok = crypto.verify("RSA-SHA256", Buffer.from(`${h64}.${p64}`), pubKey, b64urlToBuf(s64));
      if (!ok) return null;

      const now = Math.floor(Date.now() / 1000);
      if (typeof payload.exp !== "number") return null; // require exp
      if (now > payload.exp + tol) return null;
      if (typeof payload.nbf === "number" && now + tol < payload.nbf) return null;
      if (issuer && payload.iss !== issuer) return null;
      if (audience) {
        const a = payload.aud;
        const okAud = Array.isArray(a) ? a.includes(audience) : a === audience;
        if (!okAud) return null;
      }

      const client = getClaim(payload, clientClaim);
      if (!client || typeof client !== "string") return null;
      const role = roleClaim ? getClaim(payload, roleClaim) : undefined;
      return {
        client_id: client.trim().toLowerCase(),
        role: typeof role === "string" && role ? role : "viewer",
        subject: payload.sub,
      };
    } catch {
      return null;
    }
  };
}

/**
 * JWKS-backed key resolver (prod). Fetches the signing keys from `jwksUrl` (global fetch,
 * injectable for tests) with a small in-memory cache, and returns the RSA public key for a
 * token's kid.
 */
function createJwksKeyResolver(opts = {}) {
  const jwksUrl = opts.jwksUrl;
  if (!jwksUrl) throw new Error("createJwksKeyResolver: jwksUrl is required");
  const fetchImpl = opts.fetch || globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("createJwksKeyResolver: no fetch available");
  const ttlMs = Number.isFinite(opts.ttlMs) ? opts.ttlMs : 3600000;
  let cache = null;
  let cacheAt = 0;

  async function keys() {
    const now = Date.now();
    if (cache && now - cacheAt < ttlMs) return cache;
    const res = await fetchImpl(jwksUrl);
    if (!res.ok) throw new Error("jwks fetch " + res.status);
    const body = await res.json();
    cache = Array.isArray(body.keys) ? body.keys : [];
    cacheAt = now;
    return cache;
  }

  return async function getKey(kid) {
    const ks = await keys();
    const jwk = ks.find((k) => k.kid === kid) || (ks.length === 1 ? ks[0] : null);
    if (!jwk) return null;
    return crypto.createPublicKey({ key: jwk, format: "jwk" });
  };
}

/** Build an authorizer from env, or undefined (Read API then stays deny-by-default). */
function authorizerFromEnv(env = {}) {
  if (!env.ASP_AUTH_JWKS_URL || !env.ASP_AUTH_CLIENT_CLAIM) return undefined;
  return createBearerVerifier({
    getKey: createJwksKeyResolver({ jwksUrl: env.ASP_AUTH_JWKS_URL }),
    issuer: env.ASP_AUTH_ISSUER,
    audience: env.ASP_AUTH_AUDIENCE,
    clientClaim: env.ASP_AUTH_CLIENT_CLAIM,
    roleClaim: env.ASP_AUTH_ROLE_CLAIM,
  });
}

module.exports = { createBearerVerifier, createJwksKeyResolver, authorizerFromEnv };
