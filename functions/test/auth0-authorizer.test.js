"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  createBearerVerifier,
  createJwksKeyResolver,
  authorizerFromEnv,
} = require("../store/auth0-authorizer");
const { createReadHandler } = require("../store/read-api");
const { makeRes } = require("../testkit/express-shim");

// --- test JWT machinery (RS256) ----------------------------------------------------
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const KID = "test-key-1";
const b64url = (buf) =>
  Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function signJwt(payload, { alg = "RS256", kid = KID, key = privateKey, tamper = false } = {}) {
  const header = b64url(JSON.stringify({ alg, typ: "JWT", kid }));
  const body = b64url(JSON.stringify(payload));
  let sig;
  if (alg === "none") sig = "";
  else if (alg === "HS256") sig = b64url(crypto.createHmac("sha256", "secret").update(`${header}.${body}`).digest());
  else sig = b64url(crypto.sign("RSA-SHA256", Buffer.from(`${header}.${body}`), key));
  let token = `${header}.${body}.${sig}`;
  if (tamper) {
    const evil = b64url(JSON.stringify({ ...payload, "client_id": "globex" }));
    token = `${header}.${evil}.${sig}`; // payload changed, signature not re-computed
  }
  return token;
}

const NOW = Math.floor(Date.now() / 1000);
const goodPayload = (over = {}) => ({
  sub: "auth0|123", iss: "https://asp.auth0.com/", aud: "asp-api",
  exp: NOW + 3600, "https://asp/client_id": "acme", "https://asp/role": "operator", ...over,
});
const staticKey = async (kid) => (kid === KID ? publicKey : null);
const req = (token) => ({ headers: token ? { authorization: "Bearer " + token } : {} });

function verifier(over = {}) {
  return createBearerVerifier({
    getKey: staticKey, issuer: "https://asp.auth0.com/", audience: "asp-api",
    clientClaim: "https://asp/client_id", roleClaim: "https://asp/role", ...over,
  });
}

test("valid RS256 token yields tenant + role (client_id lowercased)", async () => {
  const p = await verifier()(req(signJwt(goodPayload({ "https://asp/client_id": "Acme" }))));
  assert.deepEqual(p, { client_id: "acme", role: "operator", subject: "auth0|123" });
});

test("role defaults to viewer when the role claim is absent", async () => {
  const p = await verifier()(req(signJwt(goodPayload({ "https://asp/role": undefined }))));
  assert.equal(p.role, "viewer");
});

test("rejects alg:none (deny)", async () => {
  assert.equal(await verifier()(req(signJwt(goodPayload(), { alg: "none" }))), null);
});

test("rejects HS256 header (alg pinning defeats key-confusion)", async () => {
  assert.equal(await verifier()(req(signJwt(goodPayload(), { alg: "HS256" }))), null);
});

test("rejects a tampered payload (signature no longer matches)", async () => {
  assert.equal(await verifier()(req(signJwt(goodPayload(), { tamper: true }))), null);
});

test("rejects an expired token", async () => {
  assert.equal(await verifier()(req(signJwt(goodPayload({ exp: NOW - 3600 })))), null);
});

test("rejects a not-yet-valid token (nbf in the future)", async () => {
  assert.equal(await verifier()(req(signJwt(goodPayload({ nbf: NOW + 3600 })))), null);
});

test("requires exp", async () => {
  assert.equal(await verifier()(req(signJwt(goodPayload({ exp: undefined })))), null);
});

test("enforces issuer and audience when configured", async () => {
  assert.equal(await verifier()(req(signJwt(goodPayload({ iss: "https://evil/" })))), null);
  assert.equal(await verifier()(req(signJwt(goodPayload({ aud: "other-api" })))), null);
});

test("rejects an unknown signing key (kid miss)", async () => {
  const { privateKey: otherPriv } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  assert.equal(await verifier()(req(signJwt(goodPayload(), { key: otherPriv }))), null);
});

test("rejects missing/garbage bearer tokens", async () => {
  const v = verifier();
  assert.equal(await v(req("")), null);
  assert.equal(await v(req("not.a.jwt.at.all")), null);
  assert.equal(await v({ headers: { authorization: "Basic abc" } }), null);
});

test("rejects a token with no client claim", async () => {
  assert.equal(await verifier()(req(signJwt(goodPayload({ "https://asp/client_id": undefined })))), null);
});

test("createBearerVerifier validates its own config", () => {
  assert.throws(() => createBearerVerifier({ clientClaim: "x" }), /getKey/);
  assert.throws(() => createBearerVerifier({ getKey: () => {} }), /clientClaim/);
});

test("JWKS resolver fetches the key and verifies end to end", async () => {
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: KID, use: "sig", alg: "RS256" };
  const fakeFetch = async () => ({ ok: true, async json() { return { keys: [jwk] }; } });
  const getKey = createJwksKeyResolver({ jwksUrl: "https://asp.auth0.com/.well-known/jwks.json", fetch: fakeFetch });
  const v = createBearerVerifier({ getKey, clientClaim: "https://asp/client_id" });
  const p = await v(req(signJwt(goodPayload())));
  assert.equal(p.client_id, "acme");
});

test("authorizerFromEnv is undefined (deny-by-default) unless fully configured", () => {
  assert.equal(authorizerFromEnv({}), undefined);
  assert.equal(authorizerFromEnv({ ASP_AUTH_JWKS_URL: "https://x/jwks" }), undefined);
  assert.equal(typeof authorizerFromEnv({ ASP_AUTH_JWKS_URL: "https://x/jwks", ASP_AUTH_CLIENT_CLAIM: "cid" }), "function");
});

// --- end to end through the Read API with a real token -----------------------------
test("Read API + real bearer token: own tenant 200, cross-tenant 403, no token 401", async () => {
  const pool = {
    async query(sql, params) {
      if (sql.trim().startsWith("SELECT") && sql.includes("FROM scans"))
        return [[{ client_id: params[0], scan_id: "s1", status: "completed", summary_json: "{}" }], []];
      return [[], []];
    },
  };
  const handler = createReadHandler({ pool, authorize: verifier() });
  const get = (url, token) => ({
    method: "GET", url, path: url.split("?")[0], query: {},
    headers: token ? { authorization: "Bearer " + token } : {},
  });
  const token = signJwt(goodPayload()); // client_id acme

  let res = makeRes();
  await handler(get("/clients/acme/scans", token), res);
  assert.equal(res.statusCode, 200);

  res = makeRes();
  await handler(get("/clients/globex/scans", token), res); // token is for acme
  assert.equal(res.statusCode, 403);

  res = makeRes();
  await handler(get("/clients/acme/scans"), res); // no token
  assert.equal(res.statusCode, 401);
});
