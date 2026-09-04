/**
 * Tiny req/res shims so the handler can be driven from a raw node:http server
 * (the local smoke server) and from unit tests, without pulling in Express.
 * In production the Cloud Functions runtime supplies the real Express req/res.
 */

"use strict";

/** Build a fake response that records status/json/headers for assertions. */
function makeRes() {
  const res = {
    statusCode: 200,
    body: undefined,
    headers: {},
    setHeader(k, v) {
      this.headers[k.toLowerCase()] = v;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      this._sent = true;
      return this;
    },
  };
  return res;
}

/** Build a fake request from a method/body/headers triple. */
function makeReq({ method = "POST", body = {}, headers = {}, path = "/", url } = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return {
    method,
    body,
    path,
    url: url || path,
    headers: lower,
    get(name) {
      return lower[String(name).toLowerCase()];
    },
  };
}

module.exports = { makeRes, makeReq };
