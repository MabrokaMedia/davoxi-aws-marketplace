"use strict";

const crypto = require("crypto");

/**
 * Unit tests for auth middleware and SNS URL validation logic.
 *
 * These tests exercise the logic directly without requiring a compiled build
 * or a running HTTP server.
 */

// ---------------------------------------------------------------------------
// Inline the pure logic under test (mirrors src/middleware/auth.ts and
// src/routes/sns.ts) so tests run without a build step.
// safeCompare mirrors the implementation in src/middleware/auth.ts.
// ---------------------------------------------------------------------------

function safeCompare(a, b) {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function makeInternalSecretAuth(envSecret) {
  return function internalSecretAuth(req, res, next) {
    const secret = envSecret;
    const provided = req.headers["x-internal-secret"];
    if (!secret || !provided || !safeCompare(provided, secret)) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    next();
  };
}

function makeAdminSecretAuth(envSecret) {
  return function adminSecretAuth(req, res, next) {
    const secret = envSecret;
    const provided = req.headers["x-admin-secret"];
    if (!secret || !provided || !safeCompare(provided, secret)) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    next();
  };
}

function validateSnsSignatureUrl(url) {
  return /^https:\/\/sns\.[a-z0-9-]+\.amazonaws\.com\//.test(url);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockRes() {
  const res = {
    _status: null,
    _body: null,
    status(code) {
      this._status = code;
      return this;
    },
    json(body) {
      this._body = body;
      return this;
    },
  };
  return res;
}

// ---------------------------------------------------------------------------
// Tests: internalSecretAuth middleware
// ---------------------------------------------------------------------------

describe("internalSecretAuth", () => {
  const SECRET = "test-internal-secret-xyz";
  const middleware = makeInternalSecretAuth(SECRET);

  test("rejects request with no x-internal-secret header", () => {
    const req = { headers: {} };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBe(401);
    expect(res._body).toEqual({ error: "Unauthorized" });
    expect(next).not.toHaveBeenCalled();
  });

  test("rejects request with wrong x-internal-secret header", () => {
    const req = { headers: { "x-internal-secret": "wrong-secret" } };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBe(401);
    expect(res._body).toEqual({ error: "Unauthorized" });
    expect(next).not.toHaveBeenCalled();
  });

  test("accepts request with correct x-internal-secret header", () => {
    const req = { headers: { "x-internal-secret": SECRET } };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBeNull();
    expect(next).toHaveBeenCalledTimes(1);
  });

  test("rejects when INTERNAL_METERING_SECRET env var is not set", () => {
    const middlewareNoSecret = makeInternalSecretAuth(undefined);
    const req = { headers: { "x-internal-secret": SECRET } };
    const res = mockRes();
    const next = jest.fn();

    middlewareNoSecret(req, res, next);

    expect(res._status).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("rejects a prefix of the secret (length-mismatch timing-safe check)", () => {
    const req = { headers: { "x-internal-secret": SECRET.slice(0, -1) } };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("rejects a secret extended by one character (length-mismatch timing-safe check)", () => {
    const req = { headers: { "x-internal-secret": SECRET + "X" } };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Tests: adminSecretAuth middleware
// ---------------------------------------------------------------------------

describe("adminSecretAuth", () => {
  const SECRET = "test-admin-secret-abc";
  const middleware = makeAdminSecretAuth(SECRET);

  test("rejects /settings/api-key request with no x-admin-secret header", () => {
    const req = { headers: {} };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBe(401);
    expect(res._body).toEqual({ error: "Unauthorized" });
    expect(next).not.toHaveBeenCalled();
  });

  test("rejects /settings/api-key request with wrong x-admin-secret header", () => {
    const req = { headers: { "x-admin-secret": "bad-secret" } };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("accepts /settings/api-key request with correct x-admin-secret header", () => {
    const req = { headers: { "x-admin-secret": SECRET } };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBeNull();
    expect(next).toHaveBeenCalledTimes(1);
  });

  test("rejects a prefix of the admin secret (length-mismatch timing-safe check)", () => {
    const req = { headers: { "x-admin-secret": SECRET.slice(0, -1) } };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("rejects admin secret extended by one character (length-mismatch timing-safe check)", () => {
    const req = { headers: { "x-admin-secret": SECRET + "Y" } };
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res._status).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Tests: validateSnsSignatureUrl (SNS SSRF protection)
// ---------------------------------------------------------------------------

describe("validateSnsSignatureUrl", () => {
  test("accepts valid amazonaws.com SNS URL", () => {
    expect(validateSnsSignatureUrl("https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123")).toBe(true);
  });

  test("accepts SNS URL for other AWS regions", () => {
    expect(validateSnsSignatureUrl("https://sns.eu-west-1.amazonaws.com/")).toBe(true);
    expect(validateSnsSignatureUrl("https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-xyz")).toBe(true);
  });

  test("rejects non-amazonaws.com URL", () => {
    expect(validateSnsSignatureUrl("https://evil.com/hook")).toBe(false);
  });

  test("rejects URL that contains amazonaws.com but is not a valid SNS URL", () => {
    expect(validateSnsSignatureUrl("https://evil.com/amazonaws.com/sns")).toBe(false);
    expect(validateSnsSignatureUrl("https://notreally.amazonaws.com.evil.com/")).toBe(false);
  });

  test("rejects http (non-https) amazonaws.com URL", () => {
    expect(validateSnsSignatureUrl("http://sns.us-east-1.amazonaws.com/")).toBe(false);
  });

  test("rejects empty string", () => {
    expect(validateSnsSignatureUrl("")).toBe(false);
  });
});
