"use strict";

/**
 * Unit tests for the in-memory IP rate limiter middleware (ipRateLimit).
 * Logic is inlined here (mirrors src/server.ts) so tests run without a build step.
 */

// ---------------------------------------------------------------------------
// Inline rate-limiter logic from src/server.ts
// ---------------------------------------------------------------------------

const RATE_LIMIT_MAX = 100;
const RATE_LIMIT_WINDOW_MS = 60_000;

function makeIpRateLimit(store, nowFn) {
  return function ipRateLimit(req, res, next) {
    // Use last X-Forwarded-For entry: AWS ALB appends the real client IP there.
    // The first entry is client-controlled and can be spoofed.
    const ip =
      (req.headers && typeof req.headers["x-forwarded-for"] === "string"
        ? req.headers["x-forwarded-for"].split(",").at(-1).trim()
        : null) ??
      (req.socket && req.socket.remoteAddress) ??
      "unknown";
    const now = nowFn();

    let entry = store.get(ip);
    if (!entry || now >= entry.reset) {
      entry = { count: 1, reset: now + RATE_LIMIT_WINDOW_MS };
      store.set(ip, entry);
      next();
      return;
    }

    entry.count += 1;
    if (entry.count > RATE_LIMIT_MAX) {
      const retryAfter = Math.ceil((entry.reset - now) / 1000);
      res.setHeader("Retry-After", String(retryAfter));
      res.status(429).json({ error: "Too many requests" });
      return;
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockRes() {
  const res = {
    _status: null,
    _body: null,
    _headers: {},
    setHeader(key, value) {
      this._headers[key] = value;
    },
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

function makeReq(ip, forwardedFor) {
  return {
    headers: forwardedFor ? { "x-forwarded-for": forwardedFor } : {},
    socket: { remoteAddress: ip },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ipRateLimit", () => {
  test("allows first request for a new IP", () => {
    const store = new Map();
    let now = 1000;
    const middleware = makeIpRateLimit(store, () => now);
    const req = makeReq("10.0.0.1");
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res._status).toBeNull();
  });

  test("allows exactly RATE_LIMIT_MAX (100) requests within the window", () => {
    const store = new Map();
    let now = 1000;
    const middleware = makeIpRateLimit(store, () => now);
    const req = makeReq("10.0.0.2");
    const next = jest.fn();

    for (let i = 0; i < 100; i++) {
      const res = mockRes();
      middleware(req, res, next);
      expect(res._status).toBeNull();
    }

    expect(next).toHaveBeenCalledTimes(100);
  });

  test("rejects the 101st request within the window with 429", () => {
    const store = new Map();
    let now = 1000;
    const middleware = makeIpRateLimit(store, () => now);
    const req = makeReq("10.0.0.3");
    const next = jest.fn();

    for (let i = 0; i < 100; i++) {
      middleware(req, mockRes(), next);
    }

    const res = mockRes();
    middleware(req, res, next);

    expect(res._status).toBe(429);
    expect(res._body).toEqual({ error: "Too many requests" });
    expect(next).toHaveBeenCalledTimes(100); // not called on the 101st
  });

  test("resets the counter after the window expires", () => {
    const store = new Map();
    let now = 1000;
    const middleware = makeIpRateLimit(store, () => now);
    const req = makeReq("10.0.0.4");
    const next = jest.fn();

    // Exhaust the limit
    for (let i = 0; i < 101; i++) {
      middleware(req, mockRes(), next);
    }
    expect(next).toHaveBeenCalledTimes(100);

    // Advance time past the window reset
    now = 1000 + RATE_LIMIT_WINDOW_MS + 1;
    const res = mockRes();
    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(101); // allowed after reset
    expect(res._status).toBeNull();
  });

  test("tracks different IPs independently", () => {
    const store = new Map();
    let now = 1000;
    const middleware = makeIpRateLimit(store, () => now);
    const next = jest.fn();

    // Exhaust limit for IP A
    const reqA = makeReq("10.0.0.5");
    for (let i = 0; i < 101; i++) {
      middleware(reqA, mockRes(), next);
    }
    expect(next).toHaveBeenCalledTimes(100);

    // IP B should still have its full quota
    const reqB = makeReq("10.0.0.6");
    const res = mockRes();
    middleware(reqB, res, next);
    expect(next).toHaveBeenCalledTimes(101);
    expect(res._status).toBeNull();
  });

  test("uses the LAST X-Forwarded-For entry (set by ALB, not client-spoofable)", () => {
    const store = new Map();
    let now = 1000;
    const middleware = makeIpRateLimit(store, () => now);
    const next = jest.fn();

    // Client sends X-Forwarded-For: spoofed-ip; ALB appends real IP at end
    const req = makeReq("127.0.0.1", "203.0.113.42, 10.0.0.1");
    const res = mockRes();
    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    // Rate limiter must key on the LAST entry (ALB-appended real IP), not the first (spoofable)
    expect(store.has("10.0.0.1")).toBe(true);
    expect(store.has("203.0.113.42")).toBe(false);
    expect(store.has("127.0.0.1")).toBe(false);
  });

  test("spoofed X-Forwarded-For prefix cannot bypass rate limit (last entry is authoritative)", () => {
    const store = new Map();
    let now = 1000;
    const middleware = makeIpRateLimit(store, () => now);
    const next = jest.fn();

    // Exhaust limit for the real IP (last entry)
    const realIp = "198.51.100.7";
    for (let i = 0; i < 100; i++) {
      // Attacker rotates the first entry but the last (real) IP stays the same
      const req = makeReq("127.0.0.1", `fake-ip-${i}, ${realIp}`);
      middleware(req, mockRes(), next);
    }
    expect(next).toHaveBeenCalledTimes(100);

    // 101st request — different spoofed prefix, same real IP — must be rejected
    const req101 = makeReq("127.0.0.1", `another-fake-ip, ${realIp}`);
    const res = mockRes();
    middleware(req101, res, next);

    expect(res._status).toBe(429);
    expect(next).toHaveBeenCalledTimes(100);
  });

  test("sets Retry-After header on 429 response", () => {
    const store = new Map();
    let now = 1000;
    const middleware = makeIpRateLimit(store, () => now);
    const req = makeReq("10.0.0.7");
    const next = jest.fn();

    for (let i = 0; i < 101; i++) {
      middleware(req, mockRes(), next);
    }

    const res = mockRes();
    middleware(req, res, next);

    expect(res._status).toBe(429);
    expect(res._headers["Retry-After"]).toBeDefined();
    const retryAfter = parseInt(res._headers["Retry-After"], 10);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(60);
  });
});
