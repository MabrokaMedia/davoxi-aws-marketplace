"use strict";

/**
 * Unit tests for gcRateLimitStore — the periodic sweep that prevents the
 * in-memory rate-limit store from growing unbounded across the process lifetime.
 *
 * Mirrors the implementation in src/server.ts so the test runs without a build step.
 */

const RATE_LIMIT_MAX_ENTRIES = 100_000;

function makeGc(store) {
  return function gcRateLimitStore(now) {
    let removed = 0;
    for (const [ip, entry] of store) {
      if (now >= entry.reset) {
        store.delete(ip);
        removed += 1;
      }
    }
    if (store.size > RATE_LIMIT_MAX_ENTRIES) {
      const overflow = store.size - RATE_LIMIT_MAX_ENTRIES;
      let i = 0;
      for (const ip of store.keys()) {
        if (i >= overflow) break;
        store.delete(ip);
        removed += 1;
        i += 1;
      }
    }
    return removed;
  };
}

describe("gcRateLimitStore", () => {
  test("removes only entries whose reset time is in the past", () => {
    const store = new Map([
      ["1.1.1.1", { count: 5, reset: 100 }],
      ["2.2.2.2", { count: 3, reset: 1_000_000 }],
      ["3.3.3.3", { count: 10, reset: 200 }],
    ]);
    const removed = makeGc(store)(500);

    expect(removed).toBe(2);
    expect(store.has("1.1.1.1")).toBe(false);
    expect(store.has("3.3.3.3")).toBe(false);
    expect(store.has("2.2.2.2")).toBe(true);
  });

  test("returns 0 when nothing has expired", () => {
    const store = new Map([
      ["1.1.1.1", { count: 1, reset: 5_000_000 }],
      ["2.2.2.2", { count: 1, reset: 5_000_000 }],
    ]);
    expect(makeGc(store)(1)).toBe(0);
    expect(store.size).toBe(2);
  });

  test("clears all entries when all are expired", () => {
    const store = new Map();
    for (let i = 0; i < 50; i++) {
      store.set(`10.0.0.${i}`, { count: 1, reset: 100 });
    }
    expect(makeGc(store)(1_000)).toBe(50);
    expect(store.size).toBe(0);
  });

  test("hard-caps the store at MAX_ENTRIES even if nothing has expired", () => {
    const store = new Map();
    const N = RATE_LIMIT_MAX_ENTRIES + 25;
    for (let i = 0; i < N; i++) {
      // All in the future — none would be expired by time-based pass
      store.set(`fresh-${i}`, { count: 1, reset: 9_999_999 });
    }
    const removed = makeGc(store)(0);
    expect(removed).toBeGreaterThanOrEqual(25);
    expect(store.size).toBeLessThanOrEqual(RATE_LIMIT_MAX_ENTRIES);
  });

  test("is idempotent", () => {
    const store = new Map([
      ["1.1.1.1", { count: 1, reset: 100 }],
      ["2.2.2.2", { count: 1, reset: 5_000_000 }],
    ]);
    const gc = makeGc(store);
    gc(500);
    const second = gc(500);
    expect(second).toBe(0);
    expect(store.size).toBe(1);
  });
});
