"use strict";

/**
 * Security regression test: pins transitive dependency versions known
 * to have had high-severity advisories patched in a specific release.
 *
 * If npm later resolves an older (vulnerable) version into the lockfile,
 * these tests fail. That keeps the audit-fix from silently regressing on
 * a future `npm install` without a lockfile.
 *
 * Add a new entry here every time a future audit-fix patches a transitive.
 */

const fs = require("fs");
const path = require("path");

function readLockfile() {
  const lockPath = path.join(__dirname, "..", "..", "..", "package-lock.json");
  return JSON.parse(fs.readFileSync(lockPath, "utf8"));
}

function findPackageVersion(lock, name) {
  const pkgs = lock.packages || {};
  const versions = [];
  for (const [key, val] of Object.entries(pkgs)) {
    if (key === `node_modules/${name}` || key.endsWith(`/node_modules/${name}`)) {
      if (val && val.version) versions.push(val.version);
    }
  }
  return versions;
}

function compareSemver(a, b) {
  const pa = a.split(".").map((n) => parseInt(n, 10));
  const pb = b.split(".").map((n) => parseInt(n, 10));
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

describe("transitive dependency security pins", () => {
  let lock;
  beforeAll(() => {
    lock = readLockfile();
  });

  // GHSA-5wm8-gmm8-39j9 + GHSA-45c6-75p6-83cc — fixed in 1.1.7+
  it("fast-xml-builder is at or above the patched 1.1.7 threshold", () => {
    const versions = findPackageVersion(lock, "fast-xml-builder");
    expect(versions.length).toBeGreaterThan(0);
    for (const v of versions) {
      expect(compareSemver(v, "1.1.7")).toBeGreaterThanOrEqual(0);
    }
  });
});
