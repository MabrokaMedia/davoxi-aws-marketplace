import { Request, Response, NextFunction } from "express";
import crypto from "crypto";

/**
 * Constant-time comparison of two strings to prevent timing-based side-channel attacks.
 */
function safeCompare(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  // Buffers must be same length for timingSafeEqual; short-circuit length mismatch
  // without revealing which is longer via timing.
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

/**
 * Middleware: require a valid x-internal-secret header.
 * Used to protect internal endpoints like /metering/report and /metering/entitlements.
 */
export function internalSecretAuth(req: Request, res: Response, next: NextFunction): void {
  const secret = process.env.INTERNAL_METERING_SECRET;
  const raw = req.headers["x-internal-secret"];
  const provided = Array.isArray(raw) ? raw[0] : raw;

  if (!secret || !provided || !safeCompare(provided, secret)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  next();
}

/**
 * Middleware: require a valid x-admin-secret header.
 * Used to protect admin endpoints like /settings/api-key.
 */
export function adminSecretAuth(req: Request, res: Response, next: NextFunction): void {
  const secret = process.env.ADMIN_SECRET;
  const raw = req.headers["x-admin-secret"];
  const provided = Array.isArray(raw) ? raw[0] : raw;

  if (!secret || !provided || !safeCompare(provided, secret)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  next();
}
