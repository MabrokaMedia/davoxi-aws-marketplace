import { Request, Response, NextFunction } from "express";

/**
 * Middleware: require a valid x-internal-secret header.
 * Used to protect internal endpoints like /metering/report and /metering/entitlements.
 */
export function internalSecretAuth(req: Request, res: Response, next: NextFunction): void {
  const secret = process.env.INTERNAL_METERING_SECRET;
  const provided = req.headers["x-internal-secret"];

  if (!secret || !provided || provided !== secret) {
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
  const provided = req.headers["x-admin-secret"];

  if (!secret || !provided || provided !== secret) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  next();
}
