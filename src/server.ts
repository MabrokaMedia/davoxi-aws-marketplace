import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import { config } from "./config";
import registrationRoutes from "./routes/registration";
import settingsRoutes from "./routes/settings";
import meteringRoutes from "./routes/metering";
import snsRoutes from "./routes/sns";

const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : false }));
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' })); // For marketplace registration token

// ---------------------------------------------------------------------------
// In-memory IP rate limiter: 100 requests per minute per IP
// ---------------------------------------------------------------------------

interface RateLimitEntry {
  count: number;
  reset: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();
const RATE_LIMIT_MAX = 100;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_GC_INTERVAL_MS = 5 * 60_000;
const RATE_LIMIT_MAX_ENTRIES = 100_000;

/**
 * Sweep expired entries so the store doesn't grow unbounded across the process lifetime.
 * Exported for unit-testing purposes.
 */
export function gcRateLimitStore(now: number = Date.now()): number {
  let removed = 0;
  for (const [ip, entry] of rateLimitStore) {
    if (now >= entry.reset) {
      rateLimitStore.delete(ip);
      removed += 1;
    }
  }
  // Hard cap as a safety valve in case the IP space genuinely exceeds the cap inside one window.
  if (rateLimitStore.size > RATE_LIMIT_MAX_ENTRIES) {
    const overflow = rateLimitStore.size - RATE_LIMIT_MAX_ENTRIES;
    let i = 0;
    for (const ip of rateLimitStore.keys()) {
      if (i >= overflow) break;
      rateLimitStore.delete(ip);
      removed += 1;
      i += 1;
    }
  }
  return removed;
}

const rateLimitGc = setInterval(() => {
  gcRateLimitStore();
}, RATE_LIMIT_GC_INTERVAL_MS);
rateLimitGc.unref?.();

export function ipRateLimit(req: Request, res: Response, next: NextFunction): void {
  // Use the rightmost (last) X-Forwarded-For entry: AWS ALB appends the real client IP there.
  // The first entry is client-controlled and can be spoofed to bypass rate limiting.
  const ip = (req.headers["x-forwarded-for"] as string | undefined)?.split(",").at(-1)?.trim() ?? req.socket.remoteAddress ?? "unknown";
  const now = Date.now();

  let entry = rateLimitStore.get(ip);
  if (!entry || now >= entry.reset) {
    entry = { count: 1, reset: now + RATE_LIMIT_WINDOW_MS };
    rateLimitStore.set(ip, entry);
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
}

app.use(ipRateLimit);

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "davoxi-aws-marketplace" });
});

// Routes
app.use("/register", registrationRoutes);
app.use("/settings", settingsRoutes);
app.use("/metering", meteringRoutes);
app.use("/sns", snsRoutes);

if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`Davoxi AWS Marketplace integration running on port ${config.port}`);
  });
}

export default app;
