import { Router } from "express";
import { getCustomer, setDavoxiApiKey } from "../services/customer-store";
import { adminSecretAuth } from "../middleware/auth";

const router = Router();

/**
 * POST /settings/api-key — Link a Davoxi API key to an AWS Marketplace customer.
 */
router.post("/api-key", adminSecretAuth, async (req, res) => {
  const { customerId, apiKey } = req.body as { customerId?: string; apiKey?: string };

  if (!customerId || !apiKey) {
    res.status(400).json({ error: "customerId and apiKey are required" });
    return;
  }

  const customer = getCustomer(customerId);
  if (!customer) {
    res.status(404).json({ error: "Customer not found. Complete registration first." });
    return;
  }

  // Validate the API key against Davoxi
  try {
    const davoxiRes = await fetch(`${process.env.DAVOXI_API_URL || "https://api.davoxi.com"}/users/me`, {
      headers: { Authorization: `Bearer ${apiKey}`, Accept: "application/json" },
    });
    if (!davoxiRes.ok) {
      res.status(401).json({ error: "Invalid Davoxi API key" });
      return;
    }
  } catch {
    res.status(502).json({ error: "Could not validate API key against Davoxi" });
    return;
  }

  setDavoxiApiKey(customerId, apiKey);
  res.json({ success: true, message: "Davoxi API key linked to your AWS Marketplace subscription" });
});

export default router;
