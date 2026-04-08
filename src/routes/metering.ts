import { Router } from "express";
import { meterAllCustomers } from "../services/metering";
import { getEntitlements } from "../services/entitlements";
import { getCustomer } from "../services/customer-store";
import { internalSecretAuth } from "../middleware/auth";

const router = Router();

/**
 * POST /metering/report — Trigger hourly metering for all active customers.
 *
 * In production, call this from a scheduler (CloudWatch Events / EventBridge rule)
 * every hour. The handler fetches each customer's Davoxi usage and reports it
 * to AWS Marketplace Metering Service.
 */
router.post("/report", internalSecretAuth, async (_req, res) => {
  try {
    const results = await meterAllCustomers(async (davoxiApiKey) => {
      // Fetch usage from Davoxi API
      const usageRes = await fetch(
        `${process.env.DAVOXI_API_URL || "https://api.davoxi.com"}/usage/summary`,
        {
          headers: { Authorization: `Bearer ${davoxiApiKey}`, Accept: "application/json" },
        },
      );

      if (!usageRes.ok) {
        throw new Error(`Davoxi usage fetch failed: ${usageRes.status}`);
      }

      const usage = (await usageRes.json()) as {
        total_calls: number;
        total_minutes: number;
      };

      const businessesRes = await fetch(
        `${process.env.DAVOXI_API_URL || "https://api.davoxi.com"}/businesses`,
        {
          headers: { Authorization: `Bearer ${davoxiApiKey}`, Accept: "application/json" },
        },
      );

      let activeBusinesses = 0;
      let activeAgents = 0;

      if (businessesRes.ok) {
        const businesses = (await businessesRes.json()) as Array<{ business_id: string }>;
        activeBusinesses = businesses.length;

        // Count total agents across all businesses
        for (const biz of businesses) {
          const agentsRes = await fetch(
            `${process.env.DAVOXI_API_URL || "https://api.davoxi.com"}/businesses/${biz.business_id}/agents`,
            {
              headers: { Authorization: `Bearer ${davoxiApiKey}`, Accept: "application/json" },
            },
          );
          if (agentsRes.ok) {
            const agents = (await agentsRes.json()) as Array<{ enabled: boolean }>;
            activeAgents += agents.filter((a) => a.enabled).length;
          }
        }
      }

      return {
        callMinutes: usage.total_minutes,
        activeAgents,
        activeBusinesses,
      };
    });

    res.json({ success: true, results });
  } catch (err) {
    console.error("Metering report error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /metering/entitlements/:customerId — Check customer entitlements (contract model).
 */
router.get("/entitlements/:customerId", internalSecretAuth, async (req, res) => {
  const { customerId } = req.params;

  const customer = getCustomer(customerId);
  if (!customer) {
    res.status(404).json({ error: "Customer not found" });
    return;
  }

  try {
    const entitlements = await getEntitlements(customerId);
    res.json({ customerId, entitlements });
  } catch (err) {
    console.error("Entitlements fetch error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
