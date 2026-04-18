import { Router } from "express";
import { resolveCustomer } from "../services/metering";
import { saveCustomer } from "../services/customer-store";

const router = Router();

/**
 * POST /register — AWS Marketplace redirects customers here after subscription.
 *
 * The registration token is sent as a form-encoded POST body.
 * We resolve it to get the customer ID and AWS account, then onboard them.
 */
router.post("/", async (req, res) => {
  const registrationToken = req.body["x-amzn-marketplace-token"] as string | undefined;

  if (!registrationToken) {
    res.status(400).json({ error: "Missing marketplace registration token" });
    return;
  }

  try {
    const customer = await resolveCustomer(registrationToken);

    saveCustomer({
      customerId: customer.customerId,
      awsAccountId: customer.awsAccountId,
      productCode: customer.productCode,
      registeredAt: new Date().toISOString(),
      active: true,
    });

    // In production, redirect to your onboarding UI
    res.json({
      success: true,
      customerId: customer.customerId,
      message:
        "Welcome to Davoxi! Your AWS Marketplace subscription is active. " +
        "Configure your Davoxi API key at /settings to complete setup.",
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("Registration failed:", message);
    // Do not surface internal AWS SDK error details to the caller
    res.status(500).json({ error: "Registration failed" });
  }
});

export default router;
