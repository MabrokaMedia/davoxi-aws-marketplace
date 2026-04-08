import { Router } from "express";
import { deactivateCustomer, getCustomer } from "../services/customer-store";

const router = Router();

/**
 * Validate that the SNS SubscribeURL hostname is a legitimate amazonaws.com endpoint.
 * Prevents SSRF by rejecting non-AWS URLs.
 *
 * TODO: For full security, add cryptographic SNS message signature verification
 * using the sns-validator npm package once it is available in this project.
 */
export function validateSnsSignatureUrl(url: string): boolean {
  return /^https:\/\/sns\.[a-z0-9-]+\.amazonaws\.com\//.test(url);
}

interface SNSMessage {
  Type: string;
  TopicArn?: string;
  Message?: string;
  SubscribeURL?: string;
}

interface MarketplaceNotification {
  action: string;
  "customer-identifier": string;
  "product-code": string;
}

/**
 * POST /sns — Handle AWS Marketplace SNS notifications.
 *
 * AWS Marketplace sends SNS notifications for subscription lifecycle events:
 *   - subscribe-success: Customer subscription confirmed
 *   - unsubscribe-pending: Customer initiated cancellation
 *   - subscribe-fail: Subscription failed
 */
router.post("/", async (req, res) => {
  const snsMessage = req.body as SNSMessage;

  // Handle SNS subscription confirmation
  if (snsMessage.Type === "SubscriptionConfirmation" && snsMessage.SubscribeURL) {
    if (!validateSnsSignatureUrl(snsMessage.SubscribeURL)) {
      res.status(403).json({ error: "Invalid SubscribeURL" });
      return;
    }
    try {
      await fetch(snsMessage.SubscribeURL);
      console.log("SNS subscription confirmed");
    } catch (err) {
      console.error("Failed to confirm SNS subscription:", err);
    }
    res.status(200).send();
    return;
  }

  // Handle notification
  if (snsMessage.Type === "Notification" && snsMessage.Message) {
    let notification: MarketplaceNotification;
    try {
      notification = JSON.parse(snsMessage.Message) as MarketplaceNotification;
    } catch {
      res.status(400).json({ error: "Invalid notification payload" });
      return;
    }

    const customerId = notification["customer-identifier"];

    switch (notification.action) {
      case "subscribe-success":
        console.log(`Subscription confirmed for customer ${customerId}`);
        break;

      case "unsubscribe-pending": {
        console.log(`Unsubscribe pending for customer ${customerId}`);
        // Deactivate customer — they have up to 1 hour to finalize usage
        const customer = getCustomer(customerId);
        if (customer) {
          deactivateCustomer(customerId);
          console.log(`Customer ${customerId} deactivated`);
        }
        break;
      }

      case "subscribe-fail":
        console.log(`Subscription failed for customer ${customerId}`);
        deactivateCustomer(customerId);
        break;

      default:
        console.log(`Unknown marketplace action: ${notification.action}`);
    }
  }

  res.status(200).send();
});

export default router;
