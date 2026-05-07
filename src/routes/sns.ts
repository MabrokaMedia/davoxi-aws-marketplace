import { Router } from "express";
import crypto from "crypto";
import { deactivateCustomer, getCustomer } from "../services/customer-store";

const router = Router();

/**
 * Validate that a URL hostname belongs to amazonaws.com.
 * Used for both SubscribeURL (SSRF guard) and SigningCertURL (cert pinning).
 */
export function validateSnsSignatureUrl(url: string): boolean {
  return /^https:\/\/sns\.[a-z0-9-]+\.amazonaws\.com\//.test(url);
}

/**
 * Validate that a SigningCertURL is from a legitimate AWS SNS host.
 * SNS certs are served from sns.*.amazonaws.com (same pattern as topic ARNs).
 */
export function validateSigningCertUrl(url: string): boolean {
  return /^https:\/\/sns\.[a-z0-9-]+\.amazonaws\.com\//.test(url);
}

interface SNSMessage {
  Type: string;
  TopicArn?: string;
  Message?: string;
  MessageId?: string;
  Timestamp?: string;
  Subject?: string;
  SubscribeURL?: string;
  Token?: string;
  Signature?: string;
  SignatureVersion?: string;
  SigningCertURL?: string;
}

interface MarketplaceNotification {
  action: string;
  "customer-identifier": string;
  "product-code": string;
}

/**
 * Download a PEM certificate from a validated AWS SNS URL.
 * Throws if the URL fails validation or the fetch fails.
 */
async function fetchSigningCert(certUrl: string): Promise<string> {
  if (!validateSigningCertUrl(certUrl)) {
    throw new Error("SigningCertURL is not from a trusted amazonaws.com host");
  }
  const response = await fetch(certUrl);
  if (!response.ok) {
    throw new Error(`Failed to fetch signing cert: HTTP ${response.status}`);
  }
  return response.text();
}

/**
 * Build the canonical string-to-sign for a Notification message.
 * Keys are sorted alphabetically; each pair is appended as "KeyName\nValue\n".
 *
 * For Notification: Message, MessageId, Subject (if present), Timestamp, TopicArn, Type
 * For SubscriptionConfirmation / UnsubscribeConfirmation: Message, MessageId, SubscribeURL, Timestamp, Token, TopicArn, Type
 */
function buildStringToSign(message: SNSMessage): string {
  let keys: string[];
  if (message.Type === "Notification") {
    keys = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"];
  } else {
    // SubscriptionConfirmation and UnsubscribeConfirmation
    keys = ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"];
  }

  let str = "";
  for (const key of keys) {
    const value = (message as unknown as Record<string, string | undefined>)[key];
    if (value !== undefined && value !== null) {
      str += `${key}\n${value}\n`;
    }
  }
  return str;
}

/**
 * Verify the SHA1withRSA signature of an SNS message.
 * Returns true if the signature is valid, false otherwise.
 *
 * Algorithm:
 * 1. Validate SigningCertURL is from amazonaws.com
 * 2. Download the PEM cert
 * 3. Build the canonical string-to-sign based on message type
 * 4. Verify message.Signature (base64) against the cert using SHA1withRSA
 */
export async function verifySnsSignature(message: SNSMessage): Promise<boolean> {
  if (!message.Signature || !message.SigningCertURL) {
    return false;
  }

  // AWS SNS uses Version 1 (SHA1withRSA) historically; Version 2 (SHA256withRSA) was
  // added in 2022 and is the recommended default. Accept both.
  let algorithm: string;
  if (message.SignatureVersion === "1") {
    algorithm = "SHA1";
  } else if (message.SignatureVersion === "2") {
    algorithm = "SHA256";
  } else {
    return false;
  }

  let pem: string;
  try {
    pem = await fetchSigningCert(message.SigningCertURL);
  } catch {
    return false;
  }

  const stringToSign = buildStringToSign(message);

  try {
    const verifier = crypto.createVerify(algorithm);
    verifier.update(stringToSign, "utf8");
    return verifier.verify(pem, message.Signature, "base64");
  } catch {
    return false;
  }
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

  // Verify cryptographic signature before acting on any message
  const signatureValid = await verifySnsSignature(snsMessage);
  if (!signatureValid) {
    res.status(403).json({ error: "Invalid SNS signature" });
    return;
  }

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
