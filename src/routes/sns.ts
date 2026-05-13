import { Router } from "express";
import crypto from "crypto";
import { deactivateCustomer, getCustomer } from "../services/customer-store";

const router = Router();

const SNS_HOSTNAME_RE = /^sns\.[a-z0-9-]+\.amazonaws\.com$/;
const SIGNING_CERT_FETCH_TIMEOUT_MS = 5000;
const SIGNING_CERT_MAX_BYTES = 64 * 1024;
// AWS guidance: SNS signing timestamps are considered fresh for one hour.
const SNS_TIMESTAMP_MAX_SKEW_MS = 60 * 60 * 1000;

/**
 * Parse a URL string and assert it is a strict https://sns.<region>.amazonaws.com URL.
 * Rejects userinfo (`https://sns.us-east-1.amazonaws.com@evil.com/`), wrong protocol,
 * and hostnames that merely contain "amazonaws.com" as a substring.
 */
function isStrictSnsUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  if (parsed.username !== "" || parsed.password !== "") return false;
  return SNS_HOSTNAME_RE.test(parsed.hostname);
}

/**
 * Validate that a URL hostname belongs to amazonaws.com.
 * Used for both SubscribeURL (SSRF guard) and SigningCertURL (cert pinning).
 */
export function validateSnsSignatureUrl(url: string): boolean {
  return isStrictSnsUrl(url);
}

/**
 * Validate that a SigningCertURL is from a legitimate AWS SNS host.
 * SNS certs are served from sns.*.amazonaws.com (same pattern as topic ARNs).
 */
export function validateSigningCertUrl(url: string): boolean {
  return isStrictSnsUrl(url);
}

/**
 * Validate the SNS Timestamp is recent. Rejects missing/unparseable/stale (>1h)
 * timestamps and timestamps too far in the future (>5 min clock skew).
 */
export function isSnsTimestampFresh(timestamp: string | undefined, nowMs: number = Date.now()): boolean {
  if (!timestamp) return false;
  const t = Date.parse(timestamp);
  if (Number.isNaN(t)) return false;
  const delta = nowMs - t;
  if (delta > SNS_TIMESTAMP_MAX_SKEW_MS) return false;
  if (delta < -5 * 60 * 1000) return false;
  return true;
}

/**
 * Validate the SNS TopicArn against an allow-list. Requires EXPECTED_SNS_TOPIC_ARN
 * env var to be set in production. Without the pin, any signed SNS message from
 * any account could trigger our handlers (cross-tenant DoS).
 */
export function isExpectedTopicArn(topicArn: string | undefined): boolean {
  const expected = process.env.EXPECTED_SNS_TOPIC_ARN;
  if (!expected) {
    // Fail-closed in production. In other stages, allow but warn — surfaces
    // misconfiguration loudly without blocking local/dev SubscriptionConfirmation flows.
    if (process.env.NODE_ENV === "production") return false;
    if (!topicArn) return false;
    console.warn("EXPECTED_SNS_TOPIC_ARN is not set; allowing TopicArn in non-production:", topicArn);
    return true;
  }
  if (!topicArn) return false;
  return topicArn === expected;
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
 *
 * Hardened: rejects redirects (manual mode treats 3xx as failure), enforces a
 * 5s timeout, and caps the response body at 64KB. This prevents redirect-based
 * SSRF and resource exhaustion via a hostile (or hijacked) signing-cert host.
 */
async function fetchSigningCert(certUrl: string): Promise<string> {
  if (!validateSigningCertUrl(certUrl)) {
    throw new Error("SigningCertURL is not from a trusted amazonaws.com host");
  }
  const response = await fetch(certUrl, {
    redirect: "manual",
    signal: AbortSignal.timeout(SIGNING_CERT_FETCH_TIMEOUT_MS),
  });
  if (response.status >= 300 && response.status < 400) {
    throw new Error(`Refusing redirect on signing cert URL: HTTP ${response.status}`);
  }
  if (!response.ok) {
    throw new Error(`Failed to fetch signing cert: HTTP ${response.status}`);
  }
  const text = await response.text();
  if (text.length > SIGNING_CERT_MAX_BYTES) {
    throw new Error(`Signing cert response exceeds ${SIGNING_CERT_MAX_BYTES} bytes`);
  }
  return text;
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

  // Pin to the expected Marketplace topic — without this any AWS account
  // holding any SNS topic could publish signed messages that drive our handlers.
  if (!isExpectedTopicArn(snsMessage.TopicArn)) {
    res.status(403).json({ error: "Unexpected TopicArn" });
    return;
  }

  // Reject stale or future-dated messages. Replays of legitimately-signed
  // events would otherwise re-deactivate customers indefinitely.
  if (!isSnsTimestampFresh(snsMessage.Timestamp)) {
    res.status(403).json({ error: "Stale or missing Timestamp" });
    return;
  }

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
      await fetch(snsMessage.SubscribeURL, {
        redirect: "manual",
        signal: AbortSignal.timeout(SIGNING_CERT_FETCH_TIMEOUT_MS),
      });
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
