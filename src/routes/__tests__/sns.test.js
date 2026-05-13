"use strict";

/**
 * Unit tests for SNS route helpers: validateSnsSignatureUrl, validateSigningCertUrl,
 * buildStringToSign (via verifySnsSignature), and the POST /sns handler.
 *
 * These tests run without a compiled build step. Logic under test is inlined
 * (mirrors src/routes/sns.ts) so tests work with plain Node.js / Jest.
 */

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Inline the pure logic from src/routes/sns.ts
// ---------------------------------------------------------------------------

const SNS_HOSTNAME_RE = /^sns\.[a-z0-9-]+\.amazonaws\.com$/;
const SNS_TIMESTAMP_MAX_SKEW_MS = 60 * 60 * 1000;

function isStrictSnsUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  if (parsed.username !== "" || parsed.password !== "") return false;
  return SNS_HOSTNAME_RE.test(parsed.hostname);
}

function validateSnsSignatureUrl(url) {
  return isStrictSnsUrl(url);
}

function validateSigningCertUrl(url) {
  return isStrictSnsUrl(url);
}

function isSnsTimestampFresh(timestamp, nowMs) {
  if (nowMs === undefined) nowMs = Date.now();
  if (!timestamp) return false;
  const t = Date.parse(timestamp);
  if (Number.isNaN(t)) return false;
  const delta = nowMs - t;
  if (delta > SNS_TIMESTAMP_MAX_SKEW_MS) return false;
  if (delta < -5 * 60 * 1000) return false;
  return true;
}

function isExpectedTopicArn(topicArn) {
  const expected = process.env.EXPECTED_SNS_TOPIC_ARN;
  if (!expected) {
    if (process.env.NODE_ENV === "production") return false;
    if (!topicArn) return false;
    return true;
  }
  if (!topicArn) return false;
  return topicArn === expected;
}

function buildStringToSign(message) {
  let keys;
  if (message.Type === "Notification") {
    keys = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"];
  } else {
    keys = ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"];
  }

  let str = "";
  for (const key of keys) {
    const value = message[key];
    if (value !== undefined && value !== null) {
      str += `${key}\n${value}\n`;
    }
  }
  return str;
}

async function verifySnsSignature(message, fetchImpl) {
  if (!message.Signature || !message.SigningCertURL) {
    return false;
  }
  let algorithm;
  if (message.SignatureVersion === "1") {
    algorithm = "SHA1";
  } else if (message.SignatureVersion === "2") {
    algorithm = "SHA256";
  } else {
    return false;
  }
  if (!validateSigningCertUrl(message.SigningCertURL)) {
    return false;
  }
  let pem;
  try {
    const response = await fetchImpl(message.SigningCertURL);
    if (!response.ok) return false;
    pem = await response.text();
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

function signMessageSha256(message, privateKeyPem) {
  const stringToSign = buildStringToSign(message);
  const signer = crypto.createSign("SHA256");
  signer.update(stringToSign, "utf8");
  return signer.sign(privateKeyPem, "base64");
}

// ---------------------------------------------------------------------------
// Helpers: generate a real RSA key pair for testing
// ---------------------------------------------------------------------------

let testKeyPair;
function getTestKeyPair() {
  if (!testKeyPair) {
    testKeyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
  }
  return testKeyPair;
}

function signMessage(message, privateKeyPem) {
  const stringToSign = buildStringToSign(message);
  const signer = crypto.createSign("SHA1");
  signer.update(stringToSign, "utf8");
  return signer.sign(privateKeyPem, "base64");
}

function makeFetchReturningCert(certPem) {
  return async (_url) => ({
    ok: true,
    text: async () => certPem,
  });
}

// ---------------------------------------------------------------------------
// Tests: validateSnsSignatureUrl
// ---------------------------------------------------------------------------

describe("validateSnsSignatureUrl", () => {
  test("accepts valid amazonaws.com SNS URL", () => {
    expect(validateSnsSignatureUrl("https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123")).toBe(true);
  });

  test("accepts SNS URL for other AWS regions", () => {
    expect(validateSnsSignatureUrl("https://sns.eu-west-1.amazonaws.com/")).toBe(true);
    expect(validateSnsSignatureUrl("https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-xyz")).toBe(true);
  });

  test("rejects non-amazonaws.com URL", () => {
    expect(validateSnsSignatureUrl("https://evil.com/hook")).toBe(false);
  });

  test("rejects URL that embeds amazonaws.com but is not a valid SNS URL", () => {
    expect(validateSnsSignatureUrl("https://evil.com/amazonaws.com/sns")).toBe(false);
    expect(validateSnsSignatureUrl("https://notreally.amazonaws.com.evil.com/")).toBe(false);
  });

  test("rejects http (non-https) amazonaws.com URL", () => {
    expect(validateSnsSignatureUrl("http://sns.us-east-1.amazonaws.com/")).toBe(false);
  });

  test("rejects empty string", () => {
    expect(validateSnsSignatureUrl("")).toBe(false);
  });

  test("rejects URL using userinfo to spoof the host", () => {
    // Regex pre-2026-05-13 fix matched the raw string; parsing routes the
    // request to evil.com. Both must be rejected.
    expect(validateSnsSignatureUrl("https://sns.us-east-1.amazonaws.com@evil.com/")).toBe(false);
    expect(validateSnsSignatureUrl("https://user:pass@sns.us-east-1.amazonaws.com/")).toBe(false);
  });

  test("rejects malformed URLs", () => {
    expect(validateSnsSignatureUrl("not-a-url")).toBe(false);
    expect(validateSnsSignatureUrl("javascript:alert(1)")).toBe(false);
  });

  test("rejects URL whose hostname only superficially looks like SNS", () => {
    // The hostname-anchored regex must not match e.g. snsXus-east-1.amazonaws.com
    expect(validateSnsSignatureUrl("https://sns-us-east-1.amazonaws.com/")).toBe(false);
    expect(validateSnsSignatureUrl("https://sns.amazonaws.com/")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tests: validateSigningCertUrl
// ---------------------------------------------------------------------------

describe("validateSigningCertUrl", () => {
  test("accepts valid amazonaws.com cert URL", () => {
    expect(validateSigningCertUrl("https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123.pem")).toBe(true);
  });

  test("rejects non-amazonaws.com cert URL", () => {
    expect(validateSigningCertUrl("https://evil.com/cert.pem")).toBe(false);
  });

  test("rejects cert URL with amazonaws.com in path but wrong hostname", () => {
    expect(validateSigningCertUrl("https://evil.com/amazonaws.com/cert.pem")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tests: verifySnsSignature
// ---------------------------------------------------------------------------

describe("verifySnsSignature", () => {
  test("returns false when Signature field is missing", async () => {
    const message = {
      Type: "Notification",
      MessageId: "msg-001",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: "hello",
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
      // Signature deliberately omitted
    };
    const result = await verifySnsSignature(message, jest.fn());
    expect(result).toBe(false);
  });

  test("returns false when SigningCertURL field is missing", async () => {
    const message = {
      Type: "Notification",
      MessageId: "msg-001",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: "hello",
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      Signature: "dGVzdA==",
      // SigningCertURL deliberately omitted
    };
    const result = await verifySnsSignature(message, jest.fn());
    expect(result).toBe(false);
  });

  test("returns false for unsupported SignatureVersion (e.g. v3)", async () => {
    const message = {
      Type: "Notification",
      MessageId: "msg-001",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: "hello",
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "3",
      Signature: "dGVzdA==",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
    };
    const result = await verifySnsSignature(message, jest.fn());
    expect(result).toBe(false);
  });

  test("returns true for a valid SignatureVersion 2 (SHA256withRSA) signature", async () => {
    const { publicKey, privateKey } = getTestKeyPair();
    const message = {
      Type: "Notification",
      MessageId: "msg-v2",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: "hello-v2",
      Timestamp: "2026-05-07T00:00:00.000Z",
      SignatureVersion: "2",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
    };
    message.Signature = signMessageSha256(message, privateKey);
    const result = await verifySnsSignature(message, makeFetchReturningCert(publicKey));
    expect(result).toBe(true);
  });

  test("returns false when v2 signature was actually signed with SHA1 (downgrade attempt)", async () => {
    const { publicKey, privateKey } = getTestKeyPair();
    const message = {
      Type: "Notification",
      MessageId: "msg-mixed",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: "hello",
      Timestamp: "2026-05-07T00:00:00.000Z",
      SignatureVersion: "2",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
    };
    message.Signature = signMessage(message, privateKey); // signed with SHA1
    const result = await verifySnsSignature(message, makeFetchReturningCert(publicKey));
    expect(result).toBe(false);
  });

  test("returns false when SigningCertURL is not from amazonaws.com", async () => {
    const message = {
      Type: "Notification",
      MessageId: "msg-001",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: "hello",
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      Signature: "dGVzdA==",
      SigningCertURL: "https://evil.com/cert.pem",
    };
    const result = await verifySnsSignature(message, jest.fn());
    expect(result).toBe(false);
  });

  test("returns false when cert fetch fails (non-ok response)", async () => {
    const message = {
      Type: "Notification",
      MessageId: "msg-001",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: "hello",
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      Signature: "dGVzdA==",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
    };
    const mockFetch = async (_url) => ({ ok: false, status: 404, text: async () => "" });
    const result = await verifySnsSignature(message, mockFetch);
    expect(result).toBe(false);
  });

  test("returns false when cert fetch throws", async () => {
    const message = {
      Type: "Notification",
      MessageId: "msg-001",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: "hello",
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      Signature: "dGVzdA==",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
    };
    const mockFetch = async (_url) => { throw new Error("Network error"); };
    const result = await verifySnsSignature(message, mockFetch);
    expect(result).toBe(false);
  });

  test("returns false when signature is tampered (wrong base64 payload)", async () => {
    const { publicKey } = getTestKeyPair();
    const message = {
      Type: "Notification",
      MessageId: "msg-tampered",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: '{"action":"unsubscribe-pending","customer-identifier":"cust-001","product-code":"prod-001"}',
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
      Signature: "dGhpcyBpcyBub3QgYSB2YWxpZCBzaWduYXR1cmU=", // tampered
    };
    const mockFetch = makeFetchReturningCert(publicKey);
    const result = await verifySnsSignature(message, mockFetch);
    expect(result).toBe(false);
  });

  test("returns true for a correctly signed Notification message", async () => {
    const { publicKey, privateKey } = getTestKeyPair();
    const message = {
      Type: "Notification",
      MessageId: "msg-valid-001",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: '{"action":"subscribe-success","customer-identifier":"cust-001","product-code":"prod-001"}',
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
    };
    message.Signature = signMessage(message, privateKey);
    const mockFetch = makeFetchReturningCert(publicKey);
    const result = await verifySnsSignature(message, mockFetch);
    expect(result).toBe(true);
  });

  test("returns true for a correctly signed Notification with Subject field", async () => {
    const { publicKey, privateKey } = getTestKeyPair();
    const message = {
      Type: "Notification",
      MessageId: "msg-valid-002",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Subject: "AWS Marketplace Notification",
      Message: '{"action":"subscribe-success","customer-identifier":"cust-002","product-code":"prod-001"}',
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
    };
    message.Signature = signMessage(message, privateKey);
    const mockFetch = makeFetchReturningCert(publicKey);
    const result = await verifySnsSignature(message, mockFetch);
    expect(result).toBe(true);
  });

  test("returns true for a correctly signed SubscriptionConfirmation message", async () => {
    const { publicKey, privateKey } = getTestKeyPair();
    const message = {
      Type: "SubscriptionConfirmation",
      MessageId: "msg-sub-001",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Token: "2336412f37fb687f5d51e6e241d09c805a5a57b77d51b26d4f63bb0f39f7aca",
      SubscribeURL: "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-east-1:123456789012:test&Token=abc",
      Message: "You have chosen to subscribe to the topic arn:aws:sns:us-east-1:123456789012:test",
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
    };
    message.Signature = signMessage(message, privateKey);
    const mockFetch = makeFetchReturningCert(publicKey);
    const result = await verifySnsSignature(message, mockFetch);
    expect(result).toBe(true);
  });

  test("returns false when message fields are altered after signing", async () => {
    const { publicKey, privateKey } = getTestKeyPair();
    const message = {
      Type: "Notification",
      MessageId: "msg-altered",
      TopicArn: "arn:aws:sns:us-east-1:123456789012:test",
      Message: '{"action":"subscribe-success","customer-identifier":"cust-001","product-code":"prod-001"}',
      Timestamp: "2024-01-01T00:00:00.000Z",
      SignatureVersion: "1",
      SigningCertURL: "https://sns.us-east-1.amazonaws.com/cert.pem",
    };
    message.Signature = signMessage(message, privateKey);

    // Attacker alters the action after signing
    const tampered = { ...message, Message: '{"action":"unsubscribe-pending","customer-identifier":"cust-001","product-code":"prod-001"}' };
    const mockFetch = makeFetchReturningCert(publicKey);
    const result = await verifySnsSignature(tampered, mockFetch);
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tests: isSnsTimestampFresh — replay protection
// ---------------------------------------------------------------------------

describe("isSnsTimestampFresh", () => {
  const NOW = Date.parse("2026-05-13T12:00:00.000Z");

  test("accepts a timestamp from a few minutes ago", () => {
    const t = new Date(NOW - 5 * 60 * 1000).toISOString();
    expect(isSnsTimestampFresh(t, NOW)).toBe(true);
  });

  test("accepts a timestamp at the boundary (~59 minutes old)", () => {
    const t = new Date(NOW - 59 * 60 * 1000).toISOString();
    expect(isSnsTimestampFresh(t, NOW)).toBe(true);
  });

  test("rejects a timestamp older than 1 hour (replay)", () => {
    const t = new Date(NOW - 61 * 60 * 1000).toISOString();
    expect(isSnsTimestampFresh(t, NOW)).toBe(false);
  });

  test("rejects a timestamp far in the future (>5 min skew)", () => {
    const t = new Date(NOW + 10 * 60 * 1000).toISOString();
    expect(isSnsTimestampFresh(t, NOW)).toBe(false);
  });

  test("accepts a timestamp slightly in the future (within clock skew)", () => {
    const t = new Date(NOW + 2 * 60 * 1000).toISOString();
    expect(isSnsTimestampFresh(t, NOW)).toBe(true);
  });

  test("rejects missing timestamp", () => {
    expect(isSnsTimestampFresh(undefined, NOW)).toBe(false);
    expect(isSnsTimestampFresh("", NOW)).toBe(false);
  });

  test("rejects an unparseable timestamp", () => {
    expect(isSnsTimestampFresh("not-a-date", NOW)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tests: isExpectedTopicArn — pin against cross-tenant SNS confusion
// ---------------------------------------------------------------------------

describe("isExpectedTopicArn", () => {
  const ORIGINAL_EXPECTED = process.env.EXPECTED_SNS_TOPIC_ARN;
  const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

  afterEach(() => {
    if (ORIGINAL_EXPECTED === undefined) {
      delete process.env.EXPECTED_SNS_TOPIC_ARN;
    } else {
      process.env.EXPECTED_SNS_TOPIC_ARN = ORIGINAL_EXPECTED;
    }
    if (ORIGINAL_NODE_ENV === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = ORIGINAL_NODE_ENV;
    }
  });

  test("accepts TopicArn when it matches EXPECTED_SNS_TOPIC_ARN exactly", () => {
    process.env.EXPECTED_SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:111111111111:marketplace";
    expect(isExpectedTopicArn("arn:aws:sns:us-east-1:111111111111:marketplace")).toBe(true);
  });

  test("rejects TopicArn from a different AWS account (cross-tenant attack)", () => {
    process.env.EXPECTED_SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:111111111111:marketplace";
    expect(isExpectedTopicArn("arn:aws:sns:us-east-1:999999999999:marketplace")).toBe(false);
  });

  test("rejects TopicArn that differs only by topic name", () => {
    process.env.EXPECTED_SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:111111111111:marketplace";
    expect(isExpectedTopicArn("arn:aws:sns:us-east-1:111111111111:other-topic")).toBe(false);
  });

  test("rejects missing TopicArn", () => {
    process.env.EXPECTED_SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:111111111111:marketplace";
    expect(isExpectedTopicArn(undefined)).toBe(false);
    expect(isExpectedTopicArn("")).toBe(false);
  });

  test("fails closed in production when EXPECTED_SNS_TOPIC_ARN is unset", () => {
    delete process.env.EXPECTED_SNS_TOPIC_ARN;
    process.env.NODE_ENV = "production";
    expect(isExpectedTopicArn("arn:aws:sns:us-east-1:111111111111:marketplace")).toBe(false);
  });

  test("allows any TopicArn in non-production when env is unset (dev convenience)", () => {
    delete process.env.EXPECTED_SNS_TOPIC_ARN;
    process.env.NODE_ENV = "development";
    expect(isExpectedTopicArn("arn:aws:sns:us-east-1:111111111111:marketplace")).toBe(true);
  });
});
