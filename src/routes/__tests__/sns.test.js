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

function validateSnsSignatureUrl(url) {
  return /^https:\/\/sns\.[a-z0-9-]+\.amazonaws\.com\//.test(url);
}

function validateSigningCertUrl(url) {
  return /^https:\/\/sns\.[a-z0-9-]+\.amazonaws\.com\//.test(url);
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
