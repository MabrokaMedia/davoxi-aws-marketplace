import {
  MarketplaceMeteringClient,
  BatchMeterUsageCommand,
  ResolveCustomerCommand,
} from "@aws-sdk/client-marketplace-metering";
import { config } from "../config";
import { getAllActiveCustomers } from "./customer-store";

const client = new MarketplaceMeteringClient({ region: config.aws.region });

/**
 * Resolve a registration token to get customer details.
 * Called when a new customer completes their AWS Marketplace subscription.
 */
export async function resolveCustomer(registrationToken: string) {
  const command = new ResolveCustomerCommand({
    RegistrationToken: registrationToken,
  });

  const result = await client.send(command);
  return {
    customerId: result.CustomerIdentifier!,
    awsAccountId: result.CustomerAWSAccountId!,
    productCode: result.ProductCode!,
  };
}

/**
 * Report usage for a single customer.
 */
export async function meterUsage(
  customerId: string,
  dimension: string,
  quantity: number,
  timestamp?: Date,
) {
  const command = new BatchMeterUsageCommand({
    ProductCode: config.aws.productCode,
    UsageRecords: [
      {
        CustomerIdentifier: customerId,
        Dimension: dimension,
        Quantity: quantity,
        Timestamp: timestamp ?? new Date(),
      },
    ],
  });

  return client.send(command);
}

/**
 * Report usage for all active customers.
 * Should be called hourly by a scheduler (e.g., cron, EventBridge).
 *
 * In production, this would query the Davoxi API for each customer's
 * actual usage in the last hour.
 */
export async function meterAllCustomers(
  getUsageForCustomer: (davoxiApiKey: string) => Promise<{
    callMinutes: number;
    activeAgents: number;
    activeBusinesses: number;
  }>,
) {
  const activeCustomers = getAllActiveCustomers();
  const results: Array<{ customerId: string; success: boolean; error?: string }> = [];

  for (const customer of activeCustomers) {
    if (!customer.davoxiApiKey) {
      results.push({ customerId: customer.customerId, success: false, error: "No API key" });
      continue;
    }

    try {
      const usage = await getUsageForCustomer(customer.davoxiApiKey);
      const now = new Date();

      const usageRecords = [];

      if (usage.callMinutes > 0) {
        usageRecords.push({
          CustomerIdentifier: customer.customerId,
          Dimension: config.dimensions.aiCallMinutes,
          Quantity: Math.ceil(usage.callMinutes),
          Timestamp: now,
        });
      }

      if (usage.activeAgents > 0) {
        usageRecords.push({
          CustomerIdentifier: customer.customerId,
          Dimension: config.dimensions.activeAgents,
          Quantity: usage.activeAgents,
          Timestamp: now,
        });
      }

      if (usage.activeBusinesses > 0) {
        usageRecords.push({
          CustomerIdentifier: customer.customerId,
          Dimension: config.dimensions.activeBusinesses,
          Quantity: usage.activeBusinesses,
          Timestamp: now,
        });
      }

      if (usageRecords.length > 0) {
        const command = new BatchMeterUsageCommand({
          ProductCode: config.aws.productCode,
          UsageRecords: usageRecords,
        });
        await client.send(command);
      }

      results.push({ customerId: customer.customerId, success: true });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      results.push({ customerId: customer.customerId, success: false, error: message });
      console.error(`Metering failed for ${customer.customerId}:`, message);
    }
  }

  return results;
}
