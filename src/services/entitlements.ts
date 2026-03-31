import {
  MarketplaceEntitlementServiceClient,
  GetEntitlementsCommand,
} from "@aws-sdk/client-marketplace-entitlement-service";
import { config } from "../config";

const client = new MarketplaceEntitlementServiceClient({ region: "us-east-1" });

/**
 * Check what a customer is entitled to (for SaaS Contract model).
 */
export async function getEntitlements(customerId: string) {
  const command = new GetEntitlementsCommand({
    ProductCode: config.aws.productCode,
    Filter: {
      CUSTOMER_IDENTIFIER: [customerId],
    },
  });

  const result = await client.send(command);

  return (result.Entitlements ?? []).map((e) => ({
    dimension: e.Dimension,
    value: e.Value,
    expirationDate: e.ExpirationDate,
    customerIdentifier: e.CustomerIdentifier,
    productCode: e.ProductCode,
  }));
}
