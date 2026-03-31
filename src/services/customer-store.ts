/**
 * In-memory customer store. Replace with DynamoDB in production.
 */

export interface CustomerRecord {
  customerId: string;
  awsAccountId: string;
  productCode: string;
  davoxiApiKey?: string;
  registeredAt: string;
  active: boolean;
}

const customers = new Map<string, CustomerRecord>();

export function saveCustomer(record: CustomerRecord): void {
  customers.set(record.customerId, record);
}

export function getCustomer(customerId: string): CustomerRecord | undefined {
  return customers.get(customerId);
}

export function getCustomerByAwsAccount(awsAccountId: string): CustomerRecord | undefined {
  for (const record of customers.values()) {
    if (record.awsAccountId === awsAccountId) return record;
  }
  return undefined;
}

export function getAllActiveCustomers(): CustomerRecord[] {
  return Array.from(customers.values()).filter((c) => c.active);
}

export function deactivateCustomer(customerId: string): void {
  const record = customers.get(customerId);
  if (record) {
    record.active = false;
    customers.set(customerId, record);
  }
}

export function setDavoxiApiKey(customerId: string, apiKey: string): void {
  const record = customers.get(customerId);
  if (record) {
    record.davoxiApiKey = apiKey;
    customers.set(customerId, record);
  }
}
