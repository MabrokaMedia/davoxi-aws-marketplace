export const config = {
  aws: {
    productCode: process.env.AWS_MARKETPLACE_PRODUCT_CODE || "",
    region: process.env.AWS_REGION || "us-east-1",
  },
  davoxi: {
    apiUrl: process.env.DAVOXI_API_URL || "https://api.davoxi.com",
  },
  port: parseInt(process.env.PORT || "3002", 10),
  appUrl: process.env.APP_URL || "http://localhost:3002",

  // Metering dimensions matching your AWS Marketplace product listing
  dimensions: {
    aiCallMinutes: "ai_call_minutes",
    activeAgents: "active_agents",
    activeBusinesses: "active_businesses",
  },
};
