import express from "express";
import cors from "cors";
import helmet from "helmet";
import { config } from "./config";
import registrationRoutes from "./routes/registration";
import settingsRoutes from "./routes/settings";
import meteringRoutes from "./routes/metering";
import snsRoutes from "./routes/sns";

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For marketplace registration token

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "davoxi-aws-marketplace" });
});

// Routes
app.use("/register", registrationRoutes);
app.use("/settings", settingsRoutes);
app.use("/metering", meteringRoutes);
app.use("/sns", snsRoutes);

app.listen(config.port, () => {
  console.log(`Davoxi AWS Marketplace integration running on port ${config.port}`);
});

export default app;
