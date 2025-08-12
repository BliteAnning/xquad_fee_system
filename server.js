import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cors from "cors";
import helmet from "helmet";
import client from "prom-client"
import connectCloudinary from "./config/connectCloudinary.js";
import connectDB from "./db/connectDb.js";
import { PRODUCTION_URL, SYSTEM_NAME } from "./config/env.js";
import errorMiddleware from "./middleware/error.js";
import arcjetMiddleware from "./middleware/arcjet.js";
import schoolRouter from "./routes/schoolRoutes.js";
import studentRouter from "./routes/studentRoutes.js";
import paymentRouter from "./routes/paymentRoute.js";
import refundRouter from "./routes/refundRoute.js";
import feeAssignRouter from "./routes/feeAssiRoute.js";
import auditRouter from "./routes/auditRoute.js";
import job from "./utils/cron.js";



const app = express();

let server;
dotenv.config();

const PORT = process.env.PORT || 3000;

connectCloudinary();

const collectDefaultMetrics = client.collectDefaultMetrics
collectDefaultMetrics({timeout: 5000})

const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      process.env.CLIENT_URL,
      process.env.ADMIN_CLIENT_URL,
      "http://localhost:3001",
      "http://localhost:3000",

    ].filter(Boolean);
    console.log("CORS request origin:", origin);
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log("CORS rejected origin:", origin);
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
};

job.start()
// Security headers with helmet
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://res.cloudinary.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
      connectSrc: ["'self'", PRODUCTION_URL, "https://api.cloudinary.com"],
    },
  })
);

app.use(cors(corsOptions));
app.use(express.json());

app.use("/api/v1/school", schoolRouter);
app.use("/api/v1/students", studentRouter);
app.use("/api/v1/payment", paymentRouter);
app.use("/api/v1/refund", refundRouter)
app.use("/api/v1/fee-assignment", feeAssignRouter);
app.use("/api/v1/audit", auditRouter);

app.get("/", arcjetMiddleware, (req, res) => {
  res.status(200).json({
    success: true,
    message:  `${SYSTEM_NAME} server running!!`,
    environment: process.env.NODE_ENV || "development",
    timestamp: new Date().toISOString(),
  });
});

app.get('/metrics', async (req,res)=>{
    res.set("Content-Type",client.register.contentType)
    res.end(await client.register.metrics())
})

// 404 handler
app.use(arcjetMiddleware, (req, res) => {
  res.status(404).json({
    success: false,
    message: "Endpoint does not exist.",
  });
});

app.use(arcjetMiddleware)

app.use(errorMiddleware)

const startServer = async () => {
  try {
    await connectDB();
    server = app.listen(PORT, () => {
      console.log(`Server running in ${process.env.NODE_ENV || "development"} mode`);
      console.log(`Server is running on http://localhost:${PORT}`);
      console.log(`Allowed client URL: ${process.env.CLIENT_URL}`);
      console.log(`Allowed admin URL: ${process.env.ADMIN_CLIENT_URL}`);
      console.log(`JWT_SECRET: ${process.env.JWT_SECRET ? "Set" : "Missing"}`);
      console.log(`JWT_REFRESH_SECRET: ${process.env.JWT_REFRESH_SECRET ? "Set" : "Missing"}`);
    });
  } catch (error) {
    console.error("Failed to start server", error);
    process.exit(1);
  }
};

startServer();

process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection:", err);
  server?.close(() => process.exit(1));
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  process.exit(1);
});