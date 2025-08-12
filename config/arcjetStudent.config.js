import arcjet, { shield, detectBot, tokenBucket } from "@arcjet/node";
import { ARCJET_KEY } from "./env.js";

export const ajStudent = arcjet({
  key: ARCJET_KEY,
  rules: [
    shield({ mode: "LIVE" }),
    detectBot({
      mode: "LIVE",
      allow: [
        "CATEGORY:SEARCH_ENGINE",
        // "CATEGORY:USER_AGENT",
        "CATEGORY:API",
        "CATEGORY:TESTING",
        "CATEGORY:MONITORING",
      ],
    }),
    tokenBucket({
      mode: "LIVE",
      refillRate: 3,
      interval: 10,
      capacity: 3,
      characteristics: ["ip.src"],
    }),
  ],
});