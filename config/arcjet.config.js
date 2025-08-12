import arcjet, {shield,detectBot,tokenBucket} from "@arcjet/node";
import { ARCJET_KEY } from "./env.js";

export const aj = arcjet({
  // Get your site key from https://app.arcjet.com and set it as an environment
  // variable rather than hard coding.
  key: ARCJET_KEY,
  rules: [
    // Shield protects your app from common attacks e.g. SQL injection
    shield({ mode: "LIVE" }),
    // Create a bot detection rule
    detectBot({
      mode: "LIVE", // Blocks requests. Use "DRY_RUN" to log only
      // Block all bots except the following
      allow: [
        "CATEGORY:SEARCH_ENGINE", // Google, Bing, etc
        // "CATEGORY:USER_AGENT", // Common user agents
        "CATEGORY:API", // API clients like Postman, Insomnia
        "CATEGORY:TESTING", // Testing tools like Selenium, Puppeteer
        "CATEGORY:MONITORING", // Monitoring services like UptimeRobot, Pingdom
        // Uncomment to allow these other common bot categories
        // See the full list at https://arcjet.com/bot-list
        //"CATEGORY:MONITOR", // Uptime monitoring services
        //"CATEGORY:PREVIEW", // Link previews e.g. Slack, Discord
      ],
    }),
    // Create a token bucket rate limit. Other algorithms are supported.
    tokenBucket({
      mode: "LIVE",
      // Tracked by IP address by default, but this can be customized
      // See https://docs.arcjet.com/fingerprints
      //characteristics: ["ip.src"],
      refillRate: 5, // Refill 5 tokens per interval
      interval: 10, // Refill every 10 seconds
      capacity: 5, // Bucket capacity of 5 tokens
      characteristics: ["ip.src"], // Track by IP address
      // Uncomment to allow requests from the same IP address
      // that are part of the same session (e.g. same browser tab)
      //session: true,
    }),
  ],
});