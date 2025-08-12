import { aj } from "../config/arcjet.config.js";

const arcjetMiddleware = async (req, res, next) => {
  try {
    const decision = await aj.protect(req, { requested: 1 });

    if (decision.isDenied()) {
      if (decision.reason.isRateLimit()) {
        return res.status(429).json({
          success: false,
          message: "Rate limit exceeded. Please try again later.",
        });
      }
      if (decision.reason.isBot()) {
        return res.status(403).json({
          success: false,
          message: "Access denied for botws.",
        });
      }
    //   if(decision.ip.isHosting()){
    //     return res.status(403).json({
    //       success: false,
    //       message: "Access denied for hosting services.",
    //     });
    //   }

    //   if (decision.reason.isShield()) {
    //     return res.status(400).json({
    //       success: false,
    //       message: "Request blocked by security rules.",
    //     });
    //   }

      return res.status(403).json({
        success: false,
        message: "Access denied.",
      });
    }

    next();
  } catch (error) {
    console.error("Arcjet middleware error:", error);
    res.status(500).json({
      success: false,
      message: error.message || "Internal server error",
    });
    next(error);
  }
};

export default arcjetMiddleware;
