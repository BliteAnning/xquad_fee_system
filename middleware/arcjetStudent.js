import { ajStudent } from "../config/arcjetStudent.config.js";

const arcjetStudentMiddleware = async (req, res, next) => {
  try {
    const decision = await ajStudent.protect(req, { requested: 1 });

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
          message: "Access denied for bots.",
        });
      }
      return res.status(403).json({
        success: false,
        message: "Access denied.",
      });
    }

    next();
  } catch (error) {
    console.error("Arcjet student middleware error:", {
      event: "arcjet_student_error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({
      success: false,
      message: error.message || "Internal server error",
    });
  }
};

export default arcjetStudentMiddleware;