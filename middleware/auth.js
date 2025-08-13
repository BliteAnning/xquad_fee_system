// middleware/auth.js
import jwt from "jsonwebtoken";
import { JWT_SECRET, STUDENT_JWT_SECRET } from "../config/env.js";
import School from "../models/School.js";
import Student from "../models/Student.js";

export const authenticateSchool = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split("Bearer ")[1];
    if (!token) {
      throw new Error("No token provided");
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const school = await School.findById(decoded.id);
    if (!school) {
      throw new Error("School not found");
    }

    if (!decoded.isTemp && !school.isVerified) {
      throw new Error("MFA verification required");
    }

    req.user = { id: school._id, email: school.email };
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: error.message || "Unauthorized",
    });
  }
};

export const authenticateStudent = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split("Bearer ")[1];
    if (!token) {
      throw new Error("No token provided");
    }

    const decoded = jwt.verify(token, STUDENT_JWT_SECRET);
    const student = await Student.findById(decoded.id);
    if (!student) {
      throw new Error("Student not found");
    }

    req.user = {
      id: student._id,
      email: student.email,
      schoolId: student.schoolId,
      studentId: student.studentId,
    };
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: error.message || "Unauthorized",
    });
  }
};

export const verifySchoolToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split("Bearer ")[1];
    if (!token) {
      console.error("Token verification error:", {
        event: "token_verify_error",
        error: "No token provided",
        timestamp: new Date().toISOString(),
      });
      return res
        .status(401)
        .json({ success: false, message: "No token provided" });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const school = await School.findById(decoded.id);
    if (!school) {
      console.error("Token verification error:", {
        event: "token_verify_error",
        error: "School not found",
        timestamp: new Date().toISOString(),
      });
      return res
        .status(404)
        .json({ success: false, message: "School not found" });
    }
    req.user = { id: school._id, email: school.email };
    next();
  } catch (error) {
    console.error("Token verification error:", {
      event: "token_verify_error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(401).json({ success: false, message: "Invalid token" });
  }
};
