import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import validator from "validator";
import School from "../models/School.js";
import TransactionLog from "../models/TransactionLog.js";
import Notification from "../models/Notification.js";
import RefreshToken from "../models/RefreshToken.js";
import Student from "../models/Student.js";
import Payment from "../models/Payment.js";
import Fee from "../models/Fee.js";
import Refund from "../models/Refund.js";
import {
  sendWelcomeEmail,
  sendFailedLoginEmail,
  sendStudentWelcomeEmail,
  sendAdminStudentAddedEmail,
  sendOtpEmail,
  sendMfaFailedEmail,
} from "../utils/email.js";
import {
  JWT_SECRET,
  JWT_REFRESH_SECRET,
  JWT_EXPIRES_IN,
  JWT_REFRESH_EXPIRES_IN,
  MAX_LOGIN_ATTEMPTS,
} from "../config/env.js";
import FeeModel from "../models/Fee.js";
import { logActionUtil } from "./auditController.js";
import FeeAssignmentModel from "../models/feeAssignmentModel.js";
import TransactionLogModel from "../models/TransactionLog.js";

export const register = async (req, res) => {
  let session = null;
  try {
    session = await mongoose.startSession();
    session.startTransaction();

    const { name, email, password, contactDetails, paymentProviders } =
      req.body;

    // Validate inputs
    const missingFields = [];
    if (!name) missingFields.push("name");
    if (!email) missingFields.push("email");
    if (!password) missingFields.push("password");
    if (!contactDetails?.phone) missingFields.push("contactDetails.phone");
    if (!contactDetails?.address) missingFields.push("contactDetails.address");
    if (!paymentProviders || paymentProviders.length === 0) {
      missingFields.push("At least one payment provider is required");
    }
    if (missingFields.length > 0) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(", ")}`,
      });
    }

    if (!validator.isEmail(email)) {
      await session.abortTransaction();
      session.endSession();
      return res
        .status(400)
        .json({ success: false, message: "Invalid email format" });
    }

    if (!validator.isMobilePhone(contactDetails.phone, "any")) {
      await session.abortTransaction();
      session.endSession();
      return res
        .status(400)
        .json({ success: false, message: "Invalid phone number format" });
    }

    if (
      !validator.isStrongPassword(password, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
    ) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({
        success: false,
        message:
          "Password must be strong (8+ characters, with uppercase, lowercase, number, and symbol)",
      });
    }

    const existingSchool = await School.findOne({ email }).session(session);
    if (existingSchool) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({
        success: false,
        message: "School with this email already exists",
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const school = new School({
      name,
      email,
      password, // Will be hashed by schema pre-save hook
      contactDetails,
      paymentProviders: [
        {
          ...paymentProviders[0],
          apiKey: process.env.PAYMENT_API_KEY || paymentProviders[0].apiKey,
        },
      ],
      isVerified: false,
      otp,
      otpExpires,
    });

    console.log("Creating new School document", {
      name,
      email,
      contactDetails,
      otp,
    });

    await school.save({ session });
    console.log("School saved");

    // Generate JWT tokens
    const token = jwt.sign({ id: school._id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });
    const refreshToken = jwt.sign({ id: school._id }, JWT_REFRESH_SECRET, {
      expiresIn: JWT_REFRESH_EXPIRES_IN,
    });

    // Save refresh token
    await RefreshToken.create(
      [
        {
          schoolId: school._id,
          token: refreshToken,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        },
      ],
      { session }
    );

    console.log(`Sending OTP to ${school.email} from ${school.name}...`);
    try {
      await sendOtpEmail(school, otp);
      console.log(`OTP sent`);
    } catch (error) {
      console.error("Failed to send OTP email:", error);
    }
    

    // Log OTP sent
    await TransactionLog.create(
      [
        {
          action: "otp_sent",
          schoolId: school._id,
          email,
          timestamp: new Date(),
          details: { token },
        },
      ],
      { session }
    );
    console.log(`OTP transaction log created`);

    // Create notification
    await Notification.create(
      [
        {
          recipient: email,
          type: "school_registration",
          message: `School ${name} registered successfully`,
          schoolId: school._id,
          status: "sent",
          sentAt: new Date(),
        },
      ],
      { session }
    );

    await session.commitTransaction();
    session.endSession();

    console.log({
      event: "school_registered",
      schoolId: school._id,
      email,
      timestamp: new Date().toISOString(),
    });

    return res.status(201).json({
      success: true,
      token,
      refreshToken,
      data: {
        _id: school._id,
        name: school.name,
        email: school.email,
      },
    });
  } catch (error) {
    if (session) {
      await session.abortTransaction();
      session.endSession();
    }
    console.log({
      event: "register_error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(500).json({
      success: false,
      message: error.message || "Server error during registration",
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("School login attempt:", {
      event: "school_login_attempt",
      email,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      timestamp: new Date().toISOString(),
    });

    const missingFields = [];
    if (!email) missingFields.push("email");
    if (!password) missingFields.push("password");
    if (missingFields.length > 0) {
      const error = new Error(
        `Missing required fields: ${missingFields.join(", ")}`
      );
      error.statusCode = 400;
      throw error;
    }

    if (!validator.isEmail(email)) {
      throw new Error("Invalid email format");
    }

    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000); // 1 hour
    const failedAttempts = await TransactionLog.countDocuments({
      action: { $in: ["school_login_failure", "school_mfa_failure"] },
      "metadata.ip": req.ip,
      createdAt: { $gte: oneHourAgo },
    });
    if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
      return res.status(429).json({
        success: false,
        message: "Too many failed attempts. Please try again later",
      });
    }

    const school = await School.findOne({ email });
    if (!school) {
      await logFailedLogin(
        email,
        req.ip,
        req.headers["user-agent"],
        null,
        null,
        failedAttempts + 1
      );
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const isMatch = await bcrypt.compare(password, school.password);
    if (!isMatch) {
      await logFailedLogin(
        email,
        req.ip,
        req.headers["user-agent"],
        school._id,
        null,
        failedAttempts + 1
      );
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    if (!school.isVerified) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email with the OTP sent",
      });
    }

    const token = jwt.sign({ id: school._id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });
    const refreshToken = jwt.sign({ id: school._id }, JWT_REFRESH_SECRET, {
      expiresIn: JWT_REFRESH_EXPIRES_IN,
    });

    const refreshTokenDoc = new RefreshToken({
      schoolId: school._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
    await refreshTokenDoc.save();

    await TransactionLog.create([
      {
        schoolId: school._id,
        action: "school_login_success",
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers["user-agent"],
          deviceId: req.headers["device-id"] || "unknown",
          fraudScore: 0,
        },
      },
    ]);

    return res.status(200).json({
      success: true,
      token,
      refreshToken,
      data: {
        _id: school._id,
        name: school.name,
        email: school.email,
      },
    });
  } catch (error) {
    console.error("School login error:", {
      event: "school_login_error",
      email: req.body.email,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || "Internal server error",
    });
  }
};

async function logFailedLogin(
  email,
  ip,
  userAgent,
  schoolId,
  studentId,
  failedAttempts
) {
  console.log("Logging failed login...");

  await TransactionLog.create([
    {
      schoolId,
      action: "school_login_failure",
      metadata: {
        ip,
        deviceInfo: userAgent,
        deviceId: "unknown",
        fraudScore: failedAttempts,
      },
    },
  ]);

  try {
    await Notification.create([
      {
        recipient: email,
        type: "login_failure",
        message: `Failed login attempt for ${email}`,
        schoolId,
        studentId,
        status: "sent",
        sentAt: new Date(),
      },
    ]);
  } catch (error) {
    console.log(`Notification error: `, error);
  }

  await sendFailedLoginEmail({ email, schoolId }, ip, new Date());
}

export const sendOtp = async (req, res) => {
  try {
    const school = await School.findById(req.user.id);
    if (!school) throw new Error("School not found");

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    school.otp = otp;
    school.otpExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    await school.save();
    await sendOtpEmail(school, otp);

    await TransactionLog.create({
      schoolId: school._id,
      action: "otp_sent",
      details: { email: school.email, timestamp: new Date().toISOString() },
    });

    return res.status(200).json({
      success: true,
      message: "OTP sent to your email",
    });
  } catch (error) {
    console.error("Send OTP error:", {
      event: "send_otp_error",
      schoolId: req.user?.id,
      email: req.user?.email,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(500).json({
      success: false,
      message: error.message || "Failed to send OTP",
    });
  }
};

export const resendOtp = async (req, res) => {
  try {
    const school = await School.findById(req.user.id);
    if (!school) throw new Error("School not found");

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    school.otp = otp;
    school.otpExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    await school.save();
    await sendOtpEmail(school, otp);

    await TransactionLog.create({
      schoolId: school._id,
      action: "otp_resent",
      details: { email: school.email, timestamp: new Date().toISOString() },
    });

    return res.status(200).json({
      success: true,
      message: "OTP resent to your email",
    });
  } catch (error) {
    console.error("Resend OTP error:", {
      event: "resend_otp_error",
      schoolId: req.user?.id,
      email: req.user?.email,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(500).json({
      success: false,
      message: error.message || "Failed to resend OTP",
    });
  }
};

export const verifyOtp = async (req, res) => {
  try {
    const { otp } = req.body;
    if (!otp || !validator.isNumeric(otp) || otp.length !== 6) {
      throw new Error("Invalid OTP format");
    }

    const school = await School.findOne({
      otp,
      otpExpires: { $gt: Date.now() },
    });
    if (!school) {
      await TransactionLog.create({
        action: "otp_verify_failed",
        details: { otp, timestamp: new Date().toISOString() },
      });
      throw new Error("Invalid or expired OTP");
    }

    school.isVerified = true;
    school.otp = null;
    school.otpExpires = null;
    await school.save();

    const token = jwt.sign({ id: school._id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });
    const refreshToken = jwt.sign({ id: school._id }, JWT_REFRESH_SECRET, {
      expiresIn: JWT_REFRESH_EXPIRES_IN,
    });

    await RefreshToken.create({
      schoolId: school._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    await TransactionLog.create({
      schoolId: school._id,
      action: "otp_verified",
      details: { email: school.email, timestamp: new Date().toISOString() },
    });

    await sendWelcomeEmail(school);

    return res.status(200).json({
      success: true,
      token,
      refreshToken,
      data: {
        _id: school._id,
        name: school.name,
        email: school.email,
      },
      message: "OTP verified successfully",
    });
  } catch (error) {
    console.error("Verify OTP error:", {
      event: "verify_otp_error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(400).json({
      success: false,
      message: error.message || "Failed to verify OTP",
    });
  }
};

export const checkAuth = async (req, res) => {
  try {
    // User is already authenticated by authenticateSchool middleware
    // Return user details and token validity
    return res.status(200).json({
      success: true,
      data: {
        id: req.user.id,
        email: req.user.email,
        userType: "school",
      },
      message: "Token is valid",
    });
  } catch (error) {
    console.error("Check auth error:", {
      event: "school_check_auth_error",
      schoolId: req.user?.id,
      email: req.user?.email,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(401).json({
      success: false,
      message: error.message || "Invalid or expired token",
    });
  }
};

export const addStudent = async (req, res) => {
  let session = null;
  console.log("Startin session");
  try {
    // Start MongoDB session
    session = await mongoose.startSession();
    session.startTransaction();

    const {
      name,
      email,
      password,
      phone,
      studentId,
      department,
      yearOfStudy,
      registrationInfo,
      courses,
    } = req.body;

    // Validate inputs
    const missingFields = [];
    if (!name) missingFields.push("name");
    if (!email) missingFields.push("email");
    if (!password) missingFields.push("password");
    if (!studentId) missingFields.push("studentId");
    if (!department) missingFields.push("department");
    if (!yearOfStudy) missingFields.push("yearOfStudy");
    if (missingFields.length > 0) {
      throw new Error(`Missing required fields: ${missingFields.join(", ")}`);
    }

    if (!validator.isEmail(email)) {
      throw new Error("Invalid email format");
    }

    if (phone && !validator.isMobilePhone(phone, "any")) {
      throw new Error("Invalid phone number format");
    }

    if (
      !validator.isStrongPassword(password, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
    ) {
      throw new Error(
        "Password must be at least 8 characters long and include uppercase, lowercase, numbers, and symbols."
      );
    }

    const allowedDepartments = [
      "Computer Science",
      "Engineering",
      "Business",
      "Arts",
      "Sciences",
      "Medicine",
    ];
    if (!allowedDepartments.includes(department)) {
      throw new Error(
        `Department must be one of: ${allowedDepartments.join(", ")}`
      );
    }

    const allowedYears = ["Freshman", "Sophomore", "Junior", "Senior"];
    if (!allowedYears.includes(yearOfStudy)) {
      throw new Error(
        `Year of study must be one of: ${allowedYears.join(", ")}`
      );
    }

    const allowedCourses = [
      "CS101",
      "ENG201",
      "BUS301",
      "ART101",
      "SCI201",
      "MED101",
    ];
    if (courses && courses.length > 0) {
      for (const course of courses) {
        if (!allowedCourses.includes(course)) {
          throw new Error(
            `Course ${course} is not valid. Must be one of: ${allowedCourses.join(
              ", "
            )}`
          );
        }
      }
    }

    console.log(`Requesting id...`);
    // Get school from JWT
    const schoolId = req.user.id; // From authenticateSchool middleware
    console.log(`Getting school...`);
    const school = await School.findById(schoolId).session(session);
    if (!school) {
      throw new Error("School not found");
    }

    // Validate studentId format (e.g., KNUST-123)
    const studentIdRegex = new RegExp(`^${school.name}-\\d+$`);
    if (!studentIdRegex.test(studentId)) {
      throw new Error(`Student ID must follow format: ${school.name}-<number>`);
    }

    // Check for duplicate email or studentId
    const existingStudent = await Student.findOne({
      $or: [{ email }, { $and: [{ schoolId, studentId }] }],
    }).session(session);
    if (existingStudent) {
      throw new Error("Student email or studentId already exists");
    }

    // Create student
    console.log("Creating Student document:", { name, email, studentId });
    const student = new Student({
      schoolId,
      name,
      email,
      password,
      phone,
      studentId,
      department,
      yearOfStudy,
      registrationInfo: {
        enrollmentDate: registrationInfo?.enrollmentDate || "",
        program: registrationInfo?.program || "",
        emergencyContact: registrationInfo?.emergencyContact || "",
        studentType: registrationInfo?.studentType || "",
        guardianName: registrationInfo?.guardianName || "",
      },
      courses: courses || [],
    });
    console.log(`Saving student...`);
    await student.save({ session });
    console.log("Student saved:", student._id);

    // Update school's students array
    console.log(`Updating...`);
    await School.updateOne(
      { _id: schoolId },
      { $addToSet: { students: student._id } },
      { session }
    );
    console.log("School updated with student ID:", student._id);

    // Log transaction
    console.log("Creating TransactionLog document:", {
      schoolId,
      studentId: student._id,
    });
    const transactionLog = new TransactionLog({
      schoolId,
      action: "student_added",
      metadata: {
        ip: req.ip,
        deviceId: req.headers["user-agent"],
        adminId: schoolId, // Track who added the student
        studentId: student._id,
      },
    });
    await transactionLog.save({ session });
    console.log("TransactionLog saved:", transactionLog._id);

    // Commit transaction
    await session.commitTransaction();

    // Send emails and log notifications
    try {
      console.log("Sending student welcome email to:", email);
      await sendStudentWelcomeEmail(
        student,
        school,
        password,
        student.studentId
      ); // Pass plain-text password
      console.log("Creating Notification document for student:", {
        recipient: email,
      });
      const studentNotification = new Notification({
        recipient: email,
        type: "student_added",
        message: `Student ${name} added to ${school.name}`,
        schoolId,
        studentId: student._id,
        status: "sent",
        sentAt: new Date(),
      });
      await studentNotification.save();
      console.log("Student Notification saved:", studentNotification._id);

      console.log("Sending admin notification email to:", school.email);
      await sendAdminStudentAddedEmail(school, student);
      console.log("Creating Notification document for admin:", {
        recipient: school.email,
      });
      const adminNotification = new Notification({
        recipient: school.email,
        type: "student_added_admin",
        message: `Student ${name} added to your school`,
        schoolId,
        studentId: student._id,
        status: "sent",
        sentAt: new Date(),
      });
      console.log(`Saving notification...`);
      await adminNotification.save();
      console.log("Admin Notification saved:", adminNotification._id);
    } catch (notificationError) {
      console.error(
        "Non-critical error (notification/email):",
        notificationError
      );
    }

    // End session
    if (session) {
      session.endSession();
    }

    // Increment Prometheus counter (uncomment when set up)
    // prometheus.register.getSingleMetric('students_added_total').inc();

    return res.status(201).json({
      success: true,
      data: {
        _id: student._id,
        name: student.name,
        email: student.email,
        studentId: student.studentId,
        department: student.department,
        yearOfStudy: student.yearOfStudy,
        phone: student.phone,
        registrationInfo: student.registrationInfo,
        courses: student.courses,
      },
    });
  } catch (error) {
    if (session && session.inTransaction()) {
      await session.abortTransaction();
    }
    if (session) {
      session.endSession();
    }
    console.error("Add student error:", error);
    return res.status(error.statusCode || 400).json({
      success: false,
      message: error.message || "Internal server error",
    });
  }
};

export const getAdminDashboard = async (req, res) => {
  try {
    const { id: schoolId, email } = req.user;
    const { data, status, academicSession } = req.query;

    console.log("School dashboard access:", {
      event: "school_dashboard_access",
      schoolId,
      email,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      timestamp: new Date().toISOString(),
    });

    // Verify school exists
    const school = await School.findById(schoolId).select(
      "_id name email contactDetails customFields.receiptBranding"
    );
    if (!school) {
      console.error("School not foundadmin 1:", {
        event: "school_dashboard_error",
        schoolId,
        error: "School not foundadmin",
        timestamp: new Date().toISOString(),
      });
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    // Calculate fraud score (10 points per access in 10 minutes, capped at 100)
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    const accessAttempts = await TransactionLog.countDocuments({
      action: "school_dashboard_access",
      schoolId,
      createdAt: { $gte: tenMinutesAgo },
    });
    const fraudScore = Math.min(accessAttempts * 10, 100);

    // Log dashboard access
    await new TransactionLog({
      schoolId,
      action: "school_dashboard_access",
      metadata: {
        ip: req.ip,
        deviceId: req.headers["user-agent"],
        fraudScore,
      },
    }).save();

    // Initialize response data
    let responseData = {
      school: {
        _id: school._id,
        name: school.name,
        email: school.email,
        contactDetails: school.contactDetails,
        receiptBranding: school.customFields.receiptBranding,
      },
      payments: [],
      students: [],
      fees: [],
      reports: {},
    };

    // Fetch payments (if not restricted)
    if (!data || data === "payments") {
      let paymentQuery = { schoolId };
      if (status) {
        paymentQuery.status = status;
      }
      const payments = await Payment.find(paymentQuery)
        .populate({
          path: "studentId",
          select: "_id name studentId",
        })
        .populate({
          path: "feeId",
          select: "_id feeType academicSession dueDate",
        })
        .select(
          "_id studentId feeId amount paymentProvider status receiptUrl createdAt"
        );
      responseData.payments = payments.map((payment) => ({
        _id: payment._id,
        student: {
          _id: payment.studentId._id,
          name: payment.studentId.name,
          studentId: payment.studentId.studentId,
        },
        fee: {
          _id: payment.feeId._id,
          feeType: payment.feeId.feeType,
          academicSession: payment.feeId.academicSession,
          dueDate: payment.feeId.dueDate,
        },
        amount: payment.amount,
        paymentProvider: payment.paymentProvider,
        status: payment.status,
        receiptUrl: payment.receiptUrl,
        createdAt: payment.createdAt,
      }));
    }

    // Fetch students (if not restricted)
    if (!data || data === "students") {
      const students = await Student.find({ schoolId }).select(
        "_id name email studentId department yearOfStudy courses"
      );
      responseData.students = students.map((student) => ({
        _id: student._id,
        name: student.name,
        email: student.email,
        studentId: student.studentId,
        department: student.department,
        yearOfStudy: student.yearOfStudy,
        courses: student.courses,
      }));
    }

    // Fetch fees (if not restricted)
    if (!data || data === "fees") {
      let feeQuery = { schoolId };
      if (academicSession) {
        feeQuery.academicSession = academicSession;
      }
      const fees = await Fee.find(feeQuery).select(
        "_id feeType amount dueDate academicSession allowPartialPayment"
      );
      responseData.fees = fees.map((fee) => ({
        _id: fee._id,
        feeType: fee.feeType,
        amount: fee.amount,
        dueDate: fee.dueDate,
        academicSession: fee.academicSession,
        allowPartialPayment: fee.allowPartialPayment,
      }));
    }

    // Generate reports (if not restricted to specific data)
    if (!data) {
      const totalPayments = await Payment.aggregate([
        {
          $match: {
            schoolId: new mongoose.Types.ObjectId(schoolId),
            status: "confirmed",
          },
        },
        { $group: { _id: null, total: { $sum: "$amount" } } },
      ]);
      const pendingPayments = await Payment.countDocuments({
        schoolId,
        status: "pending",
      });
      const confirmedPayments = await Payment.countDocuments({
        schoolId,
        status: "confirmed",
      });
      const studentCount = await Student.countDocuments({ schoolId });
      const overdueFees = await Fee.countDocuments({
        schoolId,
        dueDate: { $lt: new Date() },
      });
      const requestedRefunds = await Refund.countDocuments({
        schoolId,
        status: "requested",
      });
      const approvedRefunds = await Refund.countDocuments({
        schoolId,
        status: "approved",
      });

      responseData.reports = {
        totalPayments: totalPayments[0]?.total || 0,
        pendingPayments,
        confirmedPayments,
        studentCount,
        overdueFees,
        requestedRefunds,
        approvedRefunds,
      };
    }

    // Handle empty data
    if (
      responseData.payments.length === 0 &&
      responseData.students.length === 0 &&
      responseData.fees.length === 0
    ) {
      responseData.message = "No data found for this school.";
    }

    // Increment Prometheus counter (uncomment when set up)
    // prometheus.register.getSingleMetric('school_dashboard_access_total').inc();

    return res.status(200).json({
      success: true,
      data: responseData,
    });
  } catch (error) {
    console.error("School dashboard error:", {
      event: "school_dashboard_error",
      schoolId: req.user?.id,
      email: req.user?.email,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || "Internal server error",
    });
  }
};

export const getFees = async (req, res) => {
  console.log(`starting try...`)
  try {
    const schoolId = req.user.id;
    const { academicSession } = req.query;

    const query = { schoolId: new mongoose.Types.ObjectId(schoolId) };
    if (academicSession) {
      query.academicSession = academicSession;
    }

    const fees = await FeeModel.find(query).sort({ createdAt: -1 });

    console.log(`awaiting logs...`)
   try {
     await logActionUtil({
       entityType: "Fee",
       entityId: schoolId,
       action: "fees_viewed",
       actor: schoolId,
       actorType: "admin",
       metadata: {
         ip: req.ip,
         deviceInfo: req.headers["user-agent"],
         academicSession,
       },
     });console.log(`log saved`)
 
   } catch (logError) {
    console.error(`LogError`,logError)
   }
    res.status(200).json({ data: fees });
  } catch (error) {
    console.error("Error fetching fees:", {
      event: "fetch_fees_error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

export const deleteFee = async (req, res) => {
  let session = null;
  try {
    const schoolId = req.user.id;
    const feeId = req.params.id;

    session = await mongoose.startSession();
    session.startTransaction();

    const fee = await FeeModel.findOne({ _id: feeId, schoolId }).session(
      session
    );
    if (!fee) {
      await session.abortTransaction();
      return res.status(404).json({ message: "Fee not found" });
    }

    const assignments = await FeeAssignmentModel.find({ feeId }).session(
      session
    );
    if (assignments.length > 0) {
      await session.abortTransaction();
      return res
        .status(400)
        .json({ message: "Cannot delete fee with existing assignments" });
    }

    await FeeModel.deleteOne({ _id: feeId, schoolId }).session(session);

    await TransactionLogModel.create({
      schoolId,
      action: "fee_deleted",
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers["user-agent"],
        adminId: schoolId,
        feeId,
        feeType: fee.feeType,
        amount: fee.amount,
        academicSession: fee.academicSession,
      },
    });

    await logActionUtil({
      entityType: "Fee",
      entityId: feeId,
      action: "fee_deleted",
      actor: schoolId,
      actorType: "admin",
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers["user-agent"],
        adminId: schoolId,
        feeType: fee.feeType,
        amount: fee.amount,
        academicSession: fee.academicSession,
      },
    });

    await session.commitTransaction();
    res.status(200).json({ message: "Fee deleted successfully" });
  } catch (error) {
    if (session && session.inTransaction()) {
      await session.abortTransaction();
    }
    console.error("Error deleting fee:", {
      event: "delete_fee_error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ message: "Server error", error: error.message });
  } finally {
    if (session) {
      await session.endSession();
    }
  }
};

export const getStudentCount = async (req, res) => {
  try {
    const schoolId = req.user.id;
    const { department, yearOfStudy } = req.body;

    if (!department && !yearOfStudy) {
      return res
        .status(400)
        .json({
          message: "At least one of department or yearOfStudy is required",
        });
    }

    const query = { schoolId: new mongoose.Types.ObjectId(schoolId) };
    if (department) query.department = department;
    if (yearOfStudy) query.yearOfStudy = yearOfStudy;

    const count = await StudentModel.countDocuments(query);

    await logActionUtil({
      entityType: "Student",
      entityId: schoolId,
      action: "student_count_viewed",
      actor: schoolId,
      actorType: "school",
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers["user-agent"],
        department,
        yearOfStudy,
      },
    });

    res.status(200).json({ count });
  } catch (error) {
    console.error("Error counting students:", {
      event: "count_students_error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
