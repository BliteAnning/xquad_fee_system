import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import validator from "validator";
import Student from "../models/Student.js";
import TransactionLog from "../models/TransactionLog.js";
import Notification from "../models/Notification.js";
import School from "../models/School.js";
import Payment from "../models/Payment.js";
import Receipt from "../models/Receipt.js";
import Fee from "../models/Fee.js";
import StudentRefreshToken from "../models/StudentRefreshToken.js";
import {
  sendStudentLoginSuccessEmail,
  sendFailedLoginEmail,
} from "../utils/email.js";
import {
  STUDENT_JWT_SECRET,
  STUDENT_JWT_REFRESH_SECRET,
  JWT_EXPIRES_IN,
  MAX_LOGIN_ATTEMPTS,
} from "../config/env.js";
import FeeAssignmentModel from "../models/feeAssignmentModel.js";
import { logActionUtil } from "./auditController.js";

export const login = async (req, res) => {
  let session = null;
  try {
    session = await mongoose.startSession();
    session.startTransaction();

    const { email, password } = req.body;
    console.log("Student login attempt:", {
      event: "student_login_attempt",
      email,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      timestamp: new Date().toISOString(),
    });

    const missingFields = [];
    if (!email) missingFields.push("email");
    if (!password) missingFields.push("password");
    if (missingFields.length > 0) {
      throw new Error(`Missing required fields: ${missingFields.join(", ")}`);
    }

    if (!validator.isEmail(email)) {
      throw new Error("Invalid email format");
    }

    // Check for login lockout
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const failedAttempts = await TransactionLog.countDocuments({
      action: "student_login_failure",
      "metadata.ip": req.ip,
      createdAt: { $gte: oneHourAgo },
    }).session(session);
    if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
      throw new Error(
        "Too many failed login attempts. Please try again later."
      );
    }

    // Find student
    const student = await Student.findOne({ email }).session(session);
    if (!student) {
      await logFailedLogin(
        email,
        req.ip,
        req.headers["user-agent"],
        null,
        null,
        failedAttempts + 1,
        session
      );
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, student.password);
    if (!isMatch) {
      console.log("70");
      await logFailedLogin(
        email,
        req.ip,
        req.headers["user-agent"],
        student._id,
        student.schoolId,
        failedAttempts + 1,
        session
      );
      console.log("80");
      try {
        console.log("Sending login failure notification...");
        await sendFailedLoginEmail(student, req.ip, new Date());
        await new Notification({
          recipient: student.email,
          type: "login_failure",
          message: `Failed login attempt for ${student.email}`,
          schoolId: student.schoolId,
          studentId: student._id,
          status: "sent",
          sentAt: new Date(),
        }).save({ session });
      } catch (notificationError) {
        console.error("Non-critical error (notification/email):", {
          event: "notification_failure",
          error: notificationError.message,
          timestamp: new Date().toISOString(),
        });
        console.log("Sending notification failure transaction log...");
        await new TransactionLog({
          studentId: student._id,
          schoolId: student.schoolId,
          action: "notification_failure",
          metadata: {
            ip: req.ip,
            deviceId: req.headers["user-agent"],
            error: notificationError.message,
          },
        }).save({ session });
        console.log("Sent notification failure transaction log.");
      }
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Generate JWT and refresh token
    const token = jwt.sign(
      {
        id: student._id,
        email: student.email,
        schoolId: student.schoolId,
        studentId: student.studentId,
      },
      STUDENT_JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    const refreshToken = jwt.sign(
      { id: student._id },
      STUDENT_JWT_REFRESH_SECRET,
      {
        expiresIn: "7d",
      }
    );

    // Save refresh token
    const refreshTokenDoc = new StudentRefreshToken({
      studentId: student._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
    await refreshTokenDoc.save({ session });

    // Log successful login
    console.log("Sending successful login transaction log...");
    await new TransactionLog({
      schoolId: student.schoolId,
      studentId: student._id,
      action: "student_login_success",
      metadata: {
        ip: req.ip,
        deviceId: req.headers["user-agent"],
        fraudScore: 0,
      },
    }).save({ session });
    console.log("Sent successful login transaction log.");

    // Send success notification
    try {
      console.log("Sending login success notification...");
      await sendStudentLoginSuccessEmail(student);
      await new Notification({
        recipient: student.email,
        type: "student_login_success",
        message: `Successful login for ${student.name}`,
        schoolId: student.schoolId,
        studentId: student._id,
        status: "sent",
        sentAt: new Date(),
      }).save({ session });
      console.log("Sent login success notification.");
    } catch (notificationError) {
      console.error("Non-critical error (notification/email):", {
        event: "notification_failure",
        error: notificationError.message,
        timestamp: new Date().toISOString(),
      });
      console.log("Sending notification failure transaction log...");
      await new TransactionLog({
        studentId: student._id,
        schoolId: student.schoolId,
        action: "notification_failure",
        metadata: {
          ip: req.ip,
          deviceId: req.headers["user-agent"],
          error: notificationError.message,
        },
      }).save({ session });
      console.log("Sent notification failure transaction log.");
    }

    await session.commitTransaction();

    // Increment Prometheus counter (uncomment when set up)
    // prometheus.register.getSingleMetric('student_logins_total').inc();

    res.status(200).json({
      success: true,
      data: {
        _id: student._id,
        name: student.name,
        email: student.email,
        studentId: student.studentId,
        schoolId: student.schoolId,
        department: student.department,
        yearOfStudy: student.yearOfStudy,
      },
      token,
      refreshToken,
    });
  } catch (error) {
    if (session && session.inTransaction()) {
      await session.abortTransaction();
    }
    console.error("Student login error:", {
      event: "student_login_error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return res.status(error.statusCode || 400).json({
      success: false,
      message: error.message || "Internal server error",
    });
  } finally {
    if (session) {
      session.endSession();
    }
  }
};

const logFailedLogin = async (
  email,
  ip,
  deviceId,
  studentId,
  schoolId,
  failedAttempts,
  session
) => {
  console.log("230");
  try {
    console.log("231", { email, studentId, schoolId, failedAttempts });
    const fraudScore = Math.min(failedAttempts * 20, 100); // Simple rule: 20 points per failed attempt
    const transactionLog = new TransactionLog({
      studentId,
      schoolId,
      action: "student_login_failure",
      metadata: { ip, deviceId, email, fraudScore },
    });
    // await transactionLog.save({ session });
    await transactionLog.save();

    console.log("243");
  } catch (error) {
    console.error("Failed to log failed login:", {
      event: "log_failed_login_error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
};

export const getDashboard = async (req, res) => {
  try {
    const { id: studentId, schoolId, email } = req.user;
    const { data } = req.query; // Optional: "payments" or "receipts"

    console.log("Student dashboard access:", {
      event: "student_dashboard_access",
      studentId,
      email,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      timestamp: new Date().toISOString(),
    });

    // Verify student exists in School.students array
    const school = await School.findOne({ _id: schoolId, students: studentId });
    if (!school) {
      console.error("Student not found in school:", {
        event: "student_dashboard_error",
        studentId,
        schoolId,
        error: "Student not associated with school",
        timestamp: new Date().toISOString(),
      });
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    // Calculate fraud score based on access frequency (last 10 minutes)
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    const accessAttempts = await TransactionLog.countDocuments({
      action: "student_dashboard_access",
      studentId,
      createdAt: { $gte: tenMinutesAgo },
    });
    const fraudScore = Math.min(accessAttempts * 10, 100);

    // Log dashboard access
    await new TransactionLog({
      studentId,
      schoolId,
      action: "student_dashboard_access",
      metadata: {
        ip: req.ip,
        deviceId: req.headers["user-agent"],
        fraudScore,
      },
    }).save();

    // Fetch student data
    const student = await Student.findById(studentId).select(
      "_id name email studentId department yearOfStudy courses"
    );
    if (!student) {
      console.error("Student not found:", {
        event: "student_dashboard_error",
        studentId,
        error: "Student not found",
        timestamp: new Date().toISOString(),
      });
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    // Initialize response data
    let responseData = {
      student: {
        _id: student._id,
        name: student.name,
        email: student.email,
        studentId: student.studentId,
        department: student.department,
        yearOfStudy: student.yearOfStudy,
        courses: student.courses,
      },
      payments: [],
      receipts: [],
    };

    // Fetch payments (if not restricted to receipts)
    if (!data || data === "payments") {
      const payments = await Payment.find({ studentId, schoolId })
        .populate({
          path: "feeId",
          select: "feeType academicSession dueDate",
        })
        .select("_id amount feeId paymentProvider status receiptUrl createdAt");
      responseData.payments = payments.map((payment) => ({
        _id: payment._id,
        amount: payment.amount,
        feeId: payment.feeId._id,
        feeDetails: {
          feeType: payment.feeId.feeType,
          academicSession: payment.feeId.academicSession,
          dueDate: payment.feeId.dueDate,
        },
        paymentProvider: payment.paymentProvider,
        status: payment.status,
        receiptUrl: payment.receiptUrl,
        createdAt: payment.createdAt,
      }));
    }

    // Fetch receipts (if not restricted to payments)
    if (!data || data === "receipts") {
      const receipts = await Receipt.find({ studentId, schoolId }).select(
        "_id receiptNumber amount date pdfUrl branding"
      );
      responseData.receipts = receipts.map((receipt) => ({
        _id: receipt._id,
        receiptNumber: receipt.receiptNumber,
        amount: receipt.amount,
        date: receipt.date,
        pdfUrl: receipt.pdfUrl,
        branding: receipt.branding,
      }));
    }

    // Handle empty payments/receipts
    if (
      responseData.payments.length === 0 &&
      responseData.receipts.length === 0
    ) {
      responseData.message = "No payments or receipts found for this student.";
    }

    // Increment Prometheus counter (uncomment when set up)
    // prometheus.register.getSingleMetric('student_dashboard_access_total').inc();

    return res.status(200).json({
      success: true,
      data: responseData,
    });
  } catch (error) {
    console.error("Student dashboard error:", {
      event: "student_dashboard_error",
      studentId: req.user?.id,
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

export const getStudentDashboard = async (req, res) => {
  try {
    const studentId = req.user.id;
    const schoolId = req.user.schoolId;
    const { data } = req.query;

    const responseData = { student: {}, payments: [], receipts: [] };

    if (!data || data === "student") {
      const student = await Student.findById(studentId).select(
        "_id name email studentId department yearOfStudy courses"
      );
      if (!student) {
        throw new Error("Student not found", { cause: { statusCode: 404 } });
      }
      responseData.student = {
        _id: student._id,
        name: student.name,
        email: student.email,
        studentId: student.studentId,
        department: student.department,
        yearOfStudy: student.yearOfStudy,
        courses: student.courses,
      };
    }

    if (!data || data === "payments") {
      const payments = await Payment.find({ studentId, schoolId })
        .populate({
          path: "feeId",
          select: "feeType academicSession dueDate",
        })
        .select("_id amount feeId paymentProvider status receiptUrl createdAt");
      responseData.payments = payments.map((payment) => ({
        _id: payment._id,
        amount: payment.amount,
        feeId: payment.feeId._id,
        feeDetails: {
          feeType: payment.feeId.feeType,
          academicSession: payment.feeId.academicSession,
          dueDate: payment.feeId.dueDate,
        },
        paymentProvider: payment.paymentProvider,
        status: payment.status,
        receiptUrl: payment.receiptUrl,
        createdAt: payment.createdAt,
      }));
    }

    if (!data || data === "receipts") {
      const receipts = await Receipt.find({ studentId, schoolId }).select(
        "_id receiptNumber amount date pdfUrl branding"
      );
      responseData.receipts = receipts.map((receipt) => ({
        _id: receipt._id,
        receiptNumber: receipt.receiptNumber,
        amount: receipt.amount,
        date: receipt.date,
        pdfUrl: receipt.pdfUrl,
        branding: receipt.branding,
      }));
    }

    if (
      responseData.payments.length === 0 &&
      responseData.receipts.length === 0
    ) {
      responseData.message = "No payments or receipts found for this student.";
    }

    return res.status(200).json({
      success: true,
      data: responseData,
    });
  } catch (error) {
    console.error("Student dashboard error:", {
      event: "student_dashboard_error",
      studentId: req.user?.id,
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

export const getStudentFeeAssignments = async (req, res) => {
  try {
    const studentId = req.user.id;
    const schoolId = req.user.schoolId;
    const { feeType, status } = req.query;

    const query = { studentId, schoolId };
    if (feeType) query['feeId.feeType'] = { $regex: feeType, $options: 'i' };
    if (status) query.status = status;

    try {
      await FeeAssignmentModel.updateMany(
        {
          studentId,
          schoolId,
          status: { $in: ['assigned', 'partially_paid'] },
          'feeId.dueDate': { $lt: new Date() },
          $expr: { $lt: ['$amountPaid', '$amountDue'] },
        },
        { $set: { status: 'overdue' } }
      );
    } catch (error) {
      console.error('Error updating overdue status:', {
        event: 'update_overdue_status_error',
        error: error.message,
        timestamp: new Date().toISOString(),
      });
    }

    const feeAssignments = await FeeAssignmentModel.find(query)
      .populate({
        path: 'feeId',
        select: 'feeType amount dueDate academicSession',
      })
      .lean();

    try {
      await logActionUtil({
        entityType: 'FeeAssignment',
        entityId: studentId,
        action: 'fee_assignments_viewed',
        actor: studentId,
        actorType: 'student',
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          filters: { feeType, status },
          feeAssignmentCount: feeAssignments.length,
        },
      });
    } catch (error) {
      console.error({
        event: 'log_action_util_error',
        error: error.message,
        timestamp: new Date().toISOString(),
      });
    }

    if (feeAssignments.length === 0) {
      return res.status(404).json({ message: 'No fee assignments found for this student' });
    }

    res.status(200).json({
      feeAssignments,
    });
  } catch (error) {
    console.error('Error retrieving fee assignments:', {
      event: 'get_student_fee_assignments_error',
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

export const checkAuth = async (req, res) => {
  try {
    const studentId = req.user.id;
    const student = await Student.findById(studentId).lean();
    if (!student) {
      await logActionUtil({
        entityType: 'Student',
        entityId: studentId,
        action: 'check_auth_failure',
        actor: studentId,
        actorType: 'student',
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          reason: 'Student not found',
        },
      });
      await TransactionLog.create({
        action: 'check_auth_failure',
        schoolId: req.user.schoolId,
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          reason: 'Student not found',
        },
      });
      return res.status(401).json({ message: 'Student not found' });
    }

    const refreshTokenDoc = await StudentRefreshToken.findOne({ studentId });
    if (!refreshTokenDoc) {
     try {
       await logActionUtil({
         entityType: 'Student',
         entityId: studentId,
         action: 'check_auth_failure',
         actor: studentId,
         actorType: 'student',
         metadata: {
           ip: req.ip,
           deviceInfo: req.headers['user-agent'],
           reason: 'No refresh token found',
         }
        });
     } catch (error) {
      console.log(`LogActionUtil Error:`,error)
     }
      try {
        await TransactionLog.create({
          action: 'check_auth_failure',
          schoolId: req.user.schoolId,
          metadata: {
            ip: req.ip,
            deviceInfo: req.headers['user-agent'],
            reason: 'No refresh token found',
          },
        });
        return res.status(401).json({ message: 'Invalid refresh token' });
      } catch (error) {
        console.log(`TransactionLog Error:`,error)
      }
    }

    let accessToken = req.headers.authorization.split('Bearer ')[1];
    let refreshToken = refreshTokenDoc.token;

    try {
      jwt.verify(accessToken, STUDENT_JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        try {
          jwt.verify(refreshToken, STUDENT_JWT_REFRESH_SECRET);
          accessToken = jwt.sign(
            { id: student._id, schoolId: student.schoolId },
            STUDENT_JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
          );
          refreshToken = jwt.sign(
            { id: student._id },
            STUDENT_JWT_REFRESH_SECRET,
            { expiresIn: '7d' }
          );
          await StudentRefreshToken.findOneAndUpdate(
            { studentId },
            {
              token: refreshToken,
              expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            },
            { upsert: true }
          );
          await logActionUtil({
            entityType: 'Student',
            entityId: studentId,
            action: 'token_refreshed',
            actor: studentId,
            actorType: 'student',
            metadata: {
              ip: req.ip,
              deviceInfo: req.headers['user-agent'],
            },
          });
          await TransactionLog.create({
            action: 'token_refreshed',
            schoolId: student.schoolId,
            metadata: {
              ip: req.ip,
              deviceInfo: req.headers['user-agent'],
            },
          });
        } catch (refreshError) {
          await logActionUtil({
            entityType: 'Student',
            entityId: studentId,
            action: 'check_auth_failure',
            actor: studentId,
            actorType: 'student',
            metadata: {
              ip: req.ip,
              deviceInfo: req.headers['user-agent'],
              reason: 'Invalid refresh token',
            },
          });
          await TransactionLog.create({
            action: 'check_auth_failure',
            schoolId: student.schoolId,
            metadata: {
              ip: req.ip,
              deviceInfo: req.headers['user-agent'],
              reason: 'Invalid refresh token',
            },
          });
          return res.status(401).json({ message: 'Invalid refresh token' });
        }
      } else {
        await logActionUtil({
          entityType: 'Student',
          entityId: studentId,
          action: 'check_auth_failure',
          actor: studentId,
          actorType: 'student',
          metadata: {
            ip: req.ip,
            deviceInfo: req.headers['user-agent'],
            reason: error.message,
          },
        });
        await TransactionLog.create({
          action: 'check_auth_failure',
          schoolId: student.schoolId,
          metadata: {
            ip: req.ip,
            deviceInfo: req.headers['user-agent'],
            reason: error.message,
          },
        });
        return res.status(401).json({ message: 'Invalid token' });
      }
    }

    await logActionUtil({
      entityType: 'Student',
      entityId: studentId,
      action: 'check_auth_success',
      actor: studentId,
      actorType: 'student',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
      },
    });
    await TransactionLog.create({
      action: 'check_auth_success',
      schoolId: student.schoolId,
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
      },
    });

    res.status(200).json({
      user: {
        _id: student._id,
        name: student.name,
        email: student.email,
        studentId: student.studentId,
        department: student.department,
        yearOfStudy: student.yearOfStudy,
        courses: student.courses,
      },
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.error('Error checking auth:', {
      event: 'check_auth_error',
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    await logActionUtil({
      entityType: 'Student',
      entityId: req.user?.id || 'unknown',
      action: 'check_auth_failure',
      actor: req.user?.id || null,
      actorType: 'student',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        reason: error.message,
      },
    });
    await TransactionLog.create({
      action: 'check_auth_failure',
      schoolId: req.user?.schoolId || null,
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        reason: error.message,
      },
    });
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

export const getStudentPayments = async (req, res) => {
  try {
    const studentId = req.user.id;
    const schoolId = req.user.schoolId;
    const { status, feeType } = req.query;

    const query = { studentId, schoolId };
    if (status) query.status = status;
    if (feeType) query['feeId.feeType'] = { $regex: feeType, $options: 'i' };

    const payments = await Payment.find(query)
      .populate({ path: 'feeId', select: 'feeType academicSession dueDate' })
      .select('_id amount feeId paymentProvider status receiptUrl createdAt')
      .lean();
    if (payments.length === 0) {
      return res.status(404).json({ message: 'No payments found for this student' });
    }
    res.status(200).json({
      payments: payments.map((payment) => ({
        _id: payment._id,
        amount: payment.amount,
        feeId: payment.feeId._id,
        feeDetails: {
          feeType: payment.feeId.feeType,
          academicSession: payment.feeId.academicSession,
          dueDate: payment.feeId.dueDate,
        },
        paymentProvider: payment.paymentProvider,
        status: payment.status,
        receiptUrl: payment.receiptUrl,
        createdAt: payment.createdAt,
      })),
    });
  } catch (error) {
    console.error('Error retrieving student payments:', {
      event: 'get_student_payments_error',
      studentId: req.user?.id,
      email: req.user?.email,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

export const getStudentNotifications = async (req, res) => {
  try {
    const studentId = req.user.id;
    const schoolId = req.user.schoolId;
    const { type, status, page = 1, limit = 20, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

    const query = { studentId, schoolId, deletedAt: null };
    if (type) query.type = { $regex: type, $options: 'i' };
    if (status) query.status = status;

    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const notifications = await Notification.find(query)
      .sort(sort)
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .lean();

    // Update notifications to mark as read and sent
    await Notification.updateMany(
      { _id: { $in: notifications.map(n => n._id) }, read: false },
      { $set: { read: true, status: 'sent', sentAt: new Date() } }
    );

    const total = await Notification.countDocuments(query);
    const unreadCount = await Notification.countDocuments({ studentId, schoolId, read: false, deletedAt: null });

    await logActionUtil({
      entityType: 'Notification',
      entityId: studentId,
      action: 'notifications_viewed',
      actor: studentId,
      actorType: 'student',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        filters: { type, status },
        notificationCount: notifications.length,
      },
    });

    await TransactionLog.create({
      schoolId,
      action: 'notifications_viewed',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        studentId,
        filters: { type, status },
      },
    });

    res.status(200).json({
      notifications,
      total,
      unreadCount,
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (error) {
    console.error('Error retrieving notifications:', {
      event: 'get_student_notifications_error',
      studentId: req.user?.id,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

export const markNotificationsRead = async (req, res) => {
  try {
    const studentId = req.user.id;
    const schoolId = req.user.schoolId;
    const { notificationIds } = req.body; 

    const query = { studentId, schoolId, deletedAt: null, read: false };
    if (notificationIds && Array.isArray(notificationIds)) {
      query._id = { $in: notificationIds };
    }

    const result = await Notification.updateMany(
      query,
      { $set: { read: true, status: 'sent', sentAt: new Date() } }
    );

    await logActionUtil({
      entityType: 'Notification',
      entityId: studentId,
      action: 'notifications_marked_read',
      actor: studentId,
      actorType: 'student',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        notificationCount: result.modifiedCount,
      },
    });

    await TransactionLog.create({
      schoolId,
      action: 'notifications_marked_read',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        studentId,
        notificationCount: result.modifiedCount,
      },
    });

    res.status(200).json({ message: `Marked ${result.modifiedCount} notifications as read` });
  } catch (error) {
    console.error('Error marking notifications as read:', {
      event: 'mark_notifications_read_error',
      studentId: req.user?.id,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

export const deleteNotification = async (req, res) => {
  try {
    const studentId = req.user.id;
    const schoolId = req.user.schoolId;
    const notificationId = req.params.id;

    const notification = await Notification.findOne({
      _id: notificationId,
      studentId,
      schoolId,
      deletedAt: null,
    });

    if (!notification) {
      return res.status(404).json({ message: 'Notification not found or already deleted' });
    }

    notification.deletedAt = new Date();
    await notification.save();

    await logActionUtil({
      entityType: 'Notification',
      entityId: notificationId,
      action: 'notification_deleted',
      actor: studentId,
      actorType: 'student',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        notificationType: notification.type,
      },
    });

    await TransactionLog.create({
      schoolId,
      action: 'notification_deleted',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        studentId,
        notificationId,
        notificationType: notification.type,
      },
    });

    res.status(200).json({ message: 'Notification deleted successfully' });
  } catch (error) {
    console.error('Error deleting notification:', {
      event: 'delete_notification_error',
      studentId: req.user?.id,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

export const clearAllNotifications = async (req, res) => {
  try {
    const studentId = req.user.id;
    const schoolId = req.user.schoolId;

    const result = await Notification.updateMany(
      { studentId, schoolId, deletedAt: null },
      { $set: { deletedAt: new Date() } }
    );

    await logActionUtil({
      entityType: 'Notification',
      entityId: studentId,
      action: 'notifications_cleared',
      actor: studentId,
      actorType: 'student',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        notificationCount: result.modifiedCount,
      },
    });

    await TransactionLog.create({
      schoolId,
      action: 'notifications_cleared',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        studentId,
        notificationCount: result.modifiedCount,
      },
    });

    res.status(200).json({ message: `Cleared ${result.modifiedCount} notifications` });
  } catch (error) {
    console.error('Error clearing notifications:', {
      event: 'clear_notifications_error',
      studentId: req.user?.id,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};


