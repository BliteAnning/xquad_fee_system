import https from "https";
import PaymentModel from "../models/Payment.js";
import FeeModel from "../models/Fee.js";
import SchoolModel from "../models/School.js";
import TransactionLogModel from "../models/TransactionLog.js";
import { logActionUtil } from "./auditController.js";
import { createInvoice } from "./invoiceController.js";
import { updateFeeAssignmentStatus } from "./feeAssignController.js";
import axios from "axios";
import FeeAssignmentModel from "../models/feeAssignmentModel.js";
import ReceiptModel from '../models/Receipt.js'; 
import StudentModel from '../models/Student.js'; 
import { v2 as cloudinary } from 'cloudinary'; 
import {jsPDF} from 'jspdf'; 
import { sendFraudAlertEmail, sendReceipt } from '../utils/email.js';
import mongoose from 'mongoose'; 
import COLORS from "../config/colors.js";
import autoTable from "jspdf-autotable";
import { checkFraud } from '../utils/fraudDetection.js';

const PAYSTACK_BASE_URL = "api.paystack.co";
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

export const initializePayment = async (req, res) => {
  let session = null;
  try {
    session = await mongoose.startSession();
    session.startTransaction();

    const { feeId, amount } = req.body;
    const studentId = req.user.id;

    // Validate fee
    const fee = await FeeModel.findById(feeId).session(session);
    if (!fee) {
      session.endSession();
      return res.status(404).json({ message: "Fee not found" });
    }

    // Check partial payment
    if (amount < fee.amount && !fee.allowPartialPayment) {
      await session.abortTransaction(); // CHANGE: Abort transaction
      session.endSession();
      return res
        .status(400)
        .json({ message: "Partial payments not allowed for this fee" });
    }

    // Validate amount
    if (amount <= 0) {
      await session.abortTransaction(); // CHANGE: Abort transaction
      session.endSession();
      return res.status(400).json({ message: "Amount must be greater than 0" });
    }

    // Get school for Paystack API key
    const school = await SchoolModel.findById(fee.schoolId);
    if (!school) {
      await session.abortTransaction(); // CHANGE: Abort transaction
      session.endSession();
      return res.status(404).json({ message: "School not found" });
    }

    const paystackProvider = school.paymentProviders.find(
      (p) => p.provider === "Paystack"
    );
    if (!paystackProvider) {
      await session.abortTransaction(); // CHANGE: Abort transaction
      session.endSession();
      return res
        .status(400)
        .json({ message: "Paystack not configured for this school" });
    }

    const schoolId = fee.schoolId;

    // Create payment record
    const payment = new PaymentModel({
      studentId,
      schoolId,
      feeId,
      amount,
      paymentProvider: "Paystack",
      status: "initiated",
    });

    // Initialize Paystack transaction
    const params = JSON.stringify({
      email: req.user.email,
      amount: amount * 100, // Paystack expects amount in kobo
      reference: `PAY-${payment._id}-${Date.now()}`,
      callback_url: process.env.PAYSTACK_CALLBACK_URL,
    });

    const options = {
      hostname: PAYSTACK_BASE_URL,
      port: 443,
      path: "/transaction/initialize",
      method: "POST",
      headers: {
        Authorization: "Bearer " + process.env.PAYSTACK_SECRET_KEY,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(params),
      },
    };

    const paystackRequest = await new Promise((resolve, reject) => {
      const req = https.request(options, (response) => {
        let data = "";
        response.on("data", (chunk) => {
          data += chunk;
        });
        response.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch (error) {
            reject(error);
          }
        });
      });
      req.on("error", (error) => reject(error));
      req.write(params);
      req.end();
    });

    if (!paystackRequest.status) {
      await session.abortTransaction(); // CHANGE: Abort transaction
      session.endSession();
      return res
        .status(500)
        .json({
          message: "Paystack initialization failed",
          error: paystackRequest.message,
        });
    }

    payment.providerMetadata.set("paystackRef", paystackRequest.data.reference);
    await payment.save({ session });

    const assignment = await FeeAssignmentModel.findOne({
      feeId: payment.feeId,
      studentId: payment.studentId,
    });

    if (!assignment) {
      return res.status(404).json({
        successs: false,
        message: "Fee assignment not found",
      });
    }

    assignment.amountPaid += payment.amount;
    assignment.status =
      assignment.amountPaid >= assignment.amountDue
        ? "fully_paid"
        : "partially_paid";
    await assignment.save();

    // CHANGE: Generate receipt PDF
    const student = await StudentModel.findById(studentId).session(session);
    if (!student) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Student not found' });
    }

    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.setTextColor(COLORS.textPrimary); // CHANGE: Use OCEAN theme textPrimary color
    doc.text(`${school.name} Payment Receipt`, 20, 20);

    doc.setFontSize(12);
    doc.setTextColor(COLORS.textSecondary);

    autoTable(doc, {
      startY: 30,
      head: [['Field', 'Details']],
      body: [
        ['Receipt Number', `REC-${payment._id}-${Date.now()}`],
        ['Student Name', student.name],
        ['Student ID', student.studentId],
        ['Student Email', student.email],
        ['School Name', school.name],
        ['Fee Type', fee.feeType],
        ['Academic Session', fee.academicSession],
        ['Payment Amount', `NGN ${amount.toFixed(2)}`],
        ['Payment Date', new Date().toISOString().split('T')[0]],
      ],
      theme: 'grid',
      headStyles: { fillColor: COLORS.primary, textColor: COLORS.white }, // CHANGE: Use OCEAN theme colors
      bodyStyles: { textColor: COLORS.textDark }, // CHANGE: Use OCEAN theme textDark
    });

    const pdfBuffer = doc.output('arraybuffer');

    // CHANGE: Upload PDF to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { resource_type: 'raw', folder: 'receipts' },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      stream.end(Buffer.from(pdfBuffer));
    });

    // CHANGE: Create Receipt record
    const receipt = new ReceiptModel({
      paymentId: payment._id,
      studentId,
      schoolId,
      receiptNumber: `REC-${payment._id}-${Date.now()}`,
      amount,
      date: new Date(),
      pdfUrl: uploadResult.secure_url,
      branding: {
        primaryColor: COLORS.primary, // CHANGE: Use OCEAN theme primary color
      },
    });
    await receipt.save({ session });

 // CHANGE: Send receipt email to student and school
    const mailOptions = {
      from: `"${school.name} Payment System" <${process.env.EMAIL_HOST}>`,
      to: [student.email, school.email].join(','), // CHANGE: Send to both student and school
      subject: `Payment Receipt: ${receipt.receiptNumber}`,
      html: `
        <h1 style="color: ${COLORS.primary}">Payment Receipt</h1>
        <p>Dear ${student.name},</p>
        <p>A payment has been initiated at ${school.name}.</p>
        <p><strong>Receipt Number:</strong> ${receipt.receiptNumber}</p>
        <p><strong>Student Name:</strong> ${student.name}</p>
        <p><strong>Student ID:</strong> ${student.studentId}</p>
        <p><strong>Amount:</strong> NGN ${amount.toFixed(2)}</p>
        <p><strong>Fee Type:</strong> ${fee.feeType}</p>
        <p><strong>Academic Session:</strong> ${fee.academicSession}</p>
        <p><strong>Payment Date:</strong> ${new Date().toISOString().split('T')[0]}</p>
        <p>Download your receipt: <a href="${receipt.pdfUrl}">View Receipt</a></p>
      `,
    };

    await sendFeeAssignmentEmail(student, fee, fee.dueDate, mailOptions); // CHANGE: Reuse sendFeeAssignmentEmail with custom mailOptions

    // CHANGE: Log receipt generation and email sending
    try {
      await TransactionLogModel.create({
        paymentId: payment._id,
        schoolId,
        action: 'receipt_generated',
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          studentId,
          receiptNumber: receipt.receiptNumber,
        },
      });
    } catch (error) {
      console.error(`TLog Err 1`,error)
    }

    // await logActionUtil({
    //   entityType: 'Receipt',
    //   entityId: receipt._id,
    //   action: 'receipt_generated',
    //   actor: null,
    //   actorType: 'system',
    //   metadata: {
    //     ip: req.ip,
    //     deviceInfo: req.headers['user-agent'],
    //     studentId,
    //     receiptNumber: receipt.receiptNumber,
    //   },
    // }, { session });

    await session.commitTransaction(); 
    session.endSession();

    res.status(200).json({
      message: "Payment initialized successfully",
      paymentUrl: paystackRequest.data.authorization_url,
      payment,
    });
  } catch (error) {
   if (session) {
      await session.abortTransaction(); 
      session.endSession(); 
    }
    console.error('Error initializing payment:', error);
    try {
      await TransactionLogModel.create({
        action: 'payment_initialization_error',
        schoolId: req.body.feeId ? (await FeeModel.findById(req.body.feeId))?.schoolId : null,
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          error: error.message,
        },
      });
    } catch (error) {
      console.error(`TLog Err 2`,error)
    }
    // CHANGE: Log error to AuditLog
    // await logActionUtil({
    //   entityType: 'Payment',
    //   entityId: null,
    //   action: 'payment_initialization_error',
    //   actor: null,
    //   actorType: 'system',
    //   metadata: {
    //     ip: req.ip,
    //     deviceInfo: req.headers['user-agent'],
    //     error: error.message,
    //   },
    // });
    res.status(500).json({ message: 'Server error', error: error.message });
  }
  }


// Verify Payment (called after Paystack callback)
export const verifyPayment = async (req, res) => {
  try {
    const { reference } = req.query;
    const payment = await PaymentModel.findOne({
      "providerMetadata.paystackRef": reference,
    })
      .populate("studentId")
      .populate("schoolId")
      .populate("feeId");
    if (!payment) {
      return res.status(404).json({ message: "Payment not found" });
    }

    const response = await axios.get(
      `https://${PAYSTACK_BASE_URL}/transaction/verify/${reference}`,
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      }
    );

    if (response.data.status && response.data.data.status === "success") {
      payment.status = "confirmed";
      payment.providerMetadata.set("paystackData", response.data.data); // Store full Paystack response
      await payment.save();

      // Log to TransactionLog
      await TransactionLogModel.create({
        paymentId: payment._id,
        schoolId: payment.schoolId,
        action: "payment_confirmed",
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers["user-agent"],
          studentId: payment.studentId,
        },
      });

      // Log to AuditLog
      await logActionUtil({
        entityType: "Payment",
        entityId: payment._id,
        action: "payment_confirmed",
        actor: payment.schoolId,
        actorType: "admin",
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers["user-agent"],
          studentId: payment.schoolId,
          paystackRef: reference,
        },
      });

      // Generate invoice
      await createInvoice(
        { body: { paymentId: payment._id } },
        {
          status: (code) => ({ json: (data) => ({ code, data }) }),
        }
      );

      // Update fee assignment status
      await updateFeeAssignmentStatus({ paymentId: payment._id });

      res
        .status(200)
        .json({ message: "Payment verified successfully", payment });
    } else {
      payment.status = "rejected";
      await payment.save();

      // Log to AuditLog
      await logActionUtil({
        entityType: "Payment",
        entityId: payment._id,
        action: "payment_rejected",
        actor: null,
        actorType: "system",
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers["user-agent"],
          studentId: payment.studentId,
          paystackRef: reference,
        },
      });

      res
        .status(400)
        .json({
          message: "Payment verification failed",
          error: response.data.message,
        });
    }
  } catch (error) {
    console.error("Error verifying payment:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Handle Paystack Webhook
export const handleWebhook = async (req, res) => {
  try {
    const event = req.body;

    if (event.event === "charge.success") {
      const reference = event.data.reference;
      const payment = await PaymentModel.findOne({
        "providerMetadata.paystackRef": reference,
      });
      if (!payment) {
        return res.status(404).json({ message: "Payment not found" });
      }

      if (payment.status !== "confirmed") {
        payment.status = "confirmed";
        payment.providerMetadata.set("paystackData", event.data);
        await payment.save();

        // Log to TransactionLog
        await TransactionLogModel.create({
          paymentId: payment._id,
          schoolId: payment.schoolId,
          action: "payment_confirmed",
          metadata: {
            ip: req.ip,
            deviceInfo: req.headers["user-agent"],
            studentId: payment.studentId,
          },
        });

        // Log to AuditLog
        await logActionUtil({
          entityType: "Payment",
          entityId: payment._id,
          action: "payment_confirmed",
          actor: null,
          actorType: "system",
          metadata: {
            ip: req.ip,
            deviceInfo: req.headers["user-agent"],
            studentId: payment.studentId,
            paystackRef: reference,
          },
        });

        // Generate invoice
        await createInvoice(
          { body: { paymentId: payment._id } },
          {
            status: (code) => ({ json: (data) => ({ code, data }) }),
          }
        );

        // Update fee assignment status
        await updateFeeAssignmentStatus({ paymentId: payment._id });
      }

      res.status(200).json({ message: "Webhook processed successfully" });
    } else if (event.event === "charge.failed") {
      const reference = event.data.reference;
      const payment = await PaymentModel.findOne({
        "providerMetadata.paystackRef": reference,
      });
      if (!payment) {
        return res.status(404).json({ message: "Payment not found" });
      }

      payment.status = "rejected";
      await payment.save();

      // Log to TransactionLog
      await TransactionLogModel.create({
        paymentId: payment._id,
        schoolId: payment.schoolId,
        action: "payment_rejected",
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers["user-agent"],
          studentId: payment.studentId,
        },
      });

      // Log to AuditLog
      await logActionUtil({
        entityType: "Payment",
        entityId: payment._id,
        action: "payment_rejected",
        actor: null,
        actorType: "system",
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers["user-agent"],
          studentId: payment.studentId,
          paystackRef: reference,
        },
      });

      res.status(200).json({ message: "Webhook processed successfully" });
    } else {
      res.status(200).json({ message: "Webhook event ignored" });
    }
  } catch (error) {
    console.error("Error processing webhook:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
