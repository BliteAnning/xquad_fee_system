import mongoose from 'mongoose';
import moment from 'moment';
import FeeAssignmentModel from '../models/feeAssignmentModel.js';
import NotificationModel from '../models/Notification.js';
import FeeModel from '../models/Fee.js';
import StudentModel from '../models/Student.js';
import TransactionLogModel from '../models/TransactionLog.js';
import { logActionUtil } from './auditController.js';
import { sendFeeAssignmentEmail } from '../utils/email.js';
import AuditLogModel from '../models/AuditTrail.js';

// Create Fee (admin-only)
export const createFee = async (req, res) => {
  try {
    const { feeType, amount, dueDate, academicSession, allowPartialPayment, description } = req.body;
    const schoolId = req.user.id; // From authenticateSchool middleware

    // Validate input
    if (!feeType || !amount || !dueDate || !academicSession) {
      return res.status(400).json({ message: 'feeType, amount, dueDate, and academicSession are required' });
    }
    if (amount < 0) {
      return res.status(400).json({ message: 'Amount must be non-negative' });
    }
    if (new Date(dueDate) <= new Date()) {
      return res.status(400).json({ message: 'Due date must be in the future' });
    }

    // Create fee
    const fee = new FeeModel({
      schoolId,
      feeType,
      amount,
      dueDate,
      academicSession,
      allowPartialPayment: allowPartialPayment ?? true,
      description,
    });

    await fee.save();

    // Log to TransactionLog
    await TransactionLogModel.create({
      schoolId,
      action: 'fee_created',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        adminId: schoolId,
        feeId: fee._id,
        feeType,
        amount,
        academicSession,
      },
    });

    // Log to AuditLog
    await logActionUtil({
      entityType: 'Fee',
      entityId: fee._id,
      action: 'fee_created',
      actor: schoolId,
      actorType: 'admin',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        adminId: schoolId,
        feeType,
        amount,
        academicSession,
      },
    });

    res.status(201).json({ message: 'Fee created successfully', fee });
  } catch (error) {
    console.error('Error creating fee:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Create Fee Assignment (admin-only)
export const createFeeAssignment = async (req, res) => {
  let session = null;
  try {
    session = await mongoose.startSession();
    session.startTransaction();

    const { feeId, department, yearOfStudy } = req.body;
    const adminId = req.user.id;
    const clientIp = req.headers['x-forwarded-for'] || req.ip;

    // Validate inputs
    if (!feeId || !mongoose.isValidObjectId(feeId)) {
      throw Object.assign(new Error('Invalid or missing feeId'), { statusCode: 400 });
    }
    if (req.body.studentId) {
      throw Object.assign(new Error('Individual student assignments are not supported'), { statusCode: 400 });
    }
    if (!department && !yearOfStudy) {
      throw Object.assign(new Error('At least one of department or yearOfStudy must be provided'), { statusCode: 400 });
    }

    // Validate fee
    const fee = await FeeModel.findById(feeId).session(session);
    if (!fee) {
      throw Object.assign(new Error('Fee not found'), { statusCode: 404 });
    }
    if (fee.schoolId.toString() !== adminId.toString()) {
      throw Object.assign(new Error('Unauthorized: Fee does not belong to this school'), { statusCode: 403 });
    }

    // Basic fraud check (velocity: max 10 assignments per hour per school)
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recentAssignments = await FeeAssignmentModel.countDocuments({
      schoolId: adminId,
      createdAt: { $gte: oneHourAgo },
    }).session(session);
    if (recentAssignments > 10) {
      throw Object.assign(new Error('Too many fee assignments in the last hour'), { statusCode: 429 });
    }

    // Group assignment
    const validDepartments = ['Computer Science', 'Engineering', 'Business', 'Arts', 'Sciences', 'Medicine', ''];
    const validYears = ['Freshman', 'Sophomore', 'Junior', 'Senior', ''];
    if (department && !validDepartments.includes(department)) {
      throw Object.assign(new Error(`Invalid department. Must be one of: ${validDepartments.join(', ')}`), { statusCode: 400 });
    }
    if (yearOfStudy && !validYears.includes(yearOfStudy)) {
      throw Object.assign(new Error(`Invalid year of study. Must be one of: ${validYears.join(', ')}`), { statusCode: 400 });
    }

    const query = { schoolId: fee.schoolId };
    if (department) query.department = department;
    if (yearOfStudy) query.yearOfStudy = yearOfStudy;

    const students = await StudentModel.find(query).session(session);
    if (students.length === 0) {
      throw Object.assign(new Error('No students found for the given criteria'), { statusCode: 404 });
    }

    const newAssignments = [];
    for (const student of students) {
      const existingAssignment = await FeeAssignmentModel.findOne({
        feeId,
        studentId: student._id,
        schoolId: adminId,
      }).session(session);
      if (existingAssignment) {
        console.log(`Skipping duplicate assignment for student ${student.studentId}`);
        continue;
      }

      newAssignments.push({
        feeId,
        schoolId: fee.schoolId,
        studentId: student._id,
        groupCriteria: { department, yearOfStudy },
        amountDue: fee.amount,
        status: 'assigned',
      });
    }

    if (newAssignments.length === 0) {
      throw Object.assign(new Error('No new assignments created (all students already assigned)'), { statusCode: 400 });
    }

    const savedAssignments = await FeeAssignmentModel.insertMany(newAssignments, { session });
    const assignments = savedAssignments;

    const transactionLogs = savedAssignments.map((assignment) => ({
      schoolId: fee.schoolId,
      action: 'fee_assigned',
      metadata: {
        ip: clientIp,
        deviceInfo: req.headers['user-agent'],
        adminId,
        feeId,
        studentId: assignment.studentId,
        department,
        yearOfStudy,
      },
    }));

    await TransactionLogModel.insertMany(transactionLogs, { session });

    for (const assignment of savedAssignments) {
      try {
        await logActionUtil({
          entityType: 'FeeAssignment',
          entityId: assignment._id,
          action: 'fee_assigned',
          actor: adminId,
          actorType: 'admin',
          metadata: {
            ip: clientIp,
            deviceInfo: req.headers['user-agent'],
            adminId,
            feeId,
            studentId: assignment.studentId,
            department,
            yearOfStudy,
          },
          session,
        });
      } catch (auditError) {
        console.error('Non-critical audit log error:', {
          event: 'audit_failure',
          error: auditError.message,
          timestamp: new Date().toISOString(),
        });
      }
    }

    for (const student of students) {
      try {
        await sendFeeAssignmentEmail(student, fee, fee.dueDate);
        await NotificationModel.create(
          [{
            recipient: student.email,
            type: 'fee_assigned',
            message: `Fee ${fee.feeType} assigned to ${student.name}`,
            schoolId: adminId,
            studentId: student._id,
            status: 'sent',
            sentAt: new Date(),
          }],
          { session }
        );
      } catch (notificationError) {
        console.error('Non-critical notification error:', {
          event: 'notification_failure',
          error: notificationError.message,
          email: student.email,
          timestamp: new Date().toISOString(),
        });
      }
    }

    await session.commitTransaction();

    return res.status(201).json({
      success: true,
      message: 'Fee assignment created successfully',
      data: assignments,
    });
  } catch (error) {
    if (session && session.inTransaction()) {
      await session.abortTransaction();
    }
    console.error('Error creating fee assignment:', {
      event: 'fee_assignment_error',
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      adminId: req.user?.id,
      feeId: req.body?.feeId,
    });
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || 'Server error',
      ...(process.env.NODE_ENV === 'development' && { error: error.message }),
    });
  } finally {
    if (session) {
      await session.endSession();
    }
  }
};



export const getStudentFeeAssignments = async (req, res) => {
  let session = null;
  try {
    session = await mongoose.startSession();
    session.startTransaction();

    const studentId = req.user.id;
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    const { status, page = 1, limit = 10 } = req.query;

    if (!studentId || !mongoose.isValidObjectId(studentId)) {
      throw Object.assign(new Error('Invalid or missing student ID'), { statusCode: 401 });
    }

    const student = await StudentModel.findById(studentId).session(session);
    if (!student) {
      throw Object.assign(new Error('Student not found'), { statusCode: 404 });
    }

    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recentAccesses = await AuditLogModel.countDocuments({
      actorType: 'student',
      actor: studentId,
      action: 'dashboard_accessed',
      createdAt: { $gte: oneHourAgo },
    }).session(session);
    if (recentAccesses > 20) {
      throw Object.assign(new Error('Too many dashboard accesses in the last hour'), { statusCode: 429 });
    }

    const query = { studentId };
    if (status) {
      if (!['assigned', 'partially_paid', 'fully_paid', 'overdue'].includes(status)) {
        throw Object.assign(new Error('Invalid status filter'), { statusCode: 400 });
      }
      query.status = status;
    }

    const assignments = await FeeAssignmentModel.find(query)
      .select('feeId schoolId status amountDue amountPaid groupCriteria createdAt updatedAt')
      .populate({
        path: 'feeId',
        select: 'feeType amount description academicSession allowPartialPayment dueDate',
      })
      .populate({
        path: 'schoolId',
        select: 'name customFields.receiptBranding',
      })
      .sort({ 'feeId.dueDate': 1, createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit))
      .session(session);

    for (const assignment of assignments) {
      if (!assignment.feeId || !assignment.schoolId) {
        console.warn('Invalid assignment data:', {
          event: 'invalid_assignment',
          assignmentId: assignment._id,
          feeId: assignment.feeId,
          schoolId: assignment.schoolId,
          timestamp: new Date().toISOString(),
        });
        throw Object.assign(new Error('Invalid assignment data: missing fee or school'), { statusCode: 500 });
      }
      if (assignment.schoolId._id.toString() !== student.schoolId.toString()) {
        console.warn('Unauthorized assignment access:', {
          event: 'unauthorized_assignment',
          studentId,
          assignmentId: assignment._id,
          schoolId: assignment.schoolId._id,
          timestamp: new Date().toISOString(),
        });
        throw Object.assign(new Error('Unauthorized access to assignment'), { statusCode: 403 });
      }
    }

    try {
      await logActionUtil({
        entityType: 'FeeAssignment',
        entityId: null,
        action: 'dashboard_accessed',
        actor: studentId,
        actorType: 'student',
        metadata: {
          ip: clientIp,
          deviceInfo: req.headers['user-agent'],
          studentId,
          page,
          limit,
          statusFilter: status || 'none',
        },
        session,
      });
    } catch (auditError) {
      console.error('Non-critical audit log error:', {
        event: 'audit_failure',
        error: auditError.message,
        timestamp: new Date().toISOString(),
      });
    }

    try {
      await NotificationModel.create(
        [{
          recipient: student.email,
          type: 'dashboard_accessed',
          message: `Student ${student.name} accessed fee assignments`,
          schoolId: student.schoolId,
          studentId: student._id,
          status: 'sent',
          sentAt: new Date(),
        }],
        { session }
      );
    } catch (notificationError) {
      console.error('Non-critical notification error:', {
        event: 'notification_failure',
        error: notificationError.message,
        email: student.email,
        timestamp: new Date().toISOString(),
      });
    }

    await session.commitTransaction();

    if (!assignments || assignments.length === 0) {
      return res.status(200).json({
        success: true,
        message: 'No fee assignments found',
        data: [],
        pagination: { page: parseInt(page), limit: parseInt(limit), total: 0 },
      });
    }

    const total = await FeeAssignmentModel.countDocuments(query).session(session);

    return res.status(200).json({
      success: true,
      message: 'Fee assignments retrieved successfully',
      data: assignments,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
      },
    });
  } catch (error) {
    if (session && session.inTransaction()) {
      await session.abortTransaction();
    }
    console.error('Error retrieving fee assignments:', {
      event: 'fee_assignments_retrieval_error',
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      studentId: req.user?.id,
    });
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || 'Server error',
      ...(process.env.NODE_ENV === 'development' && { error: error.message }),
    });
  } finally {
    if (session) {
      await session.endSession();
    }
  }
};

// Update Fee Assignment Status (called by system after payment confirmation)
export const updateFeeAssignmentStatus = async ({ paymentId }) => {
  try {
    const payment = await PaymentModel.findById(paymentId).populate('feeId');
    if (!payment || payment.status !== 'confirmed') {
      throw new Error('Payment not found or not confirmed');
    }

    const assignment = await FeeAssignmentModel.findOne({
      feeId: payment.feeId,
      studentId: payment.studentId,
    });

    if (!assignment) {
      throw new Error('Fee assignment not found');
    }

    assignment.amountPaid += payment.amount;
    assignment.status = assignment.amountPaid >= assignment.amountDue ? 'fully_paid' : 'partially_paid';
    await assignment.save();

    // Log to TransactionLog
    await TransactionLogModel.create({
      paymentId,
      schoolId: payment.schoolId,
      action: 'fee_assignment_updated',
      metadata: {
        studentId: payment.studentId,
        feeId: payment.feeId,
        amountPaid: assignment.amountPaid,
        status: assignment.status,
      },
    });

    // Log to AuditLog (system action)
    await logActionUtil({
      entityType: 'FeeAssignment',
      entityId: assignment._id,
      action: 'fee_assignment_updated',
      actor: null,
      actorType: 'system',
      metadata: {
        studentId: payment.studentId,
        feeId: payment.feeId,
        amountPaid: assignment.amountPaid,
        status: assignment.status,
      },
    });

    return assignment;
  } catch (error) {
    console.error('Error updating fee assignment status:', error);
    throw error;
  }
};