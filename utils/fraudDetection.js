import axios from 'axios';
import TransactionLogModel from '../models/TransactionLog.js';
import FraudCheckQueueModel from '../models/FraudCheckQueue.js';
import PaymentModel from '../models/Payment.js';
import StudentModel from '../models/Student.js';
import FeeAssignmentModel from '../models/FraudLog.js';

const ANOMALY_API_URL = 'https://fps-anomaly-api.onrender.com/predict';

const mapStudentType = (studentType) => {
  const universityTypes = ['Full-time', 'Part-time', 'Foreign'];
  return universityTypes.includes(studentType) ? 'university' : 'middle';
};

const mapPaymentMethod = (paymentProvider) => {
  return paymentProvider === 'Paystack' ? 'Mobile Money' : 'Bank';
};

export const checkFraud = async (payment, req, session) => {
  try {
    const student = await StudentModel.findById(payment.studentId).session(session);
    if (!student) throw new Error('Student not found');

    const feeAssignment = await FeeAssignmentModel.findOne({
      feeId: payment.feeId,
      studentId: payment.studentId,
    }).session(session);
    if (!feeAssignment) throw new Error('Fee assignment not found');

    // Check for previous device info
    const lastTransaction = await TransactionLogModel.findOne({
      studentId: payment.studentId,
      action: { $in: ['payment_initiated', 'payment_confirmed'] },
    }).sort({ createdAt: -1 });
    const isNewDevice = !lastTransaction || lastTransaction.metadata.deviceInfo !== req.headers['user-agent'];

    // Calculate time since last payment
    const lastPayment = await PaymentModel.findOne({
      studentId: payment.studentId,
      status: 'confirmed',
    }).sort({ createdAt: -1 });
    const timeSinceLastPaymentDays = lastPayment
      ? Math.floor((Date.now() - new Date(lastPayment.createdAt)) / (1000 * 60 * 60 * 24))
      : 30;

    const requestData = {
      fee_amount_due: feeAssignment.amountDue,
      amount_paid: payment.amount,
      payment_method: mapPaymentMethod(payment.paymentProvider),
      student_type: mapStudentType(student.registrationInfo.studentType || 'Full-time'),
      is_new_device: isNewDevice,
      student_name_match: true, // Default since providerMetadata lacks payer name
      time_since_last_payment_days: timeSinceLastPaymentDays,
      timestamp: new Date().toISOString(),
    };

    const response = await axios.post(ANOMALY_API_URL, requestData, {
      headers: { 'Content-Type': 'application/json' },
    });

    const { reconstruction_error, threshold, anomaly_scale } = response.data;

    // Scale reconstruction_error to 0–100
    const fraudScore = Math.min((reconstruction_error / (threshold * 2.5)) * 100, 100);

    // Log API call in TransactionLog
    await TransactionLogModel.create({
      paymentId: payment._id,
      schoolId: payment.schoolId,
      action: 'fraud_check',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        reconstruction_error,
        anomaly_scale,
        requestData,
      },
    }, { session });

    // Log fraud evaluation in FraudLog
    await FraudLogModel.create({
      paymentId: payment._id,
      schoolId: payment.schoolId,
      action: 'fraud_evaluated',
      reconstruction_error,
      anomaly_scale,
      metadata: { requestData, response: response.data },
    }, { session });

    return { fraudScore, anomaly_scale };
  } catch (error) {
    // Log error in TransactionLog
    await TransactionLogModel.create({
      paymentId: payment._id,
      schoolId: payment.schoolId,
      action: 'fraud_check_error',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        error: error.message,
      },
    }, { session });

    // Queue for retry
    await FraudCheckQueueModel.create({
      paymentId: payment._id,
      schoolId: payment.schoolId,
      requestData: {
        fee_amount_due: feeAssignment?.amountDue || 0,
        amount_paid: payment.amount,
        payment_method: mapPaymentMethod(payment.paymentProvider),
        student_type: mapStudentType(student?.registrationInfo.studentType || 'Full-time'),
        is_new_device: isNewDevice || true,
        student_name_match: true,
        time_since_last_payment_days: timeSinceLastPaymentDays || 30,
        timestamp: new Date().toISOString(),
      },
      status: 'queued',
      retries: 0,
    }, { session });

    return { fraudScore: 0, anomaly_scale: 'Low' }; // Fallback
  }
};