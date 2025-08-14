import https from 'https';
import crypto from 'crypto';
import RefundModel from '../models/Refund.js';
import PaymentModel from '../models/Payment.js';
import SchoolModel from '../models/School.js';
import TransactionLogModel from '../models/TransactionLog.js';
import { logActionUtil } from './auditController.js';

const PAYSTACK_BASE_URL = 'api.paystack.co';

// Request Refund (called by student)
export const requestRefund = async (req, res) => {
  try {
    const { paymentId, amount, reason } = req.body;
    const studentId = req.user.id; // From authenticateStudent middleware

    // Validate payment
    const payment = await PaymentModel.findById(paymentId).populate('schoolId');
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }
    if (payment.studentId.toString() !== studentId.toString()) {
      return res.status(403).json({ message: 'Unauthorized: Payment does not belong to this student' });
    }
    /*if (payment.status !== 'confirmed') {
      return res.status(400).json({ message: 'Payment must be confirmed to request a refund' });
    }*/

    // Calculate refundable amount
    const existingRefunds = await RefundModel.find({
      paymentId,
      status: { $in: ['approved', 'processed'] },
    });
    const totalRefunded = existingRefunds.reduce((sum, refund) => sum + refund.amount, 0);
    const refundableAmount = payment.amount - totalRefunded;
    if (amount <= 0 || amount > refundableAmount) {
      return res.status(400).json({ message: `Invalid refund amount. Maximum refundable: ${refundableAmount}` });
    }

    // Placeholder for third-party fraud score service
    const fraudScore = await calculateFraudScore({ paymentId, amount, studentId }); // Implement this function

    // Create refund record
    const refund = new RefundModel({
      paymentId,
      studentId,
      schoolId: payment.schoolId,
      amount,
      reason,
      status: 'requested',
      fraudScore,
      auditTrail: [
        {
          action: 'refund_requested',
          timestamp: new Date(),
          metadata: { ip: req.ip, deviceInfo: req.headers['user-agent'], studentId },
        },
      ],
    });

    await refund.save();

    // Log to TransactionLog
    await TransactionLogModel.create({
      paymentId,
      refundId: refund._id,
      schoolId: payment.schoolId,
      action: 'refund_requested',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        studentId,
        amount,
      },
    });

    // Log to AuditLog (system action, as initiated by student)
    await logActionUtil({
      entityType: 'Refund',
      entityId: refund._id,
      action: 'refund_requested',
      actor: studentId,
      actorType: 'student',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        studentId,
        studentEmail: req.user.email,
        amount,
      },
    });

    res.status(201).json({ message: 'Refund requested successfully', refund });
  } catch (error) {
    console.error('Error requesting refund:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Approve or Reject Refund (called by admin)
export const reviewRefund = async (req, res) => {
  try {
    const { refundId, status } = req.body; // status: 'approved' or 'rejected'
    const adminId = req.user.id; // From authenticateSchool middleware

    // Validate refund
    const refund = await RefundModel.findById(refundId).populate('schoolId');
    if (!refund) {
      return res.status(404).json({ message: 'Refund not found' });
    }
    if (refund.schoolId._id.toString() !== adminId.toString()) {
      return res.status(403).json({ message: 'Unauthorized: Refund does not belong to this school' });
    }
    /*if (refund.status !== 'requested') {
      return res.status(400).json({ message: 'Refund is not in requested status' });
    }*/
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status. Must be approved or rejected' });
    }

    // Update refund status and audit trail
    refund.status = status;
    refund.auditTrail.push({
      action: `refund_${status}`,
      timestamp: new Date(),
      metadata: { ip: req.ip, deviceInfo: req.headers['user-agent'], adminId },
    });
    await refund.save();

    // Log to TransactionLog
    await TransactionLogModel.create({
      paymentId: refund.paymentId,
      refundId: refund._id,
      schoolId: refund.schoolId,
      action: `refund_${status}`,
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        adminId,
        amount: refund.amount,
      },
    });

    // Log to AuditLog (admin action)
    await logActionUtil({
      entityType: 'Refund',
      entityId: refund._id,
      action: `refund_${status}`,
      actor: adminId,
      actorType: 'admin',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        adminId,
        amount: refund.amount,
      },
    });

    // If approved, initiate Paystack refund
    if (status === 'approved') {
      const payment = await PaymentModel.findById(refund.paymentId);
      if (!payment) {
        return res.status(404).json({ message: 'Associated payment not found' });
      }
      if (payment.paymentProvider !== 'Paystack') {
        return res.status(400).json({ message: `Unsupported payment provider: ${payment.paymentProvider}` });
      }
      // Handle both Map and plain object for providerMetadata
      const paystackRef = payment.providerMetadata.get("paystackRef");
      if (!paystackRef) {
        return res.status(400).json({ message: 'Paystack reference not found in payment' });
      }

      const paystackProvider = refund.schoolId.paymentProviders.find(p => p.provider === 'Paystack');
      if (!paystackProvider) {
        return res.status(400).json({ message: 'Paystack not configured for this school' });
      }

      // Initiate Paystack refund
      const params = JSON.stringify({
        transaction: payment.providerMetadata.get('paystackRef'),
        amount: refund.amount * 100, // Paystack expects amount in kobo
      });

      const options = {
        hostname: PAYSTACK_BASE_URL,
        port: 443,
        path: '/refund',
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, // Fixed space after Bearer
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(params),
        },
      };

      const paystackResponse = await new Promise((resolve, reject) => {
        const req = https.request(options, (response) => {
          let data = '';
          response.on('data', (chunk) => {
            data += chunk;
          });
          response.on('end', () => {
            try {
              const result = JSON.parse(data);
              resolve(result);
            } catch (error) {
              reject(error);
            }
          });
        });

        req.on('error', (error) => reject(error));
        req.write(params);
        req.end();
      });
        console.log(`paystackResponse`,paystackResponse);
      // Update refund status to processed if Paystack accepts it
      if (paystackResponse.status === true) {
        refund.status = 'approved';
        refund.auditTrail.push({
          action: 'refund_approved',
          timestamp: new Date(),
          metadata: { ip: req.ip, deviceInfo: req.headers['user-agent'], adminId, paystackRef: payment.providerMetadata.get('paystackRef') },
        });
        await refund.save();

        // Log to TransactionLog
        await TransactionLogModel.create({
          paymentId: refund.paymentId,
          refundId: refund._id,
          schoolId: refund.schoolId,
          action: 'refund_approved',
          metadata: {
            ip: req.ip,
            deviceInfo: req.headers['user-agent'],
            adminId,
            amount: refund.amount,
            paystackRef: payment.providerMetadata.get('paystackRef'),
          },
        });

        // Log to AuditLog
        await logActionUtil({
          entityType: 'Refund',
          entityId: refund._id,
          action: 'refund_approved',
          actor: adminId,
          actorType: 'admin',
          metadata: {
            ip: req.ip,
            deviceInfo: req.headers['user-agent'],
            adminId,
            amount: refund.amount,
            paystackRef: payment.providerMetadata.get('paystackRef'),
          },
        });
        await refund.save();
      } else {
        // Roll back status to approved if Paystack fails
        refund.status = 'failed';
        return res.status(400).json({ message: 'Paystack refund initiation failed', error: paystackResponse.message });
      }

    }

    res.status(200).json({ message: `Refund ${status} successfully`, refund });
  } catch (error) {
    console.error('Error reviewing refund:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Handle Paystack Refund Webhook
export const handleRefundWebhook = async (req, res) => {
  try {
    const event = req.body;
    const signature = req.headers['x-paystack-signature'];
    const paystackSecret = process.env.PAYSTACK_SECRET_KEY;

    // Verify Paystack webhook signature
    const hash = crypto
      .createHmac('sha512', paystackSecret)
      .update(JSON.stringify(event))
      .digest('hex');
    if (hash !== signature) {
      return res.status(401).json({ message: 'Invalid webhook signature' });
    }

    if (event.event === 'refund.processed') {
      const reference = event.data.transaction.reference;
      // Find refund by payment's paystackRef (since Paystack doesn't provide refundId)
      const payment = await PaymentModel.findOne({ 'providerMetadata.paystackRef': reference });
      if (!payment) {
        return res.status(404).json({ message: 'Payment not found' });
      }
      const refund = await RefundModel.findOne({
        paymentId: payment._id,
        status: { $in: ['approved', 'requested'] },
      }).populate('schoolId');
      if (!refund) {
        return res.status(404).json({ message: 'Refund not found' });
      }

      if (refund.status !== 'processed') {
        refund.status = 'processed';
        refund.auditTrail.push({
          action: 'refund_processed',
          timestamp: new Date(),
          metadata: { paystackRef: reference, webhook: true },
        });
        await refund.save();

        // Log to TransactionLog
        await TransactionLogModel.create({
          paymentId: refund.paymentId,
          refundId: refund._id,
          schoolId: refund.schoolId,
          action: 'refund_processed',
          metadata: {
            paystackRef: reference,
            webhook: true,
            studentId: refund.studentId,
          },
        });

        // Log to AuditLog
        await logActionUtil({
          entityType: 'Refund',
          entityId: refund._id,
          action: 'refund_processed',
          actor: null,
          actorType: 'system',
          metadata: {
            paystackRef: reference,
            webhook: true,
            studentId: refund.studentId,
            studentEmail: event.data.customer.email || '',
          },
        });
      }

      res.status(200).json({ message: 'Refund webhook processed successfully' });
    } else if (event.event === 'refund.failed') {
      const reference = event.data.transaction.reference;
      const payment = await PaymentModel.findOne({ 'providerMetadata.paystackRef': reference });
      if (!payment) {
        return res.status(404).json({ message: 'Payment not found' });
      }
      const refund = await RefundModel.findOne({
        paymentId: payment._id,
        status: { $in: ['approved', 'requested'] },
      });
      if (!refund) {
        return res.status(404).json({ message: 'Refund not found' });
      }

      refund.status = 'failed';
      refund.auditTrail.push({
        action: 'refund_failed',
        timestamp: new Date(),
        metadata: { paystackRef: reference, webhook: true },
      });
      await refund.save();

      // Log to TransactionLog
      await TransactionLogModel.create({
        paymentId: refund.paymentId,
        refundId: refund._id,
        schoolId: refund.schoolId,
        action: 'refund_failed',
        metadata: {
          paystackRef: reference,
          webhook: true,
          studentId: refund.studentId,
        },
      });

      // Log to AuditLog
      await logActionUtil({
        entityType: 'Refund',
        entityId: refund._id,
        action: 'refund_failed',
        actor: null,
        actorType: 'system',
        metadata: {
          paystackRef: reference,
          webhook: true,
          studentId: refund.studentId,
          studentEmail: event.data.customer.email || '',
        },
      });

      res.status(200).json({ message: 'Refund webhook processed successfully' });
    } else {
      res.status(200).json({ message: 'Webhook event ignored' });
    }
  } catch (error) {
    console.error('Error processing refund webhook:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Placeholder for third-party fraud score service
const calculateFraudScore = async ({ paymentId, amount, studentId }) => {
  // Implement third-party fraud score integration here
  // Example: const response = await axios.post('https://fraud-service.com/api/score', { paymentId, amount, studentId });
  return 0; // Placeholder: return actual fraud score
};

export const getAllRefunds = async (req, res) => {
  try {
    // Optionally, filter by studentId if needed: { studentId: req.user.id }
    const refunds = await RefundModel.find().populate('paymentId studentId schoolId');
    res.status(200).json({ success: true, refunds });
  } catch (error) {
    console.error('Error fetching refunds:', error);
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
};

export const getStudentRefunds = async (req, res) => {
  try {
    const studentId = req.user.id; // From authenticateStudent middleware
    const refunds = await RefundModel.find({ studentId }).populate('paymentId schoolId');
    res.status(200).json({ success: true, refunds });
  } catch (error) {
    console.error('Error fetching student refunds:', error);
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
};

export const getRefundById = async (req, res) => {
  try {
    const { id } = req.params;
    const refund = await RefundModel.findById(id)
      .populate('paymentId studentId schoolId');
      
    if (!refund) {
      return res.status(404).json({ success: false, message: 'Refund not found' });
    }
    res.status(200).json({ success: true, refund });
  } catch (error) {
    console.error('Error fetching refund:', error);
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
};