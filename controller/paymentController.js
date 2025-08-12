import https from 'https';
import PaymentModel from '../models/Payment.js';
import FeeModel from '../models/Fee.js';
import SchoolModel from '../models/School.js';
import TransactionLogModel from '../models/TransactionLog.js';
import { logActionUtil } from './auditController.js';
import { createInvoice } from './invoiceController.js';
import { updateFeeAssignmentStatus } from './feeAssignController.js';
import axios from 'axios';

const PAYSTACK_BASE_URL = 'api.paystack.co';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

export const initializePayment = async (req, res) => {
  try {
    const { feeId, amount } = req.body;
    const studentId = req.user.id; // From authenticateStudent middleware

    // Validate fee
    const fee = await FeeModel.findById(feeId);
    if (!fee) {
      return res.status(404).json({ message: 'Fee not found' });
    }

    // Check partial payment
    if (amount < fee.amount && !fee.allowPartialPayment) {
      return res.status(400).json({ message: 'Partial payments not allowed for this fee' });
    }

    // Validate amount
    if (amount <= 0) {
      return res.status(400).json({ message: 'Amount must be greater than 0' });
    }

    // Get school for Paystack API key
    const school = await SchoolModel.findById(fee.schoolId);
    if (!school) {
      return res.status(404).json({ message: 'School not found' });
    }

    const paystackProvider = school.paymentProviders.find(p => p.provider === 'Paystack');
    if (!paystackProvider) {
      return res.status(400).json({ message: 'Paystack not configured for this school' });
    }

    const schoolId = fee.schoolId;

    // Create payment record
    const payment = new PaymentModel({
      studentId,
      schoolId,
      feeId,
      amount,
      paymentProvider: 'Paystack',
      status: 'initiated',
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
      path: '/transaction/initialize',
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + process.env.PAYSTACK_SECRET_KEY,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(params),
      },
    };

    const paystackRequest = await new Promise((resolve, reject) => {
      const req = https.request(options, (response) => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (error) {
            reject(error);
          }
        });
      });
      req.on('error', (error) => reject(error));
      req.write(params);
      req.end();
    });

    if (!paystackRequest.status) {
      return res.status(500).json({ message: 'Paystack initialization failed', error: paystackRequest.message });
    }

    payment.providerMetadata.set('paystackRef', paystackRequest.data.reference);
    await payment.save();

    // Log to TransactionLog
    await TransactionLogModel.create({
      paymentId: payment._id,
      schoolId: payment.schoolId,
      action: 'payment_initiated',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        studentId,
      },
    });

    // Log to AuditLog
    await logActionUtil({
      entityType: 'Payment',
      entityId: payment._id,
      action: 'payment_initiated',
      actor: studentId,
      actorType: 'student',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        studentId,
        feeId,
        amount,
        paystackRef: paystackRequest.data.reference,
      },
    });

    res.status(200).json({
      message: 'Payment initialized successfully',
      paymentUrl: paystackRequest.data.authorization_url,
      payment,
    });
  } catch (error) {
    console.error('Error initializing payment:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Verify Payment (called after Paystack callback)
export const verifyPayment = async (req, res) => {
  try {
    const { reference } = req.query;
    const payment = await PaymentModel.findOne({ 'providerMetadata.paystackRef': reference });
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }

    
    

    const response = await axios.get(`https://${PAYSTACK_BASE_URL}/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer`+ process.env.PAYSTACK_SECRET_KEY },
    });

    if (response.data.status && response.data.data.status === 'success') {
      payment.status = 'confirmed';
      payment.providerMetadata.set('paystackData', response.data.data);
      await payment.save();

      // Log to TransactionLog
      await TransactionLogModel.create({
        paymentId: payment._id,
        schoolId: payment.schoolId,
        action: 'payment_confirmed',
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          studentId: payment.studentId,
        },
      });

      // Log to AuditLog
      await logActionUtil({
        entityType: 'Payment',
        entityId: payment._id,
        action: 'payment_confirmed',
        actor: payment.schoolId,
        actorType: 'admin',
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          studentId: payment.schoolId,
          paystackRef: reference,
        },
      });

      // Generate invoice
      await createInvoice({ body: { paymentId: payment._id } }, {
        status: (code) => ({ json: (data) => ({ code, data }) }),
      });

      // Update fee assignment status
      await updateFeeAssignmentStatus({ paymentId: payment._id });

      res.status(200).json({ message: 'Payment verified successfully', payment });
    } else {
      payment.status = 'rejected';
      await payment.save();

      // Log to AuditLog
      await logActionUtil({
        entityType: 'Payment',
        entityId: payment._id,
        action: 'payment_rejected',
        actor: null,
        actorType: 'system',
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          studentId: payment.studentId,
          paystackRef: reference,
        },
      });

      res.status(400).json({ message: 'Payment verification failed', error: response.data.message });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Handle Paystack Webhook
export const handleWebhook = async (req, res) => {
  try {
    const event = req.body;

    if (event.event === 'charge.success') {
      const reference = event.data.reference;
      const payment = await PaymentModel.findOne({ 'providerMetadata.paystackRef': reference });
      if (!payment) {
        return res.status(404).json({ message: 'Payment not found' });
      }

      if (payment.status !== 'confirmed') {
        payment.status = 'confirmed';
        payment.providerMetadata.set('paystackData', event.data);
        await payment.save();

        // Log to TransactionLog
        await TransactionLogModel.create({
          paymentId: payment._id,
          schoolId: payment.schoolId,
          action: 'payment_confirmed',
          metadata: {
            ip: req.ip,
            deviceInfo: req.headers['user-agent'],
            studentId: payment.studentId,
          },
        });

        // Log to AuditLog
        await logActionUtil({
          entityType: 'Payment',
          entityId: payment._id,
          action: 'payment_confirmed',
          actor: null,
          actorType: 'system',
          metadata: {
            ip: req.ip,
            deviceInfo: req.headers['user-agent'],
            studentId: payment.studentId,
            paystackRef: reference,
          },
        });

        // Generate invoice
        await createInvoice({ body: { paymentId: payment._id } }, {
          status: (code) => ({ json: (data) => ({ code, data }) }),
        });

        // Update fee assignment status
        await updateFeeAssignmentStatus({ paymentId: payment._id });
      }

      res.status(200).json({ message: 'Webhook processed successfully' });
    } else if (event.event === 'charge.failed') {
      const reference = event.data.reference;
      const payment = await PaymentModel.findOne({ 'providerMetadata.paystackRef': reference });
      if (!payment) {
        return res.status(404).json({ message: 'Payment not found' });
      }

      payment.status = 'rejected';
      await payment.save();

      // Log to TransactionLog
      await TransactionLogModel.create({
        paymentId: payment._id,
        schoolId: payment.schoolId,
        action: 'payment_rejected',
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          studentId: payment.studentId,
        },
      });

      // Log to AuditLog
      await logActionUtil({
        entityType: 'Payment',
        entityId: payment._id,
        action: 'payment_rejected',
        actor: null,
        actorType: 'system',
        metadata: {
          ip: req.ip,
          deviceInfo: req.headers['user-agent'],
          studentId: payment.studentId,
          paystackRef: reference,
        },
      });

      res.status(200).json({ message: 'Webhook processed successfully' });
    } else {
      res.status(200).json({ message: 'Webhook event ignored' });
    }
  } catch (error) {
    console.error('Error processing webhook:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};