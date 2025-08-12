// models/TransactionLog.js
import mongoose from 'mongoose';

const transactionLogSchema = new mongoose.Schema({
  paymentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Payment' },
  refundId: { type: mongoose.Schema.Types.ObjectId, ref: 'Refund' },
  schoolId: { type: mongoose.Schema.Types.ObjectId, ref: 'School' },
  action: { type: String, required: true },
  metadata: {
    ip: { type: String },
    deviceInfo: { type: String },
    deviceId: { type: String },
    fraudScore: { type: Number, min: 0, max: 100 },
  },
}, { timestamps: true });

// Validation: Ensure at least one of paymentId, refundId, or schoolId is present
// transactionLogSchema.pre('validate', function (next) {
//   if (!this.paymentId && !this.refundId && !this.schoolId) {
//     return next(new Error('At least one of paymentId, refundId, or schoolId is required'));
//   }
//   next();
// });

transactionLogSchema.index({ paymentId: 1, refundId: 1, schoolId: 1 });

const TransactionLogModel = mongoose.models.TransactionLog || mongoose.model('TransactionLog', transactionLogSchema);

export default TransactionLogModel;