import mongoose from 'mongoose';

const refundSchema = new mongoose.Schema({
  paymentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Payment', required: true },
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Student', required: true },
  schoolId: { type: mongoose.Schema.Types.ObjectId, ref: 'School', required: true },
  amount: { type: Number, required: true, min: 0 },
  status: {
    type: String,
    enum: ['requested', 'approved', 'rejected', 'processed'],
    default: 'requested',
  },
  reason: { type: String, required: true, trim: true },
  fraudScore: { type: Number, default: 0, min: 0, max: 100 },
  auditTrail: [{
    action: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    metadata: { type: Map, of: String },
  }],
}, { timestamps: true });

refundSchema.index({ paymentId: 1, schoolId: 1, status: 1 });

const RefundModel = mongoose.models.Refund || mongoose.model('Refund', refundSchema);

export default RefundModel;