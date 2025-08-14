import mongoose from 'mongoose';

const fraudCheckQueueSchema = new mongoose.Schema({
  paymentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Payment', required: true },
  schoolId: { type: mongoose.Schema.Types.ObjectId, ref: 'School', required: true },
  requestData: { type: Object, required: true },
  status: { type: String, enum: ['queued', 'processed', 'failed'], default: 'queued' },
  retries: { type: Number, default: 0, min: 0 },
  lastAttempt: { type: Date },
}, { timestamps: true });

fraudCheckQueueSchema.index({ paymentId: 1, status: 1 });

const FraudCheckQueueModel = mongoose.models.FraudCheckQueue || mongoose.model('FraudCheckQueue', fraudCheckQueueSchema);

export default FraudCheckQueueModel;