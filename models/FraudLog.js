import mongoose from 'mongoose';

const fraudLogSchema = new mongoose.Schema({
  paymentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Payment', required: true },
  schoolId: { type: mongoose.Schema.Types.ObjectId, ref: 'School', required: true },
  action: { type: String, required: true, default: 'fraud_evaluated' },
  reconstruction_error: { type: Number, required: true },
  anomaly_scale: { type: String, enum: ['Low', 'Medium', 'High'], required: true },
  metadata: { type: Map, of: String, default: {} },
}, { timestamps: true });

fraudLogSchema.index({ paymentId: 1, schoolId: 1 });
fraudLogSchema.index({ anomaly_scale: 1 });

const FraudLogModel = mongoose.models.FraudLog || mongoose.model('FraudLog', fraudLogSchema);

export default FraudLogModel;