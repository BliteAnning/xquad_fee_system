import mongoose from 'mongoose';

const receiptSchema = new mongoose.Schema({
    paymentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Payment', required: true },
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Student', required: true },
  schoolId: { type: mongoose.Schema.Types.ObjectId, ref: 'School', required: true },
  receiptNumber: { type: String, required: true, unique: true },
  amount: { type: Number, required: true, min: 0 },
  date: { type: Date, default: Date.now },
  pdfUrl: { type: String, required: true }, // Cloudinary URL
  branding: {
    logoUrl: { type: String },
    primaryColor: { type: String },
  },
}, { timestamps: true });

// Indexes
receiptSchema.index({ paymentId: 1, schoolId: 1 });
receiptSchema.index({ schoolId: 1, receiptNumber: 1 }, { unique: true });

const ReceiptModel = mongoose.models.Receipt || mongoose.model("Receipt", receiptSchema);

export default ReceiptModel;
