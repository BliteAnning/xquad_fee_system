import mongoose from 'mongoose';

const invoiceSchema = new mongoose.Schema(
  {
    invoiceNumber: { type: String, required: true, unique: true },
    paymentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Payment',
      required: true,
    },
    studentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Student',
      required: true,
    },
    schoolId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'School',
      required: true,
    },
    feeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Fee',
      required: true,
    },
    amount: { type: Number, required: true, min: 0 },
    tax: { type: Number, default: 0, min: 0 },
    totalAmount: { type: Number, required: true, min: 0 },
    status: {
      type: String,
      enum: ['issued', 'paid', 'void'],
      default: 'issued',
    },
    branding: {
      logoUrl: { type: String },
      primaryColor: { type: String, default: '#000000' },
    },
    feeBreakdown: [{
      feeType: { type: String, required: true },
      amount: { type: Number, required: true, min: 0 },
      description: { type: String, trim: true },
    }],
    paymentInfo: {
      paymentProvider: { type: String, required: true },
      providerReference: { type: String, required: true },
      paymentDate: { type: Date, required: true },
    },
    pdfUrl: { type: String, required: true }, // URL or path to stored PDF
  },
  { timestamps: true }
);

// Generate unique invoice number (e.g., INV-schoolId-timestamp)
invoiceSchema.pre('save', async function (next) {
  if (!this.invoiceNumber) {
    const timestamp = Date.now();
    this.invoiceNumber = `INV-${this.schoolId}-${timestamp}`;
  }
  next();
});

// Indexes for efficient querying
invoiceSchema.index({ invoiceNumber: 1 });
invoiceSchema.index({ paymentId: 1, schoolId: 1 });

const InvoiceModel = mongoose.models.Invoice || mongoose.model('Invoice', invoiceSchema);

export default InvoiceModel;