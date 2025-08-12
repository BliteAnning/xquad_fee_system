// models/School.js
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const schoolSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true },
  contactDetails: {
    phone: { type: String, trim: true },
    address: { type: String, trim: true },
  },
  customFields: {
    feeStructure: { type: Map, of: String, default: {} },
    receiptBranding: {
      logoUrl: { type: String },
      primaryColor: { type: String, default: '#000000' },
    },
  },
  paymentProviders: [{
    provider: { type: String, enum: ['Paystack', 'Flutterwave', 'Payswitch'], default: 'Paystack' },
    apiKey: { type: String },
    priority: { type: Number, default: 1 },
  }],
  students: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Student' }], 
  isVerified: { type: Boolean, default: false },
  otp: { type: String, default: null },
  otpExpires: { type: Date, default: null },
}, { timestamps: true });

schoolSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

schoolSchema.index({ email: 1 });

const SchoolModel = mongoose.models.School || mongoose.model('School', schoolSchema);

export default SchoolModel;