import mongoose from "mongoose";

const paymentSchema = new mongoose.Schema(
  {
    studentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Student",
      required: true,
    },
    schoolId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "School",
      required: true,
    },
    feeId: { type: mongoose.Schema.Types.ObjectId, ref: "Fee", required: true },
    amount: { type: Number, required: true, min: 0 },
    paymentProvider: {
      type: String,
      enum: ["Paystack", "Flutterwave", "Payswitch"],
      required: true,
    },
    providerMetadata: { type: Map, of: String, default: {} },
    status: {
      type: String,
      enum: ["initiated", "pending", "confirmed", "rejected", "expired"],
      default: "initiated",
    },
    fraudScore: { type: Number, default: 0, min: 0, max: 100 },
    receiptUrl: { type: String },
  },
  { timestamps: true }
);

paymentSchema.index({ schoolId: 1, studentId: 1, status: 1 });
paymentSchema.index({ paymentProvider: 1, "providerMetadata.paystackRef": 1 });

const PaymentModel =
  mongoose.models.Payment || mongoose.model("Payment", paymentSchema);

export default PaymentModel;