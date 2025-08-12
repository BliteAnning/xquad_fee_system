import mongoose from "mongoose";

const feeSchema = new mongoose.Schema(
  {
    schoolId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "School",
      required: true,
    },
    feeType: { type: String, required: true, trim: true }, // e.g., "Tuition", "Hostel"
    amount: { type: Number, required: true, min: 0 },
    dueDate: { type: Date, required: true },
    academicSession: { type: String, required: true, trim: true },
    allowPartialPayment: { type: Boolean, default: true },
    description: { type: String, trim: true },
  },
  { timestamps: true }
);

// Indexes
feeSchema.index({ schoolId: 1, academicSession: 1 });

const FeeModel = mongoose.models.Fee || mongoose.model("Fee", feeSchema);

export default FeeModel;
