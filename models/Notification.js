import mongoose from "mongoose";

const notificationSchema = new mongoose.Schema(
  {
    recipient: { type: String, required: true, trim: true },
    type: {
      type: String,
      enum: [
        "payment_success",
        "payment_failure",
        "refund_approved",
        "refund_rejected",
        "fee_due",
        "school_registration",
        "login_failure",
        "student_added",
        "student_added_admin",
        "student_login_success",
        "fee_assigned",
        'dashboard_accessed'
      ],
      required: true,
    },
    message: { type: String, required: true },
    status: {
      type: String,
      enum: ["sent", "failed", "pending"],
      default: "pending",
    },
    sentAt: { type: Date },
    schoolId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "School",
      required: true,
    },
    studentId: { type: mongoose.Schema.Types.ObjectId, ref: "Student" },
    paymentId: { type: mongoose.Schema.Types.ObjectId, ref: "Payment" },
    refundId: { type: mongoose.Schema.Types.ObjectId, ref: "Refund" },
  },
  { timestamps: true }
);

notificationSchema.index({ schoolId: 1, type: 1 });

const NotificationModel =
  mongoose.models.Notification ||
  mongoose.model("Notification", notificationSchema);

export default NotificationModel;
