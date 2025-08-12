import mongoose from "mongoose";

const studentRefreshTokenSchema = new mongoose.Schema(
  {
    studentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Student",
      required: true,
    },
    token: { type: String, required: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true }
);

studentRefreshTokenSchema.index({ studentId: 1, expiresAt: 1 });

const StudentRefreshTokenModel =
  mongoose.models.StudentRefreshToken ||
  mongoose.model("StudentRefreshToken", studentRefreshTokenSchema);

export default StudentRefreshTokenModel;