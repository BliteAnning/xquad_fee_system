// models/RefreshToken.js
import mongoose from "mongoose";

const refreshTokenSchema = new mongoose.Schema(
  {
    schoolId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "School",
      required: true,
    },
    token: { type: String, required: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true }
);

refreshTokenSchema.index({ schoolId: 1, expiresAt: 1 });

const RefreshTokenModel =
  mongoose.models.RefreshToken ||
  mongoose.model("RefreshToken", refreshTokenSchema);

export default RefreshTokenModel;
