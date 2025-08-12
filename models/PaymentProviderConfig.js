import mongoose from "mongoose";

// Defining the schema for payment provider configurations
const paymentProviderConfigSchema = new mongoose.Schema({
  provider: {
    type: String,
    enum: ["Paystack", "Flutterwave", "Payswitch"], // Restrict to supported providers
    required: true,
  },
  apiKey: {
    type: String,
    required: true,
    // sensitive: true, // Optional: Mark as sensitive for potential future encryption
  },
  isActive: {
    type: Boolean,
    default: true, // Only active providers can be assigned
  },
  createdAt: {
    type: Date,
    default: Date.now, // Track when the config was created
  },
});

// Create index for faster queries by provider and isActive
paymentProviderConfigSchema.index({ provider: 1, isActive: 1 });

// Export the model, reusing existing model if already defined
const PaymentProviderConfig = mongoose.models.PaymentProviderConfig || mongoose.model("PaymentProviderConfig", paymentProviderConfigSchema);

export default PaymentProviderConfig;