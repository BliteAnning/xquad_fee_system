import mongoose from 'mongoose';

const auditLogSchema = new mongoose.Schema(
  {
    entityType: {
      type: String,
      required: true,
      // enum: ['Payment', 'Refund', 'Invoice', 'Fee', 'Student', 'School',"FeeAssignment"],
    },
    entityId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      refPath: 'entityType',
    },
    action: {
      type: String,
      required: true,
      // enum: [
      //   'payment_initiated',
      //   'payment_confirmed',
      //   'payment_rejected',
      //   'payment_expired',
      //   'invoice_generated',
      //   'refund_requested',
      //   'refund_approved',
      //   'refund_rejected',
      //   'refund_processed',
      //   'student_created',
      //   'school_updated',
      //   'fee_assigned',
      //   'fee_created',
      //   'fee_updated',
      //   'dashboard_accessed',
      //   'fees_viewed',
      //   'fee_deleted'
      // ],
    },
    actorType: {
      type: String,
      enum: ['student', 'admin', 'system',],
      required: true,
    },
    actor: {
      type: mongoose.Schema.Types.ObjectId,
      refPath: 'actorRefModel', // Use a computed field for refPath
      required: function () {
        return this.actorType === 'admin' || this.actorType === 'student';
      },
    },
    actorRefModel: {
      type: String,
      required: true,
      enum: ['Student', 'School'],
      default: function () {
        return this.actorType === 'student' ? 'Student' : 'School';
      },
    },
    metadata: {
      ip: { type: String },
      deviceInfo: { type: String },
      deviceId: { type: String },
      additionalInfo: { type: Map, of: String },
    },
  },
  { timestamps: true }
);

// Indexes for efficient querying
auditLogSchema.index({ entityType: 1, entityId: 1 });
auditLogSchema.index({ actorType: 1, actor: 1 });
auditLogSchema.index({ action: 1, createdAt: 1 });

// Validate actorType and actor combination
auditLogSchema.pre('validate', async function (next) {
  if (this.actorType === 'student') {
    this.actorRefModel = 'Student';
    if (!this.actor || !(await mongoose.model('Student').exists({ _id: this.actor }))) {
      return next(new Error('Invalid student actor'));
    }
  } else if (this.actorType === 'admin') {
    this.actorRefModel = 'School';
    if (!this.actor || !(await mongoose.model('School').exists({ _id: this.actor }))) {
      return next(new Error('Invalid admin actor'));
    }
  } else if (this.actorType === 'system') {
    this.actor = null;
    this.actorRefModel = null;
  } else {
    return next(new Error('Invalid actorType'));
  }
  next();
});

const AuditLogModel = mongoose.models.AuditLog || mongoose.model('AuditLog', auditLogSchema);

export default AuditLogModel;