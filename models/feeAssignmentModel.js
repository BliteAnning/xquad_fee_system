import mongoose from 'mongoose';

const feeAssignmentSchema = new mongoose.Schema(
  {
    feeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Fee',
      required: true,
    },
    schoolId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'School',
      required: true,
    },
    studentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Student',
      required: false, // Optional for group assignments
    },
    groupCriteria: {
      department: {
        type: String,
        enum: ['Computer Science', 'Engineering', 'Business', 'Arts', 'Sciences', 'Medicine', ''],
        default: '',
      },
      yearOfStudy: {
        type: String,
        enum: ['Freshman', 'Sophomore', 'Junior', 'Senior', ''],
        default: '',
      },
    },
    status: {
      type: String,
      enum: ['assigned', 'partially_paid', 'fully_paid', 'overdue'],
      default: 'assigned',
    },
    amountDue: {
      type: Number,
      required: true,
      min: 0,
    },
    amountPaid: {
      type: Number,
      default: 0,
      min: 0,
    },
  },
  { timestamps: true }
);

// Ensure at least one of studentId or groupCriteria is provided
feeAssignmentSchema.pre('validate', function (next) {
  if (!this.studentId || (!this.groupCriteria.department && !this.groupCriteria.yearOfStudy)) {
    return next(new Error('Either studentId or groupCriteria (department/yearOfStudy) must be provided'));
  }
  next();
});

// Indexes for efficient querying
feeAssignmentSchema.index({ feeId: 1, schoolId: 1 });
feeAssignmentSchema.index({ studentId: 1, status: 1 });
feeAssignmentSchema.index({ 'groupCriteria.department': 1, 'groupCriteria.yearOfStudy': 1 });

const FeeAssignmentModel = mongoose.models.FeeAssignment || mongoose.model('FeeAssignment', feeAssignmentSchema);

export default FeeAssignmentModel;