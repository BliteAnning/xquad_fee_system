// models/Student.js
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const studentSchema = new mongoose.Schema(
  {
    schoolId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'School',
      required: true,
    },
    email: { type: String, required: true, trim: true, lowercase: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String, trim: true },
    studentId: { type: String, required: true, trim: true }, // School-specific uniqueness
    name: { type: String, required: true, trim: true },
    department: {
      type: String,
      required: true,
      trim: true,
      enum: ['Computer Science', 'Engineering', 'Business', 'Arts', 'Sciences', 'Medicine'], // Example departments
    },
    yearOfStudy: {
      type: String,
      required: true,
      enum: ['Freshman', 'Sophomore', 'Junior', 'Senior'],
    },
    registrationInfo: {
      type: Map,
      of: String,
      default: {
        enrollmentDate: '',
        program: '',
        emergencyContact: '',
        studentType: '', // e.g., Full-time, Part-time
        guardianName: '',
      },
    },
    courses: [{
      type: String,
      enum: ['CS101', 'ENG201', 'BUS301', 'ART101', 'SCI201', 'MED101'], // Example course codes
    }],
  },
  { timestamps: true }
);

studentSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Composite index for school-specific studentId uniqueness
studentSchema.index({ schoolId: 1, studentId: 1 }, { unique: true });
studentSchema.index({ email: 1 });

const StudentModel = mongoose.models.Student || mongoose.model('Student', studentSchema);

export default StudentModel;