import nodemailer from "nodemailer";
import { EMAIL_PASSWORD, SYSTEM_NAME } from "../config/env.js";
import School from "../models/School.js";

export const FROM_EMAIL = /*"kojoameyaw519@gmail.com"*/ process.env.EMAIL_HOST ;

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: FROM_EMAIL,
    pass: EMAIL_PASSWORD,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

export const sendWelcomeEmail = async (school) => {
  const mailOptions = {
    from: FROM_EMAIL,
    to: school.email,
    subject: `Welcome to ${SYSTEM_NAME}, ${school.name}!`,
    html: `
      <h1>Welcome, ${school.name}!</h1>
      <p>Your school has been successfully registered.</p>
      <p>Access the admin portal at: <a href="${process.env.ADMIN_URL}">${process.env.ADMIN_URL}</a></p>
      <p style="color:#1976D2">
        Thank you for joining!
      </p>
      
    `,
  };

  await transporter.sendMail(mailOptions);
};

export const sendFailedLoginEmail = async (user, ip, timestamp) => {
  const school = user.schoolId ? await School.findById(user.schoolId) : user;
  const name = user.name || school.name;
  const email = user.email || school.email;
  const type = user.schoolId ? "student" : "school";
  const mailOptions = {
    from: FROM_EMAIL,
    to: email,
    subject: `Failed Login Attempt for ${SYSTEM_NAME}`,
    html: `
      <h1>Security Alert for ${name}</h1>
      <p>A failed login attempt was detected for your ${type} account.</p>
      <p>Time: ${timestamp.toISOString()}</p>
      <p>IP Address: ${ip}</p>
      <p style="color:#1976D2">
        If this was not you, please secure your account.
      </p>
     
    `,
  };

  await transporter.sendMail(mailOptions);
};

export const sendOtpEmail = async (school, otp) => {
  const mailOptions = {
    from: `"${school.name} Payment System" <${FROM_EMAIL}>`,
    to: school.email,
    subject: `Your OTP for ${SYSTEM_NAME}`,
    html: `
      <h1 style="color: #1976D2">Verify Your Account</h1>
      <p>Your one-time password (OTP) for ${school.name} is:</p>
      <p><strong>${school.otp}</strong></p>
      <p>This OTP expires in 5 minutes.</p>
      <p>Login to verify: <a href="${process.env.ADMIN_CLIENT_URL}/mfa/verify">Verify OTP</a></p>
      
    `,
  };
  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error(`Error sending otp`, error);
    throw new Error(`Error sending otp email: ${error}`);
  }
};

export const sendMfaFailedEmail = async (school, ip, timestamp) => {
  const mailOptions = {
    from: `"${school.name} Payment System" <${FROM_EMAIL}>`,
    to: school.email,
    subject: `Failed MFA Attempt for ${SYSTEM_NAME}`,
    html: `
      <h1 style="color: ${
        school.customFields.receiptBranding.primaryColor
      }">Security Alert</h1>
      <p>A failed MFA attempt was detected for your account.</p>
      <p><strong>Time:</strong> ${timestamp.toISOString()}</p>
      <p><strong>IP Address:</strong> ${ip}</p>
      <p>If this was not you, please secure your account.</p>
      ${
        school.customFields.receiptBranding.logoUrl
          ? `<img src="${school.customFields.receiptBranding.logoUrl}" alt="School Logo" style="max-width: 200px;" />`
          : ""
      }
    `,
  };
  await transporter.sendMail(mailOptions);
};

export const sendStudentWelcomeEmail = async (
  student,
  school,
  plainPassword,
  studentId
) => {
  const mailOptions = {
    from: `"${school.name} Payment System" <${FROM_EMAIL}>`,
    to: student.email,
    subject: `Welcome to ${school.name}`,
    html: `
      <h1 style="color: ${
        school.customFields.receiptBranding.primaryColor
      }">Welcome, ${student.name}!</h1>
      <p>You have been added as a student at ${school.name}.</p>
      <p><strong>Student ID:</strong> ${studentId}</p>
      <p><strong>Email:</strong> ${student.email}</p>
      <p><strong>Password:</strong> ${plainPassword}</p>
      <p style="color: red; font-weight: bold;">
        For security, please reset your password after your first login.
      </p>
      <p><a href="http://localhost:3000/reset-password">Reset Password </a></p>
      <p>Login to view your payment history and courses at: <a href="http://localhost:3000/login">Login</a></p>
      ${
        school.customFields.receiptBranding.logoUrl
          ? `<img src="${school.customFields.receiptBranding.logoUrl}" alt="School Logo" style="max-width: 200px;" />`
          : ""
      }
    `,
  };
  await transporter.sendMail(mailOptions);
};

export const sendAdminStudentAddedEmail = async (school, student) => {
  const mailOptions = {
    from: `"School Payment System" <${FROM_EMAIL}>`,
    to: school.email,
    subject: `New Student Added: ${student.name}`,
    html: `
      <h1>New Student Added</h1>
      <p>A new student has been added to ${school.name}.</p>
      <p><strong>Name:</strong> ${student.name}</p>
      <p><strong>Email:</strong> ${student.email}</p>
      <p><strong>Student ID:</strong> ${student.studentId}</p>
      <p><strong>Department:</strong> ${student.department}</p>
      <p><strong>Year of Study:</strong> ${student.yearOfStudy}</p>
      <p>Manage students in your admin portal.</p>
      <p><a href="http://localhost:3000/admin">Admin Portal</a></p>
    `,
  };
  await transporter.sendMail(mailOptions);
};

export const sendStudentLoginSuccessEmail = async (student) => {
  const school = await School.findById(student.schoolId);
  const mailOptions = {
    from: `"${school.name} Payment System" <${FROM_EMAIL}>`,
    to: student.email,
    subject: `Successful Login to ${school.name}`,
    html: `
      <h1 style="color: ${
        school.customFields.receiptBranding.primaryColor
      }">Welcome Back, ${student.name}!</h1>
      <p>You have successfully logged in to your ${school.name} account.</p>
      <p>Access your dashboard to view payment history and courses: <a href="http://localhost:3000/dashboard">Dashboard</a></p>
      ${
        school.customFields.receiptBranding.logoUrl
          ? `<img src="${school.customFields.receiptBranding.logoUrl}" alt="School Logo" style="max-width: 200px;" />`
          : ""
      }
    `,
  };
  await transporter.sendMail(mailOptions);
};

export const sendFeeAssignmentEmail = async (student, fee, dueDate) => {
  const school = await School.findById(student.schoolId);
  const mailOptions = {
    from: `"${school.name} Payment System" <${FROM_EMAIL}>`,
    to: student.email,
    subject: `New Fee Assigned: ${fee.feeType}`,
    html: `
      <h1 style="color: ${
        school.customFields.receiptBranding.primaryColor
      }">Dear ${student.name},</h1>
      <p>A new fee has been assigned to you by ${school.name}.</p>
      <p><strong>Fee Type:</strong> ${fee.feeType}</p>
      <p><strong>Amount:</strong> ${fee.amount}</p>
      <p><strong>Due Date:</strong> ${dueDate.toISOString().split("T")[0]}</p>
      <p><strong>Description:</strong> ${fee.description || "N/A"}</p>
      <p>Login to your dashboard to view details: <a href="http://localhost:3000/dashboard">Dashboard</a></p>
      ${
        school.customFields.receiptBranding.logoUrl
          ? `<img src="${school.customFields.receiptBranding.logoUrl}" alt="School Logo" style="max-width: 200px;" />`
          : ""
      }
    `,
  };

  await transporter.sendMail(mailOptions);
};
