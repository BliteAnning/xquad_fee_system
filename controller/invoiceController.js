import InvoiceModel from '../models/Invoice.js';
import PaymentModel from '../models/Payment.js';
import StudentModel from '../models/Student.js';
import SchoolModel from '../models/School.js';
import FeeModel from '../models/Fee.js';
import TransactionLogModel from '../models/TransactionLog.js';
import PDFDocument from 'pdfkit';
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { v2 as cloudinary } from 'cloudinary';
import connectCloudinary from '../config/connectCloudinary.js';
import { logActionUtil } from './auditController.js';

// Initialize Cloudinary configuration
connectCloudinary();

// Upload to Cloudinary
const uploadToStorage = async (filePath, fileName) => {
  try {
    const result = await cloudinary.uploader.upload(filePath, {
      resource_type: 'raw',
      public_id: `invoices/${fileName}`,
      folder: 'invoices',
      overwrite: true,
    });
    // Delete local temp file
    fs.unlinkSync(filePath);
    return result.secure_url;
  } catch (error) {
    console.error('Cloudinary upload error:', error);
    throw new Error('Failed to upload invoice to Cloudinary');
  }
};

// Generate PDF invoice
const generateInvoicePDF = async (invoiceData, school, student, fee, payment) => {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const fileName = `invoice-${invoiceData.invoiceNumber}.pdf`;
    const filePath = path.join('temp', fileName);
    const stream = fs.createWriteStream(filePath);

    doc.pipe(stream);

    // School Branding
    doc
      .fillColor(school.customFields.receiptBranding.primaryColor || '#000000')
      .fontSize(20)
      .text(school.name, { align: 'center' });
    if (school.customFields.receiptBranding.logoUrl) {
      doc.image(school.customFields.receiptBranding.logoUrl, 50, 50, { width: 100 });
    }
    doc.moveDown();

    // Invoice Header
    doc
      .fontSize(16)
      .fillColor('#000000')
      .text(`Invoice #${invoiceData.invoiceNumber}`, { align: 'left' })
      .text(`Date: ${new Date().toLocaleDateString()}`, { align: 'left' })
      .moveDown();

    // Student Details
    doc
      .fontSize(12)
      .text('Bill To:', { underline: true })
      .text(`Name: ${student.name}`)
      .text(`Email: ${student.email}`)
      .text(`Student ID: ${student.studentId}`)
      .moveDown();

    // Fee Breakdown
    doc.text('Fee Breakdown:', { underline: true });
    invoiceData.feeBreakdown.forEach((item) => {
      doc.text(`${item.feeType}: $${item.amount.toFixed(2)}`);
      if (item.description) doc.text(`  ${item.description}`, { indent: 20 });
    });
    doc.moveDown();

    // Payment Info
    doc.text('Payment Information:', { underline: true });
    doc
      .text(`Payment Provider: ${invoiceData.paymentInfo.paymentProvider}`)
      .text(`Transaction Reference: ${invoiceData.paymentInfo.providerReference}`)
      .text(`Payment Date: ${new Date(invoiceData.paymentInfo.paymentDate).toLocaleDateString()}`)
      .moveDown();

    // Finalize PDF
    doc.end();

    stream.on('finish', () => resolve(filePath));
    stream.on('error', (error) => reject(error));
  });
};

// Create Invoice
export const createInvoice = async (req, res) => {
  try {
    const { paymentId } = req.body;

    // Validate payment
    const payment = await PaymentModel.findById(paymentId)
      .populate('studentId')
      .populate('schoolId')
      .populate('feeId');
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }
    // if (payment.status !== 'confirmed') {
    //  return res.status(400).json({ message: 'Payment must be confirmed to generate invoice' });
    //}

    const student = payment.studentId;
    const school = payment.schoolId;
    const fee = payment.feeId;

    // Prepare invoice data
    const invoiceData = {
      invoiceNumber: `INV-${school._id}-${Date.now()}`,
      paymentId,
      studentId: student._id,
      schoolId: school._id,
      feeId: fee._id,
      amount: payment.amount,
      tax: 0, // Adjust based on your tax logic
      totalAmount: payment.amount, // Adjust if tax is applied
      status: 'paid',
      branding: school.customFields.receiptBranding,
      feeBreakdown: [
        {
          feeType: fee.feeType,
          amount: payment.amount,
          description: fee.description,
        },
      ],
      paymentInfo: {
        paymentProvider: payment.paymentProvider,
        providerReference: payment.providerMetadata.get('paystackRef') || 'N/A',
        paymentDate: payment.updatedAt,
      },
    };

    // Generate PDF
    const pdfPath = await generateInvoicePDF(invoiceData, school, student, fee, payment);
    const pdfUrl = await uploadToStorage(pdfPath, `invoice-${invoiceData.invoiceNumber}.pdf`);

    // Create invoice record
    const invoice = new InvoiceModel({ ...invoiceData, pdfUrl });
    await invoice.save();

    // Update payment with receipt URL
    payment.receiptUrl = pdfUrl;
    await payment.save();

    // Log to TransactionLog
    await TransactionLogModel.create({
      paymentId,
      schoolId: school._id,
      action: 'invoice_generated',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        invoiceNumber: invoice.invoiceNumber,
      },
    });

    // Log to AuditLog
    await logActionUtil({
      entityType: 'Invoice',
      entityId: invoice._id,
      action: 'invoice_generated',
      actor: payment.schoolId,
      actorType: 'admin',
      metadata: {
        ip: req.ip,
        deviceInfo: req.headers['user-agent'],
        invoiceNumber: invoice.invoiceNumber,
        studentId: student._id,
      },
    });

    res.status(201).json({ message: 'Invoice created successfully', invoice });
  } catch (error) {
    console.error('Error creating invoice:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};