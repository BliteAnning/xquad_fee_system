import express from 'express';
import { authenticateStudent, authenticateSchool } from '../middleware/auth.js';
import { initializePayment, verifyPayment, handleWebhook } from '../controller/paymentController.js';
import { createInvoice } from '../controller/invoiceController.js';
import arcjetStudentMiddleware from '../middleware/arcjetStudent.js';

const paymentRouter = express.Router();

paymentRouter.post('/initialize', arcjetStudentMiddleware,authenticateStudent, initializePayment);
paymentRouter.post('/verify', arcjetStudentMiddleware, authenticateSchool, verifyPayment); // Optional: protect with auth if needed
paymentRouter.post('/webhook', arcjetStudentMiddleware,handleWebhook);
paymentRouter.post('/invoice/generate', arcjetStudentMiddleware, authenticateSchool, createInvoice); // Endpoint to generate invoice

export default paymentRouter;