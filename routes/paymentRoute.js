import express from 'express';
import { authenticateStudent, authenticateSchool } from '../middleware/auth.js';
import { initializePayment, verifyPayment, handleWebhook } from '../controller/paymentController.js';
import { createInvoice } from '../controller/invoiceController.js';
import arcjetStudentMiddleware from '../middleware/arcjetStudent.js';
import { getStudentPayments } from '../controller/studentController.js';

const paymentRouter = express.Router();

paymentRouter.post('/initialize', arcjetStudentMiddleware,authenticateStudent, initializePayment);
paymentRouter.get('/verify', arcjetStudentMiddleware, authenticateSchool, verifyPayment); // Optional: protect with auth if needed
paymentRouter.post('/webhook', arcjetStudentMiddleware,handleWebhook);
paymentRouter.post('/invoice/generate', arcjetStudentMiddleware, authenticateSchool, createInvoice); // Endpoint to generate invoice
paymentRouter.get('/get-payments', arcjetStudentMiddleware, authenticateStudent, getStudentPayments); // Endpoint to get student payments

export default paymentRouter;