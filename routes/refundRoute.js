import express from 'express';
import { authenticateStudent, authenticateSchool } from '../middleware/auth.js';
import { requestRefund, reviewRefund, handleRefundWebhook } from '../controller/refundController.js';
import arcjetStudentMiddleware from '../middleware/arcjetStudent.js';

const refundRouter = express.Router();

refundRouter.post('/request', arcjetStudentMiddleware,authenticateStudent, requestRefund);
refundRouter.post('/review', arcjetStudentMiddleware,authenticateSchool, reviewRefund);
refundRouter.post('/webhook', arcjetStudentMiddleware,handleRefundWebhook);

export default refundRouter;