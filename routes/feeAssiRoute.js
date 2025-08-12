import express from 'express';
import { authenticateSchool, authenticateStudent } from '../middleware/auth.js';
import { createFeeAssignment, getStudentFeeAssignments, createFee } from '../controller/feeAssignController.js';
import arcjetMiddleware from '../middleware/arcjet.js';

const feeAssignRouter = express.Router();
feeAssignRouter.post('/create', arcjetMiddleware,authenticateSchool, createFee)
feeAssignRouter.post('/assign',arcjetMiddleware, authenticateSchool, createFeeAssignment);
feeAssignRouter.get('/student', arcjetMiddleware,authenticateStudent, getStudentFeeAssignments);

export default feeAssignRouter;