import express from 'express';
import { checkAuth, getDashboard, getStudentFeeAssignments, login } from '../controller/studentController.js';
import arcjetStudentMiddleware from '../middleware/arcjetStudent.js';
import { authenticateStudent } from '../middleware/auth.js';
import { getStudentRefunds } from '../controller/refundController.js';

const studentRouter = express.Router();

studentRouter.post('/login', arcjetStudentMiddleware, login);
studentRouter.get('/dashboard', arcjetStudentMiddleware, authenticateStudent, getDashboard);
studentRouter.get('/fee-assignments', arcjetStudentMiddleware, authenticateStudent, getStudentFeeAssignments);
studentRouter.get('/check-auth', authenticateStudent, checkAuth);
studentRouter.get('/get-refunds', authenticateStudent, getStudentRefunds);

export default studentRouter;