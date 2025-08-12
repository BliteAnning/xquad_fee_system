import express from 'express';
import { getDashboard, login } from '../controller/studentController.js';
import arcjetStudentMiddleware from '../middleware/arcjetStudent.js';
import { authenticateStudent } from '../middleware/auth.js';

const studentRouter = express.Router();

studentRouter.post('/login', arcjetStudentMiddleware, login);
studentRouter.get('/dashboard', arcjetStudentMiddleware, authenticateStudent, getDashboard);

export default studentRouter;