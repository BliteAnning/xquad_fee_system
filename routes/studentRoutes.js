import express from 'express';
import { checkAuth, clearAllNotifications, deleteNotification, getDashboard, getStudentFeeAssignments, getStudentNotifications, login, markNotificationsRead } from '../controller/studentController.js';
import arcjetStudentMiddleware from '../middleware/arcjetStudent.js';
import { authenticateStudent } from '../middleware/auth.js';
import { getStudentRefunds } from '../controller/refundController.js';

const studentRouter = express.Router();

studentRouter.post('/login', arcjetStudentMiddleware, login);
studentRouter.get('/dashboard', arcjetStudentMiddleware, authenticateStudent, getDashboard);
studentRouter.get('/fee-assignments', arcjetStudentMiddleware, authenticateStudent, getStudentFeeAssignments);
studentRouter.get('/check-auth', authenticateStudent, checkAuth);
studentRouter.get('/get-refunds', authenticateStudent, getStudentRefunds);
studentRouter.get('/notifications', authenticateStudent, getStudentNotifications);
studentRouter.post('/notifications/mark-read', authenticateStudent, markNotificationsRead);
studentRouter.delete('/notifications/:id', authenticateStudent, deleteNotification);
studentRouter.delete('/notifications', authenticateStudent, clearAllNotifications);

export default studentRouter;