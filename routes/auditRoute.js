import express from 'express';
import { authenticateSchool } from '../middleware/auth.js';
import { getAuditLogs } from '../controller/auditController.js';
import arcjetMiddleware from '../middleware/arcjet.js';

const auditRouter = express.Router();


auditRouter.get('/logs', arcjetMiddleware,authenticateSchool, getAuditLogs);

export default auditRouter;