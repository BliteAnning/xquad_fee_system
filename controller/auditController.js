import AuditLogModel from '../models/AuditTrail.js';
import StudentModel from '../models/Student.js';

export const logAction = async (req, res) => {
  try {
    const { entityType, entityId, action, metadata } = req.body;

    // Validate required fields
    if (!entityType || !entityId || !action) {
      return res.status(400).json({ message: 'entityType, entityId, and action are required' });
    }

    // Determine actor and actorType
    let actor = null;
    let actorType = 'system';

    if (req.user) {
      if (req.user.studentId) {
        // From authenticateStudent middleware
        actor = req.user.id; // Student ID
        actorType = 'student';
      } else {
        // From authenticateSchool middleware
        actor = req.user.id; // School ID
        actorType = 'admin';
      }
    }

    // Create audit log entry
    const auditLog = new AuditLogModel({
      entityType,
      entityId,
      action,
      actor,
      actorType,
      metadata: {
        ip: req.ip || metadata?.ip,
        deviceInfo: req.headers['user-agent'] || metadata?.deviceInfo,
        deviceId: metadata?.deviceId,
        additionalInfo: metadata?.additionalInfo || {},
      },
    });

    await auditLog.save();

    res.status(201).json({ message: 'Action logged successfully', auditLog });
  } catch (error) {
    console.error('Error logging action:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Utility function to log actions (used by other controllers)
export const logActionUtil = async ({ entityType, entityId, action, actor, actorType, metadata }) => {
  try {
    const auditLog = new AuditLogModel({
      entityType,
      entityId,
      action,
      actor: ['admin', 'student'].includes(actorType) ? actor : null,
      actorType: actorType || 'system',
      metadata: {
        ip: metadata?.ip,
        deviceInfo: metadata?.deviceInfo,
        deviceId: metadata?.deviceId,
        additionalInfo: metadata?.additionalInfo || {},
      },
    });

    await auditLog.save();
    return auditLog;
  } catch (error) {
    console.error('Error logging action:', error);
    throw error;
  }
};

// Get audit logs (specific log by ID or all logs for the school)
export const getAuditLogs = async (req, res) => {
  try {
    const { logId, entityType, action, actorType } = req.query;
    const schoolId = req.user.id; // From authenticateSchool middleware

    // Build query
    const query = {
      $or: [
        { actorType: 'admin', actor: schoolId },
        { actorType: 'student', actor: { $in: await StudentModel.distinct('_id', { schoolId }) } },
        { actorType: 'system', actor: null },
      ],
    };

    if (logId) {
      query._id = logId;
    }
    if (entityType) {
      query.entityType = entityType;
    }
    if (action) {
      query.action = action;
    }
    if (actorType) {
      query.actorType = actorType;
    }

    // Fetch logs
    const auditLogs = await AuditLogModel.find(query)
      .sort({ createdAt: -1 }) // Recent first
      .limit(100) // Prevent excessive data
      .populate('actor', 'name email studentId') // Populate school or student details
      .populate('entityId', 'amount feeType studentId schoolId'); // Populate entity details

    if (logId && auditLogs.length === 0) {
      return res.status(404).json({ message: 'Audit log not found' });
    }

    res.status(200).json({
      message: auditLogs.length === 1 ? 'Audit log retrieved successfully' : 'Audit logs retrieved successfully',
      auditLogs,
    });
  } catch (error) {
    console.error('Error retrieving audit logs:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};