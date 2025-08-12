// tests/school.test.js
import supertest from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../server.js'; // Adjust path to your server.js
import School from '../models/School.js';
import TransactionLog from '../models/TransactionLog.js';
import Notification from '../models/Notification.js';
import * as emailUtils from '../utils/email.js';

jest.mock('../utils/email.js'); // Mock email sending

describe('School API', () => {
  let mongoServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    await mongoose.connect(mongoServer.getUri());
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  afterEach(async () => {
    await School.deleteMany({});
    await TransactionLog.deleteMany({});
    await Notification.deleteMany({});
    jest.clearAllMocks();
  });

  describe('POST /api/v1/schools/register', () => {
    const validSchool = {
      name: 'Test University',
      email: 'test@university.com',
      password: 'Password123!',
      contactDetails: { phone: '+1234567890', address: '123 Test St' },
      customFields: {
        feeStructure: { tuition: '10000' },
        receiptBranding: { logoUrl: 'https://res.cloudinary.com/logo.png', primaryColor: '#FF0000' },
      },
      paymentProviders: [{ provider: 'Paystack', apiKey: 'pk_test_123', priority: 1 }],
    };

    it('should register a school successfully', async () => {
      emailUtils.sendWelcomeEmail.mockResolvedValue();
      const res = await supertest(app)
        .post('/api/v1/schools/register')
        .send(validSchool);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('_id');
      expect(res.body.data.name).toBe('Test University');
      expect(res.body.token).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();

      const school = await School.findOne({ email: 'test@university.com' });
      expect(school).toBeDefined();
      const log = await TransactionLog.findOne({ action: 'school_registration' });
      expect(log).toBeDefined();
      const notification = await Notification.findOne({ type: 'school_registration' });
      expect(notification).toBeDefined();
    });

    it('should reject invalid email', async () => {
      const res = await supertest(app)
        .post('/api/v1/schools/register')
        .send({ ...validSchool, email: 'invalid' });

      expect(res.status).toBe(400);
      expect(res.body.message).toBe('Invalid email format');
    });

    it('should reject weak password', async () => {
      const res = await supertest(app)
        .post('/api/v1/schools/register')
        .send({ ...validSchool, password: 'weak' });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('Password does not meet requirements');
    });

    it('should reject duplicate email', async () => {
      await new School({ ...validSchool, password: await bcrypt.hash(validSchool.password, 10) }).save();
      const res = await supertest(app)
        .post('/api/v1/schools/register')
        .send(validSchool);

      expect(res.status).toBe(400);
      expect(res.body.message).toBe('Email already exists');
    });
  });

  describe('POST /api/v1/schools/login', () => {
    const schoolData = {
      name: 'Test University',
      email: 'test@university.com',
      password: 'Password123!',
      contactDetails: { phone: '+1234567890', address: '123 Test St' },
      customFields: {
        feeStructure: { tuition: '10000' },
        receiptBranding: { logoUrl: 'https://res.cloudinary.com/logo.png', primaryColor: '#FF0000' },
      },
      paymentProviders: [{ provider: 'Paystack', apiKey: 'pk_test_123', priority: 1 }],
    };

    beforeEach(async () => {
      await new School({ ...schoolData, password: await bcrypt.hash(schoolData.password, 10) }).save();
    });

    it('should login successfully', async () => {
      const res = await supertest(app)
        .post('/api/v1/schools/login')
        .send({ email: 'test@university.com', password: 'Password123!' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('_id');
      expect(res.body.data.name).toBe('Test University');
      expect(res.body.token).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();

      const log = await TransactionLog.findOne({ action: 'school_login_success' });
      expect(log).toBeDefined();
    });

    it('should reject invalid credentials', async () => {
      emailUtils.sendFailedLoginEmail.mockResolvedValue();
      const res = await supertest(app)
        .post('/api/v1/schools/login')
        .send({ email: 'test@university.com', password: 'wrong' });

      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Invalid credentials');

      const log = await TransactionLog.findOne({ action: 'school_login_failure' });
      expect(log).toBeDefined();
      const notification = await Notification.findOne({ type: 'login_failure' });
      expect(notification).toBeDefined();
    });
  });
});