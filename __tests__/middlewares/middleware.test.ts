import { requireAuth, optionalAuth, requireRole } from '../../src/middleware/auth';
import { AuthError, MissingTokenError, UserNotFoundError } from '../../src/errors';
import { generateToken } from '../../src/helpers/token';
import jwt from 'jsonwebtoken';

// Extended types for testing
interface TestRequest {
  headers: { authorization?: string; [key: string]: any };
  user?: any;
}

interface TestResponse {
  status: jest.Mock;
  json: jest.Mock;
}

describe('Middleware Functions', () => {
  const mockGetUserById = jest.fn();
  const mockReq = { headers: {} };
  const mockRes = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  const mockNext = jest.fn();
  const secret = 'test-secret';
  const testUser = { id: '123', email: 'test@example.com', role: 'user' };
  const testPayload = { userId: '123', role: 'user' };

  beforeEach(() => {
    jest.clearAllMocks();
    mockRes.status.mockReturnThis();
  });

  describe('requireAuth', () => {
    it('should authenticate valid token and attach user', async () => {
      const token = jwt.sign(testPayload, secret);
      const authMiddleware = requireAuth(mockGetUserById, secret);
      
      mockGetUserById.mockResolvedValue(testUser);
      const req = { headers: { authorization: `Bearer ${token}` } };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect((req as TestRequest).user).toEqual(testUser);
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should return 401 for missing token', async () => {
      const authMiddleware = requireAuth(mockGetUserById, secret);
      const req = { headers: {} };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Token is missing'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 for invalid token', async () => {
      const authMiddleware = requireAuth(mockGetUserById, secret);
      const req = { headers: { authorization: 'Bearer invalid-token' } };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Invalid token'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 404 for user not found', async () => {
      const token = jwt.sign(testPayload, secret);
      const authMiddleware = requireAuth(mockGetUserById, secret);
      
      mockGetUserById.mockResolvedValue(null);
      const req = { headers: { authorization: `Bearer ${token}` } };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(404);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'User not found'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('optionalAuth', () => {
    it('should attach user if valid token provided', async () => {
      const token = jwt.sign(testPayload, secret);
      const authMiddleware = optionalAuth(mockGetUserById, secret);
      
      mockGetUserById.mockResolvedValue(testUser);
      const req = { headers: { authorization: `Bearer ${token}` } };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect((req as TestRequest).user).toEqual(testUser);
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should continue without user if no token provided', async () => {
      const authMiddleware = optionalAuth(mockGetUserById, secret);
      const req = { headers: {} };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect((req as TestRequest).user).toBeUndefined();
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should continue without user if invalid token provided', async () => {
      const authMiddleware = optionalAuth(mockGetUserById, secret);
      const req = { headers: { authorization: 'Bearer invalid-token' } };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect((req as TestRequest).user).toBeUndefined();
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockRes.status).not.toHaveBeenCalled();
    });
  });

  describe('requireRole', () => {
    it('should allow access for user with correct role', async () => {
      const token = jwt.sign(testPayload, secret);
      const authMiddleware = requireRole(mockGetUserById, secret, ['user', 'admin']);
      
      mockGetUserById.mockResolvedValue(testUser);
      const req = { headers: { authorization: `Bearer ${token}` } };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect((req as TestRequest).user).toEqual(testUser);
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should deny access for user with incorrect role', async () => {
      const token = jwt.sign(testPayload, secret);
      const authMiddleware = requireRole(mockGetUserById, secret, ['admin']);
      
      mockGetUserById.mockResolvedValue(testUser);
      const req = { headers: { authorization: `Bearer ${token}` } };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Insufficient permissions'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should deny access for user without role property', async () => {
      const token = jwt.sign({ userId: '123' }, secret); // No role in token
      const authMiddleware = requireRole(mockGetUserById, secret, ['user']);
      
      const userWithoutRole = { id: '123', email: 'test@example.com' }; // No role property
      mockGetUserById.mockResolvedValue(userWithoutRole);
      const req = { headers: { authorization: `Bearer ${token}` } };
      
      await authMiddleware(req, mockRes, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Insufficient permissions'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});
