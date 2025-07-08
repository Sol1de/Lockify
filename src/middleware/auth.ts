import { GetUserById, MiddlewareFunction, AuthenticatedRequest, AuthenticatedResponse } from '../types';
import { verifyToken } from '../helpers/token';
import { extractTokenFromHeader } from '../utils/headers';
import {
  MissingTokenError,
  InvalidTokenError,
  ExpiredTokenError,
  UserNotFoundError,
  TokenError,
} from '../errors';

/**
 * Create an authentication middleware function
 * @param getUserById - Function to retrieve user by ID
 * @param secret - JWT secret for token verification
 * @returns Middleware function compatible with Express/Koa/Fastify
 */
export function requireAuth(
  getUserById: GetUserById,
  secret: string
): MiddlewareFunction {
  return async (req: Record<string, unknown>, res: Record<string, unknown>, next: (err?: Error) => void) => {
    try {
      // Extract token from Authorization header
      const authHeader = (req as any).headers?.authorization;
      const token = extractTokenFromHeader(authHeader);
      
      if (!token) {
        (res as any).status(401).json({ error: 'Token is missing' });
        return;
      }
      
      // Verify token
      const decoded = verifyToken(token, secret);
      
      // Get user by ID from token
      const userId = decoded.userId || decoded.sub;
      if (!userId) {
        (res as any).status(401).json({ error: 'Invalid token payload' });
        return;
      }
      
      const user = await getUserById(String(userId));
      if (!user) {
        (res as any).status(404).json({ error: 'User not found' });
        return;
      }
      
      // Attach user to request
      (req as any).user = user;
      next();
    } catch (error) {
      if (error instanceof InvalidTokenError) {
        (res as any).status(401).json({ error: 'Invalid token' });
      } else if (error instanceof ExpiredTokenError) {
        (res as any).status(401).json({ error: 'Token has expired' });
      } else if (error instanceof UserNotFoundError) {
        (res as any).status(404).json({ error: 'User not found' });
      } else {
        (res as any).status(401).json({ error: 'Authentication failed' });
      }
    }
  };
}

/**
 * Create an optional authentication middleware (doesn't fail if no token)
 * @param getUserById - Function to retrieve user by ID
 * @param secret - JWT secret for token verification
 * @returns Middleware function that adds user to request if token is valid
 */
export function optionalAuth(
  getUserById: GetUserById,
  secret: string
): MiddlewareFunction {
  return async (req: Record<string, unknown>, res: Record<string, unknown>, next: (err?: Error) => void) => {
    try {
      // Extract token from Authorization header
      const authHeader = (req as any).headers?.authorization;
      const token = extractTokenFromHeader(authHeader);
      
      if (!token) {
        // No token provided, continue without authentication
        next();
        return;
      }
      
      try {
        // Verify token
        const decoded = verifyToken(token, secret);
        
        // Get user by ID from token
        const userId = decoded.userId || decoded.sub;
        if (userId) {
          const user = await getUserById(String(userId));
          if (user) {
            (req as any).user = user;
          }
        }
      } catch (error) {
        // Token verification failed, but this is optional auth so we continue
        // without setting req.user
      }
      
      next();
    } catch (error) {
      // For optional auth, we don't fail on errors
      next();
    }
  };
}

/**
 * Create a role-based authentication middleware
 * @param getUserById - Function to retrieve user by ID
 * @param secret - JWT secret for token verification
 * @param allowedRoles - Array of allowed roles
 * @returns Middleware function that checks user role
 */
export function requireRole(
  getUserById: GetUserById,
  secret: string,
  allowedRoles: string[]
): MiddlewareFunction {
  return async (req: Record<string, unknown>, res: Record<string, unknown>, next: (err?: Error) => void) => {
    try {
      // First authenticate the user
      const authHeader = (req as any).headers?.authorization;
      const token = extractTokenFromHeader(authHeader);
      
      if (!token) {
        (res as any).status(401).json({ error: 'Token is missing' });
        return;
      }
      
      // Verify token
      const decoded = verifyToken(token, secret);
      
      // Get user by ID from token
      const userId = decoded.userId || decoded.sub;
      if (!userId) {
        (res as any).status(401).json({ error: 'Invalid token payload' });
        return;
      }
      
      const user = await getUserById(String(userId));
      if (!user) {
        (res as any).status(404).json({ error: 'User not found' });
        return;
      }
      
      // Check role from token payload or user object
      const userRole = decoded.role || (user as any).role;
      
      if (!userRole || !allowedRoles.includes(String(userRole))) {
        (res as any).status(403).json({ error: 'Insufficient permissions' });
        return;
      }
      
      // Attach user to request
      (req as any).user = user;
      next();
    } catch (error) {
      if (error instanceof InvalidTokenError) {
        (res as any).status(401).json({ error: 'Invalid token' });
      } else if (error instanceof ExpiredTokenError) {
        (res as any).status(401).json({ error: 'Token has expired' });
      } else if (error instanceof UserNotFoundError) {
        (res as any).status(404).json({ error: 'User not found' });
      } else {
        (res as any).status(401).json({ error: 'Authentication failed' });
      }
    }
  };
}
