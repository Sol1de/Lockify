import {
  ExpiredTokenError,
  InvalidTokenError,
  UserNotFoundError,
} from '../errors';
import { extractTokenFromHeader } from '../utils/headers';
import { verifyToken } from '../helpers/token';
import {
  AuthenticatedRequest,
  AuthenticatedResponse,
  GetUserById,
  MiddlewareFunction,
} from '../types';

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
  return async (
    req: Record<string, unknown>,
    res: Record<string, unknown>,
    next: (err?: Error) => void
  ) => {
    try {
      // Extract token from Authorization header
      const authReq = req as AuthenticatedRequest;
      const authRes = res as AuthenticatedResponse;
      const authHeader = authReq.headers?.authorization;
      const token = extractTokenFromHeader(authHeader);

      if (!token) {
        authRes.status(401).json({ error: 'Token is missing' });
        return;
      }

      // Verify token
      const decoded = verifyToken(token, secret);

      // Get user by ID from token
      const userId = decoded.userId || decoded.sub;
      if (!userId) {
        authRes.status(401).json({ error: 'Invalid token payload' });
        return;
      }

      const user = await getUserById(String(userId));
      if (!user) {
        authRes.status(404).json({ error: 'User not found' });
        return;
      }

      // Attach user to request
      authReq.user = user;
      next();
    } catch (error) {
      const authRes = res as AuthenticatedResponse;
      if (error instanceof InvalidTokenError) {
        authRes.status(401).json({ error: 'Invalid token' });
      } else if (error instanceof ExpiredTokenError) {
        authRes.status(401).json({ error: 'Token has expired' });
      } else if (error instanceof UserNotFoundError) {
        authRes.status(404).json({ error: 'User not found' });
      } else {
        authRes.status(401).json({ error: 'Authentication failed' });
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
  return async (
    req: Record<string, unknown>,
    res: Record<string, unknown>,
    next: (err?: Error) => void
  ) => {
    try {
      // Extract token from Authorization header
      const authReq = req as AuthenticatedRequest;
      const authHeader = authReq.headers?.authorization;
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
            authReq.user = user;
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
  return async (
    req: Record<string, unknown>,
    res: Record<string, unknown>,
    next: (err?: Error) => void
  ) => {
    try {
      // First authenticate the user
      const authReq = req as AuthenticatedRequest;
      const authHeader = authReq.headers?.authorization;
      const token = extractTokenFromHeader(authHeader);

      const authRes = res as AuthenticatedResponse;

      if (!token) {
        authRes.status(401).json({ error: 'Token is missing' });
        return;
      }

      // Verify token
      const decoded = verifyToken(token, secret);

      // Get user by ID from token
      const userId = decoded.userId || decoded.sub;
      if (!userId) {
        authRes.status(401).json({ error: 'Invalid token payload' });
        return;
      }

      const user = await getUserById(String(userId));
      if (!user) {
        authRes.status(404).json({ error: 'User not found' });
        return;
      }

      // Check role from token payload or user object
      const userRole = decoded.role || (user as { role?: string }).role;

      if (!userRole || !allowedRoles.includes(String(userRole))) {
        authRes.status(403).json({ error: 'Insufficient permissions' });
        return;
      }

      // Attach user to request
      authReq.user = user;
      next();
    } catch (error) {
      const authRes = res as AuthenticatedResponse;
      if (error instanceof InvalidTokenError) {
        authRes.status(401).json({ error: 'Invalid token' });
      } else if (error instanceof ExpiredTokenError) {
        authRes.status(401).json({ error: 'Token has expired' });
      } else if (error instanceof UserNotFoundError) {
        authRes.status(404).json({ error: 'User not found' });
      } else {
        authRes.status(401).json({ error: 'Authentication failed' });
      }
    }
  };
}
