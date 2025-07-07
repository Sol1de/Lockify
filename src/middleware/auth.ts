import { GetUserById, MiddlewareFunction } from '../types';
import { verifyToken } from '../helpers/token';
import { extractTokenFromHeader } from '../utils/headers';
import { 
  AuthError, 
  MissingTokenError, 
  InvalidTokenError, 
  UserNotFoundError 
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
  // TODO: Implement authentication middleware logic
  throw new Error('requireAuth not implemented');
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
  // TODO: Implement optional authentication middleware logic
  throw new Error('optionalAuth not implemented');
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
  // TODO: Implement role-based authentication middleware logic
  throw new Error('requireRole not implemented');
}

