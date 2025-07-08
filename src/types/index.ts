import type { StringValue } from 'ms';

/**
 * JWT Payload interface
 */
export interface JwtPayload {
  [key: string]: unknown;
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string | string[];
  sub?: string;
}

/**
 * JWT Options interface for token generation
 */
export interface JwtOptions {
  expiresIn?: StringValue | number;
  issuer?: string;
  audience?: string | string[];
  subject?: string;
  algorithm?: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES384' | 'ES512' | 'none';
  keyid?: string;
  noTimestamp?: boolean;
  header?: { [key: string]: unknown };
  encoding?: string;
}

/**
 * Bcrypt Options interface for password hashing
 */
export interface HashOptions {
  saltRounds?: number;
}

/**
 * User lookup function type
 */
export type GetUserById = (id: string) => Promise<Record<string, unknown> | null>;

/**
 * Middleware function type compatible with Express/Koa/Fastify
 */
export type MiddlewareFunction = (
  req: Record<string, unknown>,
  res: Record<string, unknown>,
  next: (err?: Error) => void
) => void | Promise<void>;

/**
 * Request object extended with user property
 */
export interface AuthenticatedRequest {
  user?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Response object for middleware
 */
export interface AuthenticatedResponse {
  status(code: number): AuthenticatedResponse;
  json(data: unknown): void;
  [key: string]: unknown;
}
