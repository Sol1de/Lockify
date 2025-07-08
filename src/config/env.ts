import dotenv from 'dotenv';
import { validateJwtSecret } from '../utils/validation';

// Load environment variables
dotenv.config();

/**
 * Environment configuration interface
 */
export interface EnvConfig {
  // Server
  port: number;
  nodeEnv: string;

  // JWT
  jwtSecret: string;
  jwtExpiresIn: string;
  jwtIssuer: string;
  jwtAudience: string;

  // Password Hashing
  bcryptSaltRounds: number;

  // Security
  hmacSecret?: string;
  encryptionKey?: string;

  // CORS
  corsOrigin: string;

  // Rate Limiting
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;

  // Cookies
  cookieSecret?: string;
  cookieSecure: boolean;
  cookieSameSite: 'strict' | 'lax' | 'none';

  // Session
  sessionSecret?: string;
  sessionMaxAge: number;

  // Database (optional)
  databaseUrl?: string;

  // Redis (optional)
  redisUrl?: string;

  // Logging
  logLevel: string;
  debug: string;
}

/**
 * Parse environment variable as integer with default
 */
function parseIntEnv(envVar: string | undefined, defaultValue: number): number {
  if (!envVar) return defaultValue;
  const parsed = parseInt(envVar, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

/**
 * Parse environment variable as boolean
 */
function parseBooleanEnv(
  envVar: string | undefined,
  defaultValue: boolean
): boolean {
  if (!envVar) return defaultValue;
  return envVar.toLowerCase() === 'true';
}

/**
 * Validate required environment variables
 */
function validateRequiredEnvVars(): void {
  const required = ['JWT_SECRET'];
  const missing = required.filter(envVar => !process.env[envVar]);

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}`
    );
  }

  // Validate JWT secret strength
  if (!validateJwtSecret(process.env.JWT_SECRET!)) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }
}

/**
 * Load and validate environment configuration
 */
export function loadEnvConfig(): EnvConfig {
  // Validate required variables
  validateRequiredEnvVars();

  const config: EnvConfig = {
    // Server
    port: parseIntEnv(process.env.PORT, 3000),
    nodeEnv: process.env.NODE_ENV || 'development',

    // JWT
    jwtSecret: process.env.JWT_SECRET!,
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
    jwtIssuer: process.env.JWT_ISSUER || 'lockify',
    jwtAudience: process.env.JWT_AUDIENCE || 'lockify-users',

    // Password Hashing
    bcryptSaltRounds: parseIntEnv(process.env.BCRYPT_SALT_ROUNDS, 12),

    // CORS
    corsOrigin: process.env.CORS_ORIGIN || '*',

    // Rate Limiting
    rateLimitWindowMs: parseIntEnv(process.env.RATE_LIMIT_WINDOW_MS, 900000), // 15 minutes
    rateLimitMaxRequests: parseIntEnv(process.env.RATE_LIMIT_MAX_REQUESTS, 100),

    // Cookies
    cookieSecure: parseBooleanEnv(process.env.COOKIE_SECURE, false),
    cookieSameSite:
      (process.env.COOKIE_SAME_SITE as 'strict' | 'lax' | 'none') || 'lax',

    // Session
    sessionMaxAge: parseIntEnv(process.env.SESSION_MAX_AGE, 86400000), // 24 hours

    // Logging
    logLevel: process.env.LOG_LEVEL || 'info',
    debug: process.env.DEBUG || '',
  };

  // Conditionally add optional properties only if they are defined
  if (process.env.HMAC_SECRET) {
    config.hmacSecret = process.env.HMAC_SECRET;
  }

  if (process.env.ENCRYPTION_KEY) {
    config.encryptionKey = process.env.ENCRYPTION_KEY;
  }

  if (process.env.COOKIE_SECRET) {
    config.cookieSecret = process.env.COOKIE_SECRET;
  }

  if (process.env.SESSION_SECRET) {
    config.sessionSecret = process.env.SESSION_SECRET;
  }

  if (process.env.DATABASE_URL) {
    config.databaseUrl = process.env.DATABASE_URL;
  }

  if (process.env.REDIS_URL) {
    config.redisUrl = process.env.REDIS_URL;
  }

  return config;
}

/**
 * Default environment configuration
 */
export const env = loadEnvConfig();

/**
 * Check if running in production
 */
export const isProduction = env.nodeEnv === 'production';

/**
 * Check if running in development
 */
export const isDevelopment = env.nodeEnv === 'development';

/**
 * Check if running in test
 */
export const isTest = env.nodeEnv === 'test';
