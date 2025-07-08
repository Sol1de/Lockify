import jwt from 'jsonwebtoken';
import { JwtOptions, JwtPayload } from '../types';
import {
  ExpiredTokenError,
  InvalidTokenError,
  MalformedTokenError,
  TokenError,
} from '../errors';
import { validateJwtSecret } from '../utils/validation';
import { generateJwtSecret } from '../utils/security';

/**
 * Generate a JWT token with the given payload and secret
 * @param payload - The payload to encode in the token
 * @param secret - The secret key for signing the token
 * @param options - Optional JWT options
 * @returns The generated JWT token string
 */
export function generateToken<T extends JwtPayload = JwtPayload>(
  payload: T,
  secret: string,
  options?: JwtOptions
): string {
  try {
    if (!secret) {
      throw new TokenError('Secret is required for token generation');
    }

    if (!payload || typeof payload !== 'object') {
      throw new TokenError('Payload must be an object');
    }

    const jwtOptions: jwt.SignOptions = {};

    if (options?.expiresIn !== undefined) {
      jwtOptions.expiresIn = options.expiresIn;
    }
    if (options?.issuer) {
      jwtOptions.issuer = options.issuer;
    }
    if (options?.audience) {
      jwtOptions.audience = options.audience;
    }
    if (options?.subject) {
      jwtOptions.subject = options.subject;
    }
    if (options?.algorithm) {
      jwtOptions.algorithm = options.algorithm;
    }
    if (options?.keyid) {
      jwtOptions.keyid = options.keyid;
    }
    if (options?.noTimestamp) {
      jwtOptions.noTimestamp = options.noTimestamp;
    }
    if (options?.header) {
      jwtOptions.header = {
        alg: options.algorithm || 'HS256',
        ...options.header,
      };
    }
    if (options?.encoding) {
      jwtOptions.encoding = options.encoding;
    }

    return jwt.sign(payload, secret, jwtOptions);
  } catch (error) {
    if (error instanceof TokenError) {
      throw error;
    }
    throw new TokenError('Failed to generate token');
  }
}

/**
 * Verify and decode a JWT token
 * @param token - The JWT token to verify
 * @param secret - The secret key for verification
 * @returns The decoded payload or null if invalid
 */
export function verifyToken<T extends JwtPayload = JwtPayload>(
  token: string,
  secret: string
): T {
  try {
    const decoded = jwt.verify(token, secret);
    if (typeof decoded === 'object' && decoded !== null) {
      return decoded as T;
    }
    throw new MalformedTokenError('Token payload is malformed');
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (error.name === 'TokenExpiredError') {
        throw new ExpiredTokenError('Token has expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new InvalidTokenError('Invalid token');
      }
    }
    throw new TokenError('Token verification failed');
  }
}

/**
 * Decode a JWT token without verification (unsafe)
 * @param token - The JWT token to decode
 * @returns The decoded payload or null if malformed
 */
export function decodeToken<T extends JwtPayload = JwtPayload>(
  token: string
): T | null {
  try {
    if (!token || typeof token !== 'string') {
      return null;
    }

    const decoded = jwt.decode(token, { complete: false });

    if (decoded && typeof decoded === 'object') {
      return decoded as T;
    }

    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Check if a token is expired
 * @param token - The JWT token to check
 * @returns True if token is expired
 */
export function isTokenExpired(token: string): boolean {
  try {
    const decoded = decodeToken(token);
    if (!decoded || !decoded.exp) {
      return false; // No expiration set
    }

    const currentTime = Math.floor(Date.now() / 1000);
    return decoded.exp < currentTime;
  } catch (error) {
    return true; // If we can't decode, consider it expired
  }
}

/**
 * Get token expiration date
 * @param token - The JWT token
 * @returns The expiration date or null if no expiration
 */
export function getTokenExpiration(token: string): Date | null {
  try {
    const decoded = decodeToken(token);
    if (!decoded || !decoded.exp) {
      return null;
    }

    // JWT exp is in seconds, Date constructor expects milliseconds
    return new Date(decoded.exp * 1000);
  } catch (error) {
    return null;
  }
}

/**
 * Refresh a token (generate new token with updated expiration)
 * @param token - The existing token
 * @param secret - The secret key
 * @param options - Optional new options
 * @returns New token with refreshed expiration
 */
export function refreshToken(
  token: string,
  secret: string,
  options?: JwtOptions
): string {
  try {
    // First verify the token to ensure it's valid
    const decoded = verifyToken(token, secret);

    // Remove timing-sensitive claims that shouldn't be copied
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { iat: _iat, exp: _exp, ...payload } = decoded;

    // Generate new token with refreshed expiration
    const refreshOptions: JwtOptions = {
      expiresIn: '1h', // Default refresh expiration
      ...options,
    };

    return generateToken(payload, secret, refreshOptions);
  } catch (error) {
    if (error instanceof TokenError) {
      throw error;
    }
    throw new TokenError('Failed to refresh token');
  }
}

/**
 * Generate a secure JWT secret
 * @param length - Length of the secret (default: 64)
 * @returns Secure JWT secret
 */
export function generateSecureSecret(length = 64): string {
  return generateJwtSecret(length);
}

/**
 * Validate JWT secret strength
 * @param secret - The JWT secret to validate
 * @returns True if secret meets security requirements
 */
export function validateSecret(secret: string): boolean {
  return validateJwtSecret(secret);
}

/**
 * Get token header information
 * @param token - The JWT token
 * @returns The token header or null if malformed
 */
export function getTokenHeader(token: string): Record<string, unknown> | null {
  try {
    const decoded = jwt.decode(token, { complete: true });

    if (decoded && typeof decoded === 'object' && decoded.header) {
      return decoded.header as unknown as Record<string, unknown>;
    }

    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Check if token needs refresh (expires within specified minutes)
 * @param token - The JWT token to check
 * @param minutesBeforeExpiry - Minutes before expiry to consider for refresh (default: 15)
 * @returns True if token should be refreshed
 */
export function shouldRefreshToken(
  token: string,
  minutesBeforeExpiry = 15
): boolean {
  try {
    const decoded = decodeToken(token);
    if (!decoded || !decoded.exp) {
      return false; // No expiration set
    }

    const currentTime = Math.floor(Date.now() / 1000);
    const timeUntilExpiry = decoded.exp - currentTime;
    const minutesUntilExpiry = timeUntilExpiry / 60;

    return minutesUntilExpiry <= minutesBeforeExpiry && minutesUntilExpiry > 0;
  } catch (error) {
    return true; // If we can't decode, suggest refresh
  }
}

/**
 * Get token time remaining in seconds
 * @param token - The JWT token
 * @returns Time remaining in seconds, or null if no expiration
 */
export function getTokenTimeRemaining(token: string): number | null {
  try {
    const decoded = decodeToken(token);
    if (!decoded || !decoded.exp) {
      return null;
    }

    const currentTime = Math.floor(Date.now() / 1000);
    const timeRemaining = decoded.exp - currentTime;

    return Math.max(0, timeRemaining);
  } catch (error) {
    return null;
  }
}
