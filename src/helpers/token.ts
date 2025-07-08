import jwt from 'jsonwebtoken';
import { JwtPayload } from '../types';
import { SignOptions } from 'jsonwebtoken';
import { 
  TokenError, 
  InvalidTokenError, 
  ExpiredTokenError, 
  MalformedTokenError 
} from '../errors';

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
  options?: SignOptions
): string {
  return jwt.sign(payload, secret, options);
}

/**
 * Decode a JWT token without verification (unsafe)
 * @param token - The JWT token to decode
 * @returns The decoded payload or null if malformed
 */
export function decodeToken<T extends JwtPayload = JwtPayload>(token: string): T | null {
  try {
    const decoded = jwt.decode(token);
    if (typeof decoded === 'object' && decoded !== null) {
      return decoded as T;
    }
    throw new MalformedTokenError('Token payload is malformed');
  } catch (error) {
    throw new MalformedTokenError('Failed to decode token');
  }
}

/**
 * Check if a token is expired
 * @param token - The JWT token to check
 * @returns True if token is expired
 */
export function isTokenExpired(token: string): boolean {
  const decoded = decodeToken<JwtPayload>(token);
  if (!decoded || !decoded.exp) return true;

  const nowInSeconds = Math.floor(Date.now() / 1000);
  return decoded.exp < nowInSeconds;
}

/**
 * Get token expiration date
 * @param token - The JWT token
 * @returns The expiration date or null if no expiration
 */
export function getTokenExpiration(token: string): Date | null {
  const decoded = decodeToken<JwtPayload>(token);
  if (decoded?.exp) {
    return new Date(decoded.exp * 1000);
  }
  return null;
}

/**
 * Refresh a token (generate new token with updated expiration)
 * @param token - The existing token
 * @param secret - The secret key
 * @param options - Optional new options
 * @returns New token with refreshed expiration
 */
export function refreshToken<T extends JwtPayload = JwtPayload>(
  token: string,
  secret: string,
  options?: SignOptions
): string {
  const decoded = decodeToken<T>(token);
  if (!decoded) {
    throw new InvalidTokenError('Cannot refresh invalid token');
  }

  
  const { iat, exp, nbf, ...payload } = decoded as any;

  return generateToken(payload as T, secret, options);
}
