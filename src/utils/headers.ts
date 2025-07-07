import { MissingTokenError, MalformedTokenError } from '../errors';

/**
 * Extract token from Authorization header
 * @param authHeader - The Authorization header value
 * @returns The extracted token or null if not found
 */
export function extractTokenFromHeader(authHeader: string | undefined): string | null {
  // TODO: Implement token extraction logic
  throw new Error('extractTokenFromHeader not implemented');
}

/**
 * Extract bearer token from header
 * @param authHeader - The Authorization header value
 * @returns The bearer token or null if not found
 */
export function extractBearerToken(authHeader: string | undefined): string | null {
  // TODO: Implement bearer token extraction logic
  throw new Error('extractBearerToken not implemented');
}

/**
 * Validate authorization header format
 * @param authHeader - The Authorization header value
 * @returns True if header format is valid
 */
export function validateAuthHeader(authHeader: string | undefined): boolean {
  // TODO: Implement header validation logic
  throw new Error('validateAuthHeader not implemented');
}

/**
 * Extract token from various header formats (Bearer, Basic, etc.)
 * @param authHeader - The Authorization header value
 * @param scheme - The authentication scheme (default: 'Bearer')
 * @returns The extracted token or null if not found
 */
export function extractTokenByScheme(
  authHeader: string | undefined, 
  scheme: string = 'Bearer'
): string | null {
  // TODO: Implement token extraction by scheme logic
  throw new Error('extractTokenByScheme not implemented');
}

/**
 * Extract token from cookie
 * @param cookieHeader - The Cookie header value
 * @param cookieName - Name of the cookie containing the token
 * @returns The extracted token or null if not found
 */
export function extractTokenFromCookie(
  cookieHeader: string | undefined, 
  cookieName: string = 'token'
): string | null {
  // TODO: Implement cookie token extraction logic
  throw new Error('extractTokenFromCookie not implemented');
}
