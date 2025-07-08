/**
 * Extract token from Authorization header
 * @param authHeader - The Authorization header value
 * @returns The extracted token or null if not found
 */
export function extractTokenFromHeader(
  authHeader: string | undefined
): string | null {
  if (!authHeader) {
    return null;
  }

  // Try Bearer token first
  const bearerToken = extractBearerToken(authHeader);
  if (bearerToken) {
    return bearerToken;
  }

  // Try other common schemes
  const basicToken = extractTokenByScheme(authHeader, 'Basic');
  if (basicToken) {
    return basicToken;
  }

  return null;
}

/**
 * Extract bearer token from header
 * @param authHeader - The Authorization header value
 * @returns The bearer token or null if not found
 */
export function extractBearerToken(
  authHeader: string | undefined
): string | null {
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  const trimmed = authHeader.trim();
  const bearerPrefix = 'bearer ';

  if (!trimmed.toLowerCase().startsWith(bearerPrefix)) {
    return null;
  }

  const token = trimmed.substring(bearerPrefix.length).trim();

  if (!token) {
    return null;
  }

  return token;
}

/**
 * Validate authorization header format
 * @param authHeader - The Authorization header value
 * @returns True if header format is valid
 */
export function validateAuthHeader(authHeader: string | undefined): boolean {
  if (!authHeader || typeof authHeader !== 'string') {
    return false;
  }

  const trimmed = authHeader.trim().toLowerCase();

  // Check for common authorization schemes (case-insensitive)
  const commonSchemes = [
    'bearer',
    'basic',
    'digest',
    'hoba',
    'mutual',
    'negotiate',
    'ntlm',
    'scram-sha-1',
    'scram-sha-256',
    'token',
  ];

  const hasValidScheme = commonSchemes.some(scheme => {
    const schemePrefix = `${scheme} `;
    if (trimmed.startsWith(schemePrefix)) {
      const token = trimmed.substring(schemePrefix.length).trim();
      return token.length > 0;
    }
    return false;
  });

  return hasValidScheme;
}

/**
 * Extract token from various header formats (Bearer, Basic, etc.)
 * @param authHeader - The Authorization header value
 * @param scheme - The authentication scheme (default: 'Bearer')
 * @returns The extracted token or null if not found
 */
export function extractTokenByScheme(
  authHeader: string | undefined,
  scheme = 'Bearer'
): string | null {
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  const trimmed = authHeader.trim();
  const schemePrefix = `${scheme.toLowerCase()} `;

  if (!trimmed.toLowerCase().startsWith(schemePrefix)) {
    return null;
  }

  const token = trimmed.substring(scheme.length + 1).trim();

  if (!token) {
    return null;
  }

  return token;
}

/**
 * Extract token from cookie
 * @param cookieHeader - The Cookie header value
 * @param cookieName - Name of the cookie containing the token
 * @returns The extracted token or null if not found
 */
export function extractTokenFromCookie(
  cookieHeader: string | undefined,
  cookieName = 'token'
): string | null {
  if (!cookieHeader || typeof cookieHeader !== 'string') {
    return null;
  }

  // Parse cookies from the header
  const cookies = cookieHeader.split(';').map(cookie => cookie.trim());

  for (const cookie of cookies) {
    const [name, value] = cookie.split('=').map(part => part.trim());

    if (name === cookieName && value) {
      // Decode URI component in case the token was encoded
      try {
        return decodeURIComponent(value);
      } catch (error) {
        // If decoding fails, return the value as-is
        return value;
      }
    }
  }

  return null;
}
