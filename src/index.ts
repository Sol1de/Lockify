// Export types and interfaces
export * from './types';

// Export custom errors
export * from './errors';

// Export password helpers
export {
  hashPassword,
  comparePassword,
  validatePassword,
  generateSalt,
} from './helpers/password';

// Export JWT/token helpers
export {
  generateToken,
  verifyToken,
  decodeToken,
  isTokenExpired,
  getTokenExpiration,
  refreshToken,
} from './helpers/token';

// Export middleware functions
export { requireAuth, optionalAuth, requireRole } from './middleware/auth';

// Export utility functions
export {
  extractTokenFromHeader,
  extractBearerToken,
  validateAuthHeader,
  extractTokenByScheme,
  extractTokenFromCookie,
} from './utils/headers';

export {
  validatePasswordStrength,
  validateEmail,
  validateJwtSecret,
  sanitizeInput,
  isPasswordForbidden,
  PasswordValidationOptions,
  DEFAULT_PASSWORD_OPTIONS,
} from './utils/validation';

export {
  generateSecureRandom,
  generateJwtSecret,
  hashSha256,
  generateHmac,
  verifyHmac,
  constantTimeCompare,
  generateUuid,
} from './utils/security';

