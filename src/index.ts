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

// Default export for convenience (optional)
const Lockify = {
  // Password helpers
  hashPassword: require('./helpers/password').hashPassword,
  comparePassword: require('./helpers/password').comparePassword,
  validatePassword: require('./helpers/password').validatePassword,
  generateSalt: require('./helpers/password').generateSalt,

  // Token helpers
  generateToken: require('./helpers/token').generateToken,
  verifyToken: require('./helpers/token').verifyToken,
  decodeToken: require('./helpers/token').decodeToken,
  isTokenExpired: require('./helpers/token').isTokenExpired,
  getTokenExpiration: require('./helpers/token').getTokenExpiration,
  refreshToken: require('./helpers/token').refreshToken,

  // Middleware
  requireAuth: require('./middleware/auth').requireAuth,
  optionalAuth: require('./middleware/auth').optionalAuth,
  requireRole: require('./middleware/auth').requireRole,

  // Header utilities
  extractTokenFromHeader: require('./utils/headers').extractTokenFromHeader,
  extractBearerToken: require('./utils/headers').extractBearerToken,
  validateAuthHeader: require('./utils/headers').validateAuthHeader,
  extractTokenByScheme: require('./utils/headers').extractTokenByScheme,
  extractTokenFromCookie: require('./utils/headers').extractTokenFromCookie,

  // Validation utilities
  validatePasswordStrength:
    require('./utils/validation').validatePasswordStrength,
  validateEmail: require('./utils/validation').validateEmail,
  validateJwtSecret: require('./utils/validation').validateJwtSecret,
  sanitizeInput: require('./utils/validation').sanitizeInput,
  isPasswordForbidden: require('./utils/validation').isPasswordForbidden,

  // Security utilities
  generateSecureRandom: require('./utils/security').generateSecureRandom,
  generateJwtSecret: require('./utils/security').generateJwtSecret,
  hashSha256: require('./utils/security').hashSha256,
  generateHmac: require('./utils/security').generateHmac,
  verifyHmac: require('./utils/security').verifyHmac,
  constantTimeCompare: require('./utils/security').constantTimeCompare,
  generateUuid: require('./utils/security').generateUuid,

  // Errors
  AuthError: require('./errors').AuthError,
  TokenError: require('./errors').TokenError,
  HashError: require('./errors').HashError,
  InvalidTokenError: require('./errors').InvalidTokenError,
  ExpiredTokenError: require('./errors').ExpiredTokenError,
  MissingTokenError: require('./errors').MissingTokenError,
  MalformedTokenError: require('./errors').MalformedTokenError,
  UserNotFoundError: require('./errors').UserNotFoundError,
  InvalidPasswordError: require('./errors').InvalidPasswordError,
  WeakPasswordError: require('./errors').WeakPasswordError,
};

export default Lockify;
