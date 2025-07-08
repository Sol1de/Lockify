/**
 * Base authentication error class
 */
export class AuthError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(
    message: string,
    code: string = 'AUTH_ERROR',
    statusCode: number = 401
  ) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = statusCode;

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AuthError);
    }
  }
}

/**
 * JWT token related errors
 */
export class TokenError extends AuthError {
  constructor(message: string, code: string = 'TOKEN_ERROR') {
    super(message, code, 401);
    this.name = 'TokenError';
  }
}

/**
 * Password hashing related errors
 */
export class HashError extends AuthError {
  constructor(message: string, code: string = 'HASH_ERROR') {
    super(message, code, 500);
    this.name = 'HashError';
  }
}

/**
 * Specific token error types
 */
export class InvalidTokenError extends TokenError {
  constructor(message: string = 'Invalid token') {
    super(message, 'INVALID_TOKEN');
  }
}

export class ExpiredTokenError extends TokenError {
  constructor(message: string = 'Token has expired') {
    super(message, 'EXPIRED_TOKEN');
  }
}

export class MissingTokenError extends TokenError {
  constructor(message: string = 'Token is missing') {
    super(message, 'MISSING_TOKEN');
  }
}

export class MalformedTokenError extends TokenError {
  constructor(message: string = 'Token is malformed') {
    super(message, 'MALFORMED_TOKEN');
  }
}

/**
 * User lookup related errors
 */
export class UserNotFoundError extends AuthError {
  constructor(message: string = 'User not found') {
    super(message, 'USER_NOT_FOUND', 404);
    this.name = 'UserNotFoundError';
  }
}

/**
 * Password-related errors
 */
export class InvalidPasswordError extends AuthError {
  constructor(message: string = 'Invalid password') {
    super(message, 'INVALID_PASSWORD', 401);
    this.name = 'InvalidPasswordError';
  }
}

export class WeakPasswordError extends HashError {
  constructor(
    message: string = 'Password does not meet security requirements'
  ) {
    super(message, 'WEAK_PASSWORD');
    this.name = 'WeakPasswordError';
  }
}
