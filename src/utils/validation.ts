import { WeakPasswordError, AuthError } from '../errors';

/**
 * Password strength validation options
 */
export interface PasswordValidationOptions {
  minLength?: number;
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
  forbiddenPasswords?: string[];
}

/**
 * Default password validation options
 */
export const DEFAULT_PASSWORD_OPTIONS: Required<PasswordValidationOptions> = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  forbiddenPasswords: ['password', '12345678', 'qwerty', 'admin'],
};

/**
 * Validate password strength against security requirements
 * @param password - The password to validate
 * @param options - Validation options
 * @returns True if password meets requirements
 */
export function validatePasswordStrength(
  password: string,
  options: PasswordValidationOptions = {}
): boolean {
  const settings = { ...DEFAULT_PASSWORD_OPTIONS, ...options };

  if (
    password.length < settings.minLength ||
    password.length > settings.maxLength
  ) {
    throw new WeakPasswordError('Password does not meet length requirements.');
  }

  if (settings.requireUppercase && !/[A-Z]/.test(password)) {
    throw new WeakPasswordError('Password must contain an uppercase letter.');
  }

  if (settings.requireLowercase && !/[a-z]/.test(password)) {
    throw new WeakPasswordError('Password must contain a lowercase letter.');
  }

  if (settings.requireNumbers && !/[0-9]/.test(password)) {
    throw new WeakPasswordError('Password must contain a number.');
  }

  if (
    settings.requireSpecialChars &&
    !/[!@#$%^&*(),.?":{}|<>]/.test(password)
  ) {
    throw new WeakPasswordError('Password must contain a special character.');
  }

  if (isPasswordForbidden(password, settings.forbiddenPasswords)) {
    throw new WeakPasswordError('Password is too common.');
  }

  return true; // Password is strong
}

/**
 * Validate email format
 * @param email - The email to validate
 * @returns True if email format is valid
 */
export function validateEmail(email: string): boolean {
  if (!email.trim()) {
    return false;
  }

  const emailRegex =
    /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  return emailRegex.test(email.trim());
}

/**
 * Validate JWT secret strength
 * @param secret - The JWT secret to validate
 * @returns True if secret meets security requirements
 */
export function validateJwtSecret(secret: string): boolean {
  if (!secret) {
    return false;
  }

  // JWT secret should be at least 32 characters long for security
  if (secret.length < 32) {
    return false;
  }

  // Check entropy - should contain a mix of characters
  const hasLowercase = /[a-z]/.test(secret);
  const hasUppercase = /[A-Z]/.test(secret);
  const hasNumbers = /[0-9]/.test(secret);
  const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>\-_=+]/.test(secret);

  // At least 3 out of 4 character types should be present
  const characterTypeCount = [
    hasLowercase,
    hasUppercase,
    hasNumbers,
    hasSpecialChars,
  ].filter(Boolean).length;

  return characterTypeCount >= 3;
}

/**
 * Sanitize user input
 * @param input - The input to sanitize
 * @returns Sanitized input string
 */
export function sanitizeInput(input: string): string {
  return (
    input
      // Remove HTML tags
      .replace(/<[^>]*>/g, '')
      // Remove script tags and their content
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      // Remove javascript: protocol
      .replace(/javascript:/gi, '')
      // Remove on* event handlers
      .replace(/\son\w+\s*=/gi, '')
      // Replace potentially dangerous characters
      .replace(/[<>"'&]/g, match => {
        const entities: { [key: string]: string } = {
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#x27;',
          '&': '&amp;',
        };
        return entities[match] || match;
      })
      // Trim whitespace
      .trim()
  );
}

/**
 * Check if password is in forbidden list
 * @param password - The password to check
 * @param forbiddenList - List of forbidden passwords
 * @returns True if password is forbidden
 */
export function isPasswordForbidden(
  password: string,
  forbiddenList: string[]
): boolean {
  if (!password || !forbiddenList || !Array.isArray(forbiddenList)) {
    return false;
  }

  const normalizedPassword = password.toLowerCase().trim();

  // Check exact matches
  if (
    forbiddenList.some(
      forbidden => forbidden.toLowerCase() === normalizedPassword
    )
  ) {
    return true;
  }

  // Check if password contains any forbidden password as a substantial part
  return forbiddenList.some(forbidden => {
    const normalizedForbidden = forbidden.toLowerCase().trim();
    // Only consider forbidden passwords of 4+ characters to avoid false positives
    return (
      normalizedForbidden.length >= 4 &&
      normalizedPassword.includes(normalizedForbidden) &&
      // The forbidden word should make up at least 50% of the password
      normalizedForbidden.length >= normalizedPassword.length / 2
    );
  });
}
