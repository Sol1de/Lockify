import bcrypt from 'bcrypt';
import { HashOptions } from '../types';
import { HashError } from '../errors';
import {
  PasswordValidationOptions,
  validatePasswordStrength,
} from '../utils/validation';

/**
 * Default salt rounds for bcrypt hashing
 */
const DEFAULT_SALT_ROUNDS = 12;

/**
 * Hash a password using bcrypt
 * @param password - The plain text password to hash
 * @param options - Optional hashing options
 * @returns Promise that resolves to the hashed password
 */
export async function hashPassword(
  password: string,
  options?: HashOptions
): Promise<string> {
  try {
    const saltRounds = options?.saltRounds ?? DEFAULT_SALT_ROUNDS;
    const salt = await generateSalt(saltRounds);
    return await bcrypt.hash(password, salt);
  } catch (error) {
    throw new HashError('Failed to hash password');
  }
}

/**
 * Compare a plain text password with a bcrypt hash
 * @param password - The plain text password
 * @param hash - The bcrypt hash to compare against
 * @returns Promise that resolves to true if passwords match, false otherwise
 */
export async function comparePassword(
  password: string,
  hash: string
): Promise<boolean> {
  try {
    if (!password || !hash) {
      throw new HashError('Password and hash are required');
    }

    if (!hash.startsWith('$2') || hash.length < 50) {
      throw new HashError('Failed to compare password');
    }

    return await bcrypt.compare(password, hash);
  } catch (error) {
    if (error instanceof HashError) {
      throw error;
    }
    throw new HashError('Failed to compare password');
  }
}

/**
 * Validate password strength
 * @param password - The password to validate
 * @param options - Optional validation options
 * @returns True if password meets security requirements, false otherwise
 */
export function validatePassword(
  password: string,
  options?: PasswordValidationOptions
): boolean {
  if (!password || typeof password !== 'string') {
    return false;
  }

  try {
    return validatePasswordStrength(password, options);
  } catch (error) {
    return false;
  }
}

/**
 * Generate a random salt
 * @param rounds - Number of salt rounds (optional)
 * @returns Promise that resolves to the generated salt
 */
export async function generateSalt(
  rounds: number = DEFAULT_SALT_ROUNDS
): Promise<string> {
  try {
    if (rounds < 4 || rounds > 31) {
      throw new Error('Salt rounds must be between 4 and 31');
    }
    return await bcrypt.genSalt(rounds);
  } catch (error) {
    throw new HashError('Failed to generate salt');
  }
}

/**
 * Hash a password with validation
 * @param password - The plain text password to hash
 * @param options - Optional hashing options
 * @param validationOptions - Optional password validation options
 * @returns Promise that resolves to the hashed password
 * @throws WeakPasswordError if password doesn't meet requirements
 */
export async function hashPasswordWithValidation(
  password: string,
  options?: HashOptions,
  validationOptions?: PasswordValidationOptions
): Promise<string> {
  validatePassword(password, validationOptions);
  return hashPassword(password, options);
}

/**
 * Get information about a bcrypt hash
 * @param hash - The bcrypt hash to analyze
 * @returns Information about the hash (salt rounds, etc.)
 */
export function getHashInfo(hash: string): {
  saltRounds: number;
  isValid: boolean;
} {
  try {
    const parts = hash.split('$');

    if (parts.length !== 4 || !parts[1] || !parts[2]) {
      return { saltRounds: 0, isValid: false };
    }

    const rounds = parseInt(parts[2], 10);

    if (isNaN(rounds)) {
      return { saltRounds: 0, isValid: false };
    }

    return { saltRounds: rounds, isValid: true };
  } catch (error) {
    return { saltRounds: 0, isValid: false };
  }
}
