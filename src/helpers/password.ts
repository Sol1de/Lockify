import bcrypt from 'bcrypt';
import { HashOptions } from '../types';
import { HashError } from '../errors';

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
export async function hashPassword(password: string, options?: HashOptions): Promise<string> {
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
export async function comparePassword(password: string, hash: string): Promise<boolean> {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    throw new HashError('Failed to compare password');
  }
}

/**
 * Validate password strength
 * @param password - The password to validate
 * @returns True if password meets security requirements
 */
export function validatePassword(password: string): boolean {
  const minLength = 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return (
    password.length >= minLength &&
    hasUppercase &&
    hasLowercase &&
    hasDigit &&
    hasSpecialChar
  );
}

/**
 * Generate a random salt
 * @param rounds - Number of salt rounds (optional)
 * @returns Promise that resolves to the generated salt
 */
export async function generateSalt(rounds: number = DEFAULT_SALT_ROUNDS): Promise<string> {
  try {
    return await bcrypt.genSalt(rounds);
  } catch (error) {
    throw new HashError('Failed to generate salt');
  }
}
