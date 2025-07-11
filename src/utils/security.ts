import crypto from 'crypto';

/**
 * Generate a cryptographically secure random string
 * @param length - Length of the random string
 * @returns Random string
 */
export function generateSecureRandom(length = 32): string {
  if (length <= 0 || !Number.isInteger(length)) {
    throw new Error('Length must be a positive integer');
  }

  const bytesNeeded = Math.ceil(length / 2);
  const randomBytes = crypto.randomBytes(bytesNeeded);
  return randomBytes.toString('hex').slice(0, length);
}

/**
 * Generate a secure JWT secret
 * @param length - Length of the secret (default: 64)
 * @returns Secure JWT secret
 */
export function generateJwtSecret(length = 64): string {
  if (length < 32) {
    throw new Error('JWT secret must be at least 32 characters long');
  }

  // Use printable ASCII characters (33-126) excluding problematic ones
  // ASCII 33-126 includes: !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
  const minChar = 33; // '!' character
  const maxChar = 126; // '~' character

  // Characters to avoid (quotes and backslashes that might cause issues in JSON/strings)
  const avoidChars = new Set(['"', "'", '\\', '`']);

  let secret = '';

  for (let i = 0; i < length; i++) {
    let char;
    do {
      // Generate random byte and map it to ASCII range
      const randomBytes = crypto.randomBytes(1);
      const randomByte = randomBytes[0];
      if (randomByte === undefined) {
        throw new Error('Failed to generate random byte');
      }
      const charCode = minChar + (randomByte % (maxChar - minChar + 1));
      char = String.fromCharCode(charCode);
    } while (avoidChars.has(char)); // Regenerate if we hit a problematic character

    secret += char;
  }

  return secret;
}

export function hashSha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Generate HMAC signature
 * @param data - Data to sign
 * @param secret - Secret key for HMAC
 * @param algorithm - HMAC algorithm (default: sha256)
 * @returns HMAC signature
 */
export function generateHmac(
  data: string,
  secret: string,
  algorithm = 'sha256'
): string {
  if (!data || !secret) {
    throw new Error('Data and secret are required');
  }

  try {
    return crypto.createHmac(algorithm, secret).update(data).digest('hex');
  } catch (error: unknown) {
    throw new Error(
      `HMAC generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * Verify HMAC signature
 * @param data - Original data
 * @param signature - HMAC signature to verify
 * @param secret - Secret key for HMAC
 * @param algorithm - HMAC algorithm (default: sha256)
 * @returns True if signature is valid
 */
export function verifyHmac(
  data: string,
  signature: string,
  secret: string,
  algorithm = 'sha256'
): boolean {
  const expectedSignature = generateHmac(data, secret, algorithm);
  return constantTimeCompare(expectedSignature, signature);
}

/**
 * Constant-time string comparison to prevent timing attacks
 * @param a - First string
 * @param b - Second string
 * @returns True if strings are equal
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;

  const bufferA = Buffer.from(a, 'utf-8');
  const bufferB = Buffer.from(b, 'utf-8');

  return crypto.timingSafeEqual(bufferA, bufferB);
}

/**
 * Generate a cryptographically secure UUID
 * @returns UUID string
 */
export function generateUuid(): string {
  return crypto.randomUUID();
}
