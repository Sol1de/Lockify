import {
  generateSecureRandom,
  generateJwtSecret,
  hashSha256,
  generateHmac,
  verifyHmac,
  constantTimeCompare,
  generateUuid
} from '../../src/utils/security';

describe('Security Utilities', () => {
describe('generateSecureRandom', () => {
it('should generate random string of specified length', () => {
      const length = 16;
      const randomString = generateSecureRandom(length);
      expect(randomString).toHaveLength(length);
    });

it('should generate different strings on each call', () => {
      const string1 = generateSecureRandom(16);
      const string2 = generateSecureRandom(16);
      expect(string1).not.toBe(string2);
    });

it('should throw error for invalid length', () => {
      expect(() => generateSecureRandom(0)).toThrow('Length must be a positive integer');
      expect(() => generateSecureRandom(-1)).toThrow('Length must be a positive integer');
      expect(() => generateSecureRandom(3.14)).toThrow('Length must be a positive integer');
    });

it('should use default length when no parameter provided', () => {
      const randomString = generateSecureRandom();
      expect(randomString).toHaveLength(32);
    });
  });

describe('generateJwtSecret', () => {
it('should generate JWT secret of specified length', () => {
      const length = 64;
      const jwtSecret = generateJwtSecret(length);
      expect(jwtSecret).toHaveLength(length);
    });

it('should generate cryptographically secure secret', () => {
      const secret1 = generateJwtSecret(64);
      const secret2 = generateJwtSecret(64);
      expect(secret1).not.toBe(secret2);
    });

it('should throw error for secret length less than 32', () => {
      expect(() => generateJwtSecret(31)).toThrow('JWT secret must be at least 32 characters long');
    });

it('should use default length when no parameter provided', () => {
      const jwtSecret = generateJwtSecret();
      expect(jwtSecret).toHaveLength(64);
    });
  });

describe('hashSha256', () => {
it('should generate consistent SHA-256 hash', () => {
      const data = 'test-data';
      const hash = hashSha256(data);
      expect(hash).toBe(hashSha256(data));
      expect(hash).toHaveLength(64);
    });

it('should generate different hashes for different inputs', () => {
      const data1 = 'data1';
      const data2 = 'data2';
      expect(hashSha256(data1)).not.toBe(hashSha256(data2));
    });

it('should handle empty string', () => {
      const hash = hashSha256('');
      expect(hash).toHaveLength(64);
    });
  });

describe('generateHmac', () => {
    const data = 'test-data';
    const secret = 'test-secret';

it('should generate HMAC signature', () => {
      const hmac = generateHmac(data, secret);
      expect(typeof hmac).toBe('string');
      expect(hmac).toHaveLength(64);
    });

it('should use specified algorithm', () => {
      const hmacSha256 = generateHmac(data, secret, 'sha256');
      const hmacSha512 = generateHmac(data, secret, 'sha512');
      expect(hmacSha256).not.toBe(hmacSha512);
      expect(hmacSha256).toHaveLength(64);
      expect(hmacSha512).toHaveLength(128);
    });

it('should throw error for empty data or secret', () => {
      expect(() => generateHmac('', secret)).toThrow('Data and secret are required');
      expect(() => generateHmac(data, '')).toThrow('Data and secret are required');
    });
  });

describe('verifyHmac', () => {
    const data = 'test-data';
    const secret = 'test-secret';
    const validSignature = generateHmac(data, secret);

it('should verify valid HMAC signature', () => {
      expect(verifyHmac(data, validSignature, secret)).toBe(true);
    });

it('should reject invalid HMAC signature', () => {
      const invalidSignature = 'invalid-signature';
      expect(verifyHmac(data, invalidSignature, secret)).toBe(false);
    });
  });

describe('constantTimeCompare', () => {
it('should return true for equal strings', () => {
      const str1 = 'hello world';
      const str2 = 'hello world';
      expect(constantTimeCompare(str1, str2)).toBe(true);
    });

it('should return false for different strings', () => {
      const str1 = 'hello world';
      const str2 = 'hello universe';
      expect(constantTimeCompare(str1, str2)).toBe(false);
    });

it('should prevent timing attacks', () => {
      const str1 = 'short';
      const str2 = 'much longer string';
      expect(constantTimeCompare(str1, str2)).toBe(false);
    });
  });

describe('generateUuid', () => {
it('should generate valid UUID', () => {
      const uuid = generateUuid();
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      expect(uuidRegex.test(uuid)).toBe(true);
    });

it('should generate unique UUIDs', () => {
      const uuid1 = generateUuid();
      const uuid2 = generateUuid();
      expect(uuid1).not.toBe(uuid2);
    });
  });
});
