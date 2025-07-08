import { 
  extractTokenFromHeader, 
  extractBearerToken, 
  validateAuthHeader,
  extractTokenByScheme,
  extractTokenFromCookie
} from '../../src/utils/headers';
import { MissingTokenError, MalformedTokenError } from '../../src/errors';

describe('Header Utilities', () => {
  describe('extractTokenFromHeader', () => {
    it('should extract token from valid Authorization header', () => {
      const authHeader = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
      const token = extractTokenFromHeader(authHeader);
      
      expect(token).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    });

    it('should return null for missing header', () => {
      const token = extractTokenFromHeader(undefined);
      expect(token).toBeNull();
    });

    it('should return null for invalid header format', () => {
      const invalidHeader = 'InvalidFormat';
      const token = extractTokenFromHeader(invalidHeader);
      
      expect(token).toBeNull();
    });

    it('should handle empty string header', () => {
      const token = extractTokenFromHeader('');
      expect(token).toBeNull();
    });
  });

  describe('extractBearerToken', () => {
    it('should extract Bearer token from header', () => {
      const authHeader = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
      const token = extractBearerToken(authHeader);
      
      expect(token).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    });

    it('should handle case-insensitive Bearer keyword', () => {
      const authHeaders = [
        'bearer token123',
        'Bearer token123',
        'BEARER token123',
        'BeArEr token123'
      ];
      
      authHeaders.forEach(header => {
        const token = extractBearerToken(header);
        expect(token).toBe('token123');
      });
    });

    it('should return null for non-Bearer headers', () => {
      const authHeader = 'Basic dXNlcjpwYXNzd29yZA==';
      const token = extractBearerToken(authHeader);
      
      expect(token).toBeNull();
    });

    it('should return null for missing header', () => {
      const token = extractBearerToken(undefined);
      expect(token).toBeNull();
    });
  });

  describe('validateAuthHeader', () => {
    it('should return true for valid Authorization header', () => {
      const validHeaders = [
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        'Basic dXNlcjpwYXNzd29yZA==',
        'Token abc123'
      ];
      
      validHeaders.forEach(header => {
        expect(validateAuthHeader(header)).toBe(true);
      });
    });

    it('should return false for invalid header format', () => {
      const invalidHeaders = [
        'InvalidFormat',
        '',
        'Bearer',
        'Bearer ',
        'NoScheme token123'
      ];
      
      invalidHeaders.forEach(header => {
        expect(validateAuthHeader(header)).toBe(false);
      });
    });

    it('should return false for undefined header', () => {
      expect(validateAuthHeader(undefined)).toBe(false);
    });
  });

  describe('extractTokenByScheme', () => {
    it('should extract token using custom scheme', () => {
      const authHeader = 'Basic dXNlcjpwYXNzd29yZA==';
      const token = extractTokenByScheme(authHeader, 'Basic');
      
      expect(token).toBe('dXNlcjpwYXNzd29yZA==');
    });

    it('should default to Bearer scheme', () => {
      const authHeader = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
      const token = extractTokenByScheme(authHeader);
      
      expect(token).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    });

    it('should be case-insensitive', () => {
      const authHeader = 'BEARER token123';
      const token = extractTokenByScheme(authHeader, 'bearer');
      
      expect(token).toBe('token123');
    });

    it('should return null for mismatched scheme', () => {
      const authHeader = 'Bearer token123';
      const token = extractTokenByScheme(authHeader, 'Basic');
      
      expect(token).toBeNull();
    });
  });

  describe('extractTokenFromCookie', () => {
    it('should extract token from cookie header', () => {
      const cookieHeader = 'token=abc123; othercookie=value';
      const token = extractTokenFromCookie(cookieHeader, 'token');
      
      expect(token).toBe('abc123');
    });

    it('should handle multiple cookies', () => {
      const cookieHeader = 'sessionId=xyz789; token=abc123; csrf=def456';
      const token = extractTokenFromCookie(cookieHeader, 'token');
      
      expect(token).toBe('abc123');
    });

    it('should use default cookie name', () => {
      const cookieHeader = 'token=defaultToken123';
      const token = extractTokenFromCookie(cookieHeader);
      
      expect(token).toBe('defaultToken123');
    });

    it('should return null for missing cookie', () => {
      const cookieHeader = 'sessionId=xyz789; csrf=def456';
      const token = extractTokenFromCookie(cookieHeader, 'token');
      
      expect(token).toBeNull();
    });

    it('should return null for undefined cookie header', () => {
      const token = extractTokenFromCookie(undefined, 'token');
      
      expect(token).toBeNull();
    });

    it('should handle URL-encoded cookie values', () => {
      const cookieHeader = 'token=abc%20123';
      const token = extractTokenFromCookie(cookieHeader, 'token');
      
      expect(token).toBe('abc 123');
    });
  });
});
