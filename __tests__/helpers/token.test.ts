import { 
  generateToken, 
  verifyToken, 
  decodeToken, 
  isTokenExpired,
  getTokenExpiration,
  refreshToken
} from '../../src/helpers/token';
import { TokenError, InvalidTokenError, ExpiredTokenError } from '../../src/errors';

import jwt from 'jsonwebtoken';

describe('Token Helpers', () => {
  const secret = 'test-secret';
  const payload = { userId: 123, role: 'user' };

  describe('generateToken', () => {
    it('should generate a valid JWT token', () => {
      const token = generateToken(payload, secret);
      const decoded = jwt.verify(token, secret);

      expect(typeof token).toBe('string');
      expect(decoded).toMatchObject(payload);
    });

    it('should generate token with custom options', () => {
      const options = { expiresIn: '1h' };
      const token = generateToken(payload, secret, options);
      const decoded = jwt.verify(token, secret) as jwt.JwtPayload;

      expect(decoded.exp).toBeDefined();
    });

    it('should throw error for invalid secret', () => {
      expect(() => generateToken(payload, '')).toThrow(TokenError);
    });
  });

  describe('verifyToken', () => {
    it('should verify and decode a valid token', () => {
      const token = generateToken(payload, secret);
      const decodedPayload = verifyToken(token, secret);

      expect(decodedPayload).toMatchObject(payload);
    });

    it('should throw InvalidTokenError for invalid token', () => {
      const invalidToken = 'invalid.token.string';

      expect(() => verifyToken(invalidToken, secret)).toThrow(InvalidTokenError);
    });

    it('should throw ExpiredTokenError for expired token', () => {
      const token = jwt.sign(payload, secret, { expiresIn: '-1s' });

      expect(() => verifyToken(token, secret)).toThrow(ExpiredTokenError);
    });
  });

  describe('decodeToken', () => {
    it('should decode token without verification', () => {
      const token = generateToken(payload, secret);
      const decoded = decodeToken(token);

      expect(decoded).toMatchObject(payload);
    });

    it('should return null for malformed token', () => {
      const malformedToken = 'malformed.token';
      expect(decodeToken(malformedToken)).toBeNull();
    });
  });

  describe('isTokenExpired', () => {
    it('should return true for expired token', () => {
      const token = jwt.sign(payload, secret, { expiresIn: '-1s' });

      expect(isTokenExpired(token)).toBe(true);
    });

    it('should return false for valid token', () => {
      const token = generateToken(payload, secret);

      expect(isTokenExpired(token)).toBe(false);
    });
  });

  describe('getTokenExpiration', () => {
    it('should return expiration date for token with exp claim', () => {
      const token = generateToken(payload, secret, { expiresIn: '1h' });
      const expiration = getTokenExpiration(token);

      expect(expiration).toBeInstanceOf(Date);
    });

    it('should return null for token without exp claim', () => {
      const tokenWithoutExp = jwt.sign(payload, secret);
      const expiration = getTokenExpiration(tokenWithoutExp);

      expect(expiration).toBeNull();
    });
  });

  describe('refreshToken', () => {
    it('should generate new token with refreshed expiration', () => {
      const token = generateToken(payload, secret, { expiresIn: '1h' });
      const newToken = refreshToken(token, secret, { expiresIn: '2h' });

      const oldExp = getTokenExpiration(token);
      const newExp = getTokenExpiration(newToken);

      expect(newExp).toBeGreaterThan(oldExp!);
    });

    it('should preserve original payload in refreshed token', () => {
      const token = generateToken(payload, secret);
      const refreshedToken = refreshToken(token, secret);
      const decoded = decodeToken(refreshedToken);

      expect(decoded).toMatchObject(payload);
    });
  });
});
