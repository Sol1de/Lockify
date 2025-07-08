import { hashPassword, comparePassword, validatePassword, generateSalt } from '../../src/helpers/password';
import { HashError } from '../../src/errors';

describe('Password Helpers', () => {
  describe('hashPassword', () => {
    it('should hash a password successfully', async () => {
      const password = 'TestPassword123!';
      const hash = await hashPassword(password);
      
      expect(typeof hash).toBe('string');
      expect(hash).toHaveLength(60); // bcrypt hashes are 60 characters
      expect(hash.startsWith('$2b$')).toBe(true); // bcrypt format
      expect(hash).not.toBe(password);
    });

    it('should use custom salt rounds when provided', async () => {
      const password = 'TestPassword123!';
      const customSaltRounds = 10;
      const hash = await hashPassword(password, { saltRounds: customSaltRounds });
      
      expect(typeof hash).toBe('string');
      expect(hash).toHaveLength(60);
      expect(hash).toContain('$10$'); // Should contain the salt rounds
    });

    it('should throw HashError for invalid input', async () => {
      // Mock bcrypt to throw an error
      const bcrypt = require('bcrypt');
      const originalHash = bcrypt.hash;
      bcrypt.hash = jest.fn().mockRejectedValue(new Error('Bcrypt error'));
      
      await expect(hashPassword('password')).rejects.toThrow(HashError);
      await expect(hashPassword('password')).rejects.toThrow('Failed to hash password');
      
      // Restore original function
      bcrypt.hash = originalHash;
    });
  });

  describe('comparePassword', () => {
    it('should return true for matching passwords', async () => {
      const password = 'TestPassword123!';
      const hash = await hashPassword(password);
      
      const result = await comparePassword(password, hash);
      expect(result).toBe(true);
    });

    it('should return false for non-matching passwords', async () => {
      const password = 'TestPassword123!';
      const wrongPassword = 'WrongPassword456!';
      const hash = await hashPassword(password);
      
      const result = await comparePassword(wrongPassword, hash);
      expect(result).toBe(false);
    });

    it('should handle malformed hashes gracefully', async () => {
      const password = 'TestPassword123!';
      const malformedHash = 'not-a-valid-hash';
      
      await expect(comparePassword(password, malformedHash)).rejects.toThrow(HashError);
      await expect(comparePassword(password, malformedHash)).rejects.toThrow('Failed to compare password');
    });
  });

  describe('validatePassword', () => {
    it('should return true for strong password', () => {
      const strongPassword = 'StrongPass123!';
      expect(validatePassword(strongPassword)).toBe(true);
    });

    it('should return false for weak passwords', () => {
      expect(validatePassword('weak')).toBe(false); // too short
      expect(validatePassword('nouppercasehere123!')).toBe(false); // no uppercase
      expect(validatePassword('NOLOWERCASEHERE123!')).toBe(false); // no lowercase
      expect(validatePassword('NoNumbersHere!')).toBe(false); // no numbers
      expect(validatePassword('NoSpecialChars123')).toBe(false); // no special chars
    });
  });

  describe('generateSalt', () => {
    it('should generate salt with default rounds', async () => {
      const salt = await generateSalt();
      expect(typeof salt).toBe('string');
      expect(salt.startsWith('$2b$12$')).toBe(true); // Default 12 rounds
    });

    it('should generate salt with custom rounds', async () => {
      const customRounds = 10;
      const salt = await generateSalt(customRounds);
      expect(typeof salt).toBe('string');
      expect(salt.startsWith('$2b$10$')).toBe(true);
    });

    it('should throw HashError when bcrypt fails', async () => {
      const bcrypt = require('bcrypt');
      const originalGenSalt = bcrypt.genSalt;
      bcrypt.genSalt = jest.fn().mockRejectedValue(new Error('Salt generation failed'));
      
      await expect(generateSalt()).rejects.toThrow(HashError);
      await expect(generateSalt()).rejects.toThrow('Failed to generate salt');
      
      // Restore original function
      bcrypt.genSalt = originalGenSalt;
    });
  });
});
