import { 
  validatePasswordStrength, 
  validateEmail, 
  validateJwtSecret,
  sanitizeInput,
  isPasswordForbidden,
  DEFAULT_PASSWORD_OPTIONS
} from '../../src/utils/validation';
import { WeakPasswordError } from '../../src/errors';

describe('Validation Utilities', () => {
  describe('validatePasswordStrength', () => {
    it('should validate strong password', () => {
      const strongPassword = 'StrongPassword123!';
      
      expect(() => validatePasswordStrength(strongPassword)).not.toThrow();
      expect(validatePasswordStrength(strongPassword)).toBe(true);
    });

    it('should reject weak password', () => {
      const weakPasswords = [
        'weak',                    // Too short
        'NoNumbersOrSpecial',     // No numbers or special chars
        'no-uppercase-123!',      // No uppercase
        'NO-LOWERCASE-123!',      // No lowercase
        'NoSpecialChars123',      // No special chars
        'password'                // Forbidden password
      ];
      
      weakPasswords.forEach(password => {
        expect(() => validatePasswordStrength(password)).toThrow(WeakPasswordError);
      });
    });

    it('should use custom validation options', () => {
      const customOptions = {
        minLength: 6,
        requireSpecialChars: false,
        forbiddenPasswords: ['custom-forbidden']
      };
      
      // This should pass with custom options (no special chars required)
      expect(() => validatePasswordStrength('Simple123', customOptions)).not.toThrow();
      expect(validatePasswordStrength('Simple123', customOptions)).toBe(true);
      
      // This should fail due to custom forbidden list
      expect(() => validatePasswordStrength('custom-forbidden', customOptions)).toThrow(WeakPasswordError);
    });

    it('should reject password exceeding max length', () => {
      const tooLongPassword = 'A'.repeat(129) + '1!';
      
      expect(() => validatePasswordStrength(tooLongPassword)).toThrow(WeakPasswordError);
    });
  });

  describe('validateEmail', () => {
    it('should validate correct email format', () => {
      const validEmails = [
        'test@example.com',
        'user.name@domain.co.uk',
        'first+last@company.org',
        'user123@test-domain.com'
      ];
      
      validEmails.forEach(email => {
        expect(validateEmail(email)).toBe(true);
      });
    });

    it('should reject invalid email format', () => {
      const invalidEmails = [
        'plainaddress',
        '@missingdomain.com',
        'missing@.com',
        'spaces @domain.com',
        'double@@domain.com',
        '',
        '   ',
        'user@',
        '@domain.com'
      ];
      
      invalidEmails.forEach(email => {
        expect(validateEmail(email)).toBe(false);
      });
    });
  });

  describe('validateJwtSecret', () => {
    it('should validate strong JWT secret', () => {
      const strongSecrets = [
        'MyVeryStrongJwtSecret123!@#$%^&*()',  // Has lowercase, uppercase, numbers, special chars
        'AnotherGoodSecret789-+=_[]{}Test',    // Has lowercase, uppercase, numbers, special chars  
        'ComplexSecret2023!withMixedChars123'  // Has lowercase, uppercase, numbers, special chars
      ];
      
      strongSecrets.forEach(secret => {
        expect(validateJwtSecret(secret)).toBe(true);
      });
    });

    it('should reject weak JWT secret', () => {
      const weakSecrets = [
        '',                          // Empty
        'short',                     // Too short
        'toolowercaseonly',         // Only lowercase
        'TOOUPPERCASE',             // Only uppercase
        '1234567890123456789012345678901234567890' // Only numbers
      ];
      
      weakSecrets.forEach(secret => {
        expect(validateJwtSecret(secret)).toBe(false);
      });
    });
  });

  describe('sanitizeInput', () => {
    it('should sanitize malicious input', () => {
      const maliciousInputs = [
        '<script>alert("xss")</script>',
        '<img src="x" onerror="alert(1)">',
        'javascript:alert(1)',
        '<div onclick="malicious()">content</div>',
        '<svg onload="alert(1)">'
      ];
      
      maliciousInputs.forEach(input => {
        const sanitized = sanitizeInput(input);
        expect(sanitized).not.toContain('<script>');
        expect(sanitized).not.toContain('javascript:');
        expect(sanitized).not.toContain('onclick');
        expect(sanitized).not.toContain('onload');
        expect(sanitized).not.toContain('onerror');
      });
    });

    it('should preserve safe input', () => {
      const safeInputs = [
        { input: 'Hello World', expectedContent: 'Hello' },
        { input: 'This is a normal sentence.', expectedContent: 'normal' },
        { input: 'Numbers 123 and symbols @#$', expectedContent: 'Numbers' },
        { input: 'Line breaks\nare preserved', expectedContent: 'Line' }
      ];
      
      safeInputs.forEach(({ input, expectedContent }) => {
        const sanitized = sanitizeInput(input);
        expect(sanitized).toContain(expectedContent);
      });
    });

    it('should handle HTML entities correctly', () => {
      const input = '"quotes" & ampersands';
      const sanitized = sanitizeInput(input);
      
      expect(sanitized).toContain('&quot;');
      expect(sanitized).toContain('&amp;');
    });

    it('should remove HTML tags completely', () => {
      const input = '<div>content</div><p>paragraph</p>';
      const sanitized = sanitizeInput(input);
      
      expect(sanitized).toBe('contentparagraph');
      expect(sanitized).not.toContain('<');
      expect(sanitized).not.toContain('>');
    });
  });

  describe('isPasswordForbidden', () => {
    it('should detect forbidden passwords', () => {
      const forbiddenList = ['password', '123456', 'admin', 'qwerty'];
      
      // Exact matches
      expect(isPasswordForbidden('password', forbiddenList)).toBe(true);
      expect(isPasswordForbidden('PASSWORD', forbiddenList)).toBe(true); // Case insensitive
      expect(isPasswordForbidden('admin', forbiddenList)).toBe(true);
      
      // Substantial part matches
      expect(isPasswordForbidden('password123', forbiddenList)).toBe(true);
      expect(isPasswordForbidden('mypassword', forbiddenList)).toBe(true);
    });

    it('should allow non-forbidden passwords', () => {
      const forbiddenList = ['password', '123456', 'admin'];
      
      const allowedPasswords = [
        'StrongPassword2023!',
        'MySecurePass',
        'ComplexPhrase789',
        'pass' // Too short to be considered substantial part
      ];
      
      allowedPasswords.forEach(password => {
        expect(isPasswordForbidden(password, forbiddenList)).toBe(false);
      });
    });

    it('should handle edge cases', () => {
      expect(isPasswordForbidden('', [])).toBe(false);
      expect(isPasswordForbidden('password', [])).toBe(false);
      expect(isPasswordForbidden('', ['password'])).toBe(false);
      expect(isPasswordForbidden('password', null as any)).toBe(false);
      expect(isPasswordForbidden('password', undefined as any)).toBe(false);
    });
  });
});
