/**
 * Jest setup file for global test configuration
 */

// Mock environment variables for testing
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';

// Extend Jest matchers if needed
// import '@testing-library/jest-dom/extend-expect';

// Global test utilities can be added here
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(global as any).testUtils = {
  mockUser: {
    id: '123',
    email: 'test@example.com',
    role: 'user'
  },
  mockAdmin: {
    id: '456', 
    email: 'admin@example.com',
    role: 'admin'
  }
};

// Console.log suppression during tests (optional)
const originalConsoleError = console.error;
beforeAll(() => {
  console.error = jest.fn();
});

afterAll(() => {
  console.error = originalConsoleError;
});
