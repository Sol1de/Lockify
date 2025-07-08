# Lockify 🔐

A lightweight, framework-agnostic authentication package for Node.js with bcrypt and JWT helpers. Designed to be simple, secure, and compatible with all Node.js frameworks.

[![npm version](https://badge.fury.io/js/lockify.svg)](https://badge.fury.io/js/lockify)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

## Features

- 🔒 **Secure password hashing** with bcrypt
- 🎫 **JWT token generation and validation**
- 🌐 **Framework-agnostic** - works with Express, Koa, Fastify, and more
- 📝 **Full TypeScript support** with type definitions
- 🛡️ **Custom error handling** for better debugging
- ⚙️ **Advanced JWT options** (expiration, issuer, audience, etc.)
- 🧪 **Thoroughly tested** with Jest
- 📦 **Zero configuration** - works out of the box

## Installation

```bash
npm install lockify
# or
yarn add lockify
# or
pnpm add lockify
```

## Quick Start

```typescript
import { 
  hashPassword, 
  comparePassword, 
  generateToken, 
  verifyToken, 
  requireAuth,
  optionalAuth,
  requireRole,
  validatePassword,
  generateSalt
} from 'lockify';

// Hash a password
const hashedPassword = await hashPassword('mySecretPassword');

// Compare password
const isValid = await comparePassword('mySecretPassword', hashedPassword);

// Generate JWT token
const token = generateToken({ userId: 123, role: 'user' }, 'your-secret-key');

// Verify JWT token
const decoded = verifyToken(token, 'your-secret-key');
```

## API Reference

### Password Helpers

#### `hashPassword(password: string): Promise<string>`

Hashes a password using bcrypt with a default salt rounds of 12.

```typescript
const hashedPassword = await hashPassword('userPassword123');
console.log(hashedPassword); // $2b$12$...
```

#### `comparePassword(password: string, hash: string): Promise<boolean>`

Compares a plain text password with a bcrypt hash.

```typescript
const isValid = await comparePassword('userPassword123', hashedPassword);
console.log(isValid); // true or false
```

#### `validatePassword(password: string, options?: PasswordValidationOptions): boolean`

Validates password strength according to security requirements.

```typescript
const isStrong = validatePassword('MySecurePassword123!', {
  minLength: 8,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true
});
console.log(isStrong); // true or false
```

#### `generateSalt(rounds?: number): Promise<string>`

Generates a random salt for bcrypt hashing.

```typescript
const salt = await generateSalt(12);
console.log(salt); // $2b$12$...
```

### JWT Helpers

#### `generateToken(payload: JwtPayload, secret: string, options?: JwtOptions): string`

Generates a JWT token with the given payload and secret.

```typescript
// Basic usage
const token = generateToken({ userId: 123 }, 'your-secret-key');

// With options
const token = generateToken(
  { userId: 123, role: 'admin' },
  'your-secret-key',
  {
    expiresIn: '24h',
    issuer: 'your-app-name',
    audience: 'your-users'
  }
);
```

#### `verifyToken(token: string, secret: string): JwtPayload`

Verifies and decodes a JWT token. Throws an error if the token is invalid or expired.

```typescript
try {
  const decoded = verifyToken(token, 'your-secret-key');
  console.log('User ID:', decoded.userId);
} catch (error) {
  console.log('Token verification failed:', error.message);
}
```

#### `decodeToken(token: string): JwtPayload | null`

Decodes a JWT token without verification (unsafe). Returns `null` if the token is malformed.

```typescript
const decoded = decodeToken(token);
if (decoded) {
  console.log('Token payload:', decoded);
}
```

#### `isTokenExpired(token: string): boolean`

Checks if a JWT token is expired.

```typescript
const expired = isTokenExpired(token);
console.log('Token expired:', expired);
```

#### `getTokenExpiration(token: string): Date | null`

Gets the expiration date of a JWT token.

```typescript
const expiration = getTokenExpiration(token);
if (expiration) {
  console.log('Token expires at:', expiration);
}
```

#### `refreshToken(token: string, secret: string, options?: JwtOptions): string`

Refreshes an existing token with a new expiration time.

```typescript
const newToken = refreshToken(oldToken, 'your-secret-key', {
  expiresIn: '24h'
});
```

### Authentication Middleware

#### `requireAuth(getUserById: GetUserById, secret: string): MiddlewareFunction`

Creates a middleware function that requires authentication for accessing protected routes.

```typescript
type GetUserById = (id: string) => Promise<any>;

const authMiddleware = requireAuth(
  async (id: string) => {
    // Your user lookup logic
    return await db.users.findById(id);
  },
  'your-jwt-secret'
);
```

#### `optionalAuth(getUserById: GetUserById, secret: string): MiddlewareFunction`

Creates an optional authentication middleware that adds user information to the request if a valid token is provided, but doesn't fail if no token is present.

```typescript
const optionalAuthMiddleware = optionalAuth(
  async (id: string) => {
    return await db.users.findById(id);
  },
  'your-jwt-secret'
);
```

#### `requireRole(getUserById: GetUserById, secret: string, allowedRoles: string[]): MiddlewareFunction`

Creates a role-based authentication middleware that checks if the authenticated user has the required role(s).

```typescript
const adminMiddleware = requireRole(
  async (id: string) => {
    return await db.users.findById(id);
  },
  'your-jwt-secret',
  ['admin', 'superuser']
);
```

## Framework Integration Examples

### Express.js

```typescript
import express from 'express';
import { requireAuth, generateToken, hashPassword, comparePassword } from 'lockify';

const app = express();
app.use(express.json());

// User lookup function
const getUserById = async (id: string) => {
  // Replace with your actual user lookup logic
  return await db.users.findById(id);
};

// Create auth middleware
const authMiddleware = requireAuth(getUserById, process.env.JWT_SECRET!);

// Public route - Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email
    const user = await db.users.findByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const isValid = await comparePassword(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token
    const token = generateToken(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET!,
      { expiresIn: '24h' }
    );
    
    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Public route - Register
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Hash password
    const hashedPassword = await hashPassword(password);
    
    // Create user
    const user = await db.users.create({
      email,
      password: hashedPassword
    });
    
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route
app.get('/profile', authMiddleware, (req, res) => {
  // req.user is available here
  res.json({ user: req.user });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### Koa.js

```typescript
import Koa from 'koa';
import Router from 'koa-router';
import { requireAuth } from 'lockify';

const app = new Koa();
const router = new Router();

// User lookup function
const getUserById = async (id: string) => {
  return await db.users.findById(id);
};

// Create auth middleware
const authMiddleware = requireAuth(getUserById, process.env.JWT_SECRET!);

// Convert to Koa middleware
const koaAuthMiddleware = async (ctx: Koa.Context, next: Koa.Next) => {
  await new Promise((resolve, reject) => {
    authMiddleware(ctx.request, ctx.response, (err?: any) => {
      if (err) reject(err);
      else resolve(void 0);
    });
  });
  await next();
};

// Protected route
router.get('/profile', koaAuthMiddleware, async (ctx) => {
  ctx.body = { user: ctx.request.user };
});

app.use(router.routes());
app.listen(3000);
```

### Fastify

```typescript
import fastify from 'fastify';
import { requireAuth } from 'lockify';

const app = fastify();

// User lookup function
const getUserById = async (id: string) => {
  return await db.users.findById(id);
};

// Create auth middleware
const authMiddleware = requireAuth(getUserById, process.env.JWT_SECRET!);

// Register as Fastify plugin
app.register(async (fastify) => {
  fastify.addHook('preHandler', async (request, reply) => {
    await new Promise((resolve, reject) => {
      authMiddleware(request.raw, reply.raw, (err?: any) => {
        if (err) reject(err);
        else resolve(void 0);
      });
    });
  });
  
  fastify.get('/profile', async (request, reply) => {
    return { user: (request.raw as any).user };
  });
});

app.listen({ port: 3000 });
```

## TypeScript Support

Lockify is written in TypeScript and provides full type definitions:

```typescript
import { 
  JwtPayload, 
  JwtOptions, 
  GetUserById, 
  AuthError,
  HashOptions,
  PasswordValidationOptions
} from 'lockify';

// Custom JWT payload
interface CustomPayload extends JwtPayload {
  userId: number;
  role: 'admin' | 'user';
  permissions: string[];
}

// Strongly typed user lookup
const getUserById: GetUserById = async (id: string) => {
  const user = await db.users.findById(id);
  if (!user) throw new AuthError('User not found');
  return user;
};

// Generate token with custom payload
const token = generateToken<CustomPayload>(
  {
    userId: 123,
    role: 'admin',
    permissions: ['read', 'write']
  },
  'secret'
);

// Hash password with custom options
const hash = await hashPassword('password', { saltRounds: 14 });

// Validate password with custom rules
const isValid = validatePassword('password', {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true
});
```

## Error Handling

Lockify provides custom error classes for better error handling:

```typescript
import { 
  AuthError, 
  TokenError, 
  HashError,
  InvalidTokenError,
  ExpiredTokenError,
  MissingTokenError,
  MalformedTokenError,
  UserNotFoundError,
  InvalidPasswordError,
  WeakPasswordError
} from 'lockify';

try {
  const decoded = verifyToken(token, secret);
} catch (error) {
  if (error instanceof ExpiredTokenError) {
    console.log('Token has expired:', error.message);
  } else if (error instanceof InvalidTokenError) {
    console.log('Invalid token:', error.message);
  } else if (error instanceof TokenError) {
    console.log('Token error:', error.message);
  } else if (error instanceof AuthError) {
    console.log('Auth error:', error.message);
  }
}
```

### Error Types

- `AuthError`: General authentication errors
- `TokenError`: JWT token related errors
- `HashError`: Password hashing related errors
- `InvalidTokenError`: Invalid token format or signature
- `ExpiredTokenError`: Token has expired
- `MissingTokenError`: No token provided
- `MalformedTokenError`: Token format is invalid
- `UserNotFoundError`: User lookup failed
- `InvalidPasswordError`: Password validation failed
- `WeakPasswordError`: Password doesn't meet security requirements

## Advanced Configuration

### JWT Options

```typescript
interface JwtOptions {
  expiresIn?: string | number;
  issuer?: string;
  audience?: string | string[];
  subject?: string;
  algorithm?: 
    | 'HS256' | 'HS384' | 'HS512'
    | 'RS256' | 'RS384' | 'RS512'
    | 'PS256' | 'PS384' | 'PS512'
    | 'ES256' | 'ES384' | 'ES512'
    | 'none';
  keyid?: string;
  noTimestamp?: boolean;
  header?: { [key: string]: unknown };
  encoding?: string;
}

interface HashOptions {
  saltRounds?: number;
}

interface PasswordValidationOptions {
  minLength?: number;
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSymbols?: boolean;
  forbiddenPasswords?: string[];
}
```

### Custom Salt Rounds for Bcrypt

```typescript
import { hashPassword } from 'lockify';

// Default salt rounds (12)
const hash1 = await hashPassword('password');

// Custom salt rounds
const hash2 = await hashPassword('password', { saltRounds: 14 });
```

## Best Practices

1. **Environment Variables**: Always store JWT secrets in environment variables
2. **Token Expiration**: Set appropriate expiration times for tokens
3. **Error Handling**: Always handle authentication errors gracefully
4. **HTTPS**: Use HTTPS in production to protect tokens in transit
5. **Refresh Tokens**: Implement refresh token mechanism for better security

```typescript
// Good practice example
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

const token = generateToken(
  { userId: user.id },
  JWT_SECRET,
  { expiresIn: JWT_EXPIRES_IN }
);
```

## Utility Functions

Lockify provides additional utility functions for enhanced security and validation:

### Header Utilities

```typescript
import {
  extractTokenFromHeader,
  extractBearerToken,
  validateAuthHeader,
  extractTokenByScheme,
  extractTokenFromCookie
} from 'lockify';

// Extract token from Authorization header
const token = extractTokenFromHeader('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');

// Extract specifically Bearer tokens
const bearerToken = extractBearerToken('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');

// Extract token by custom scheme
const customToken = extractTokenByScheme('Custom eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', 'Custom');

// Extract token from cookie string
const cookieToken = extractTokenFromCookie('auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', 'auth_token');
```

### Validation Utilities

```typescript
import {
  validatePasswordStrength,
  validateEmail,
  validateJwtSecret,
  sanitizeInput,
  isPasswordForbidden
} from 'lockify';

// Validate password strength
const isStrong = validatePasswordStrength('MyPassword123!');

// Validate email format
const isValidEmail = validateEmail('user@example.com');

// Validate JWT secret strength
const isSecureSecret = validateJwtSecret('your-super-secret-key');

// Sanitize user input
const clean = sanitizeInput('<script>alert("xss")</script>user input');

// Check if password is in forbidden list
const isForbidden = isPasswordForbidden('password123', ['password123', '123456']);
```

### Security Utilities

```typescript
import {
  generateSecureRandom,
  generateJwtSecret,
  hashSha256,
  generateHmac,
  verifyHmac,
  constantTimeCompare,
  generateUuid
} from 'lockify';

// Generate secure random bytes
const randomBytes = generateSecureRandom(32);

// Generate secure JWT secret
const jwtSecret = generateJwtSecret(64);

// Hash data with SHA-256
const hash = hashSha256('data to hash');

// Generate HMAC
const hmac = generateHmac('data', 'secret');

// Verify HMAC
const isValid = verifyHmac('data', 'secret', hmac);

// Constant-time string comparison
const isEqual = constantTimeCompare('string1', 'string2');

// Generate UUID
const uuid = generateUuid();
```

## Testing

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/lockify.git

# Install dependencies
npm install

# Run in development mode
npm run dev

# Build the project
npm run build

# Run tests
npm test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📧 **Email**: support@lockify.dev
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/lockify/issues)
- 📖 **Documentation**: [GitHub Wiki](https://github.com/yourusername/lockify/wiki)

## Changelog

### v1.0.0
- ✨ **Enhanced Authentication System**
  - Password hashing with bcrypt and configurable salt rounds
  - Advanced password validation with customizable strength requirements
  - JWT token generation, verification, and management
  - Token refresh functionality and expiration checking
  - Multiple authentication middleware options (required, optional, role-based)
- 🛡️ **Security Features**
  - Comprehensive error handling with specific error types
  - Secure random generation and HMAC utilities
  - Constant-time comparison functions
  - Input sanitization and validation
- 🌐 **Framework Compatibility**
  - Works with Express, Koa, Fastify, and other Node.js frameworks
  - Framework-agnostic middleware design
- 📝 **TypeScript Support**
  - Full type definitions for all functions and interfaces
  - Generic support for custom JWT payloads
  - Type-safe middleware functions
- 🧪 **Testing & Quality**
  - Comprehensive test suite with Jest
  - ESLint and Prettier configuration
  - CI/CD pipeline integration

---

Made with ❤️ by the Lockify team
