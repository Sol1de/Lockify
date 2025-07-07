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
import { hashPassword, comparePassword, generateToken, verifyToken, requireAuth } from 'lockify';

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

#### `verifyToken(token: string, secret: string): JwtPayload | null`

Verifies and decodes a JWT token. Returns `null` if the token is invalid or expired.

```typescript
const decoded = verifyToken(token, 'your-secret-key');
if (decoded) {
  console.log('User ID:', decoded.userId);
} else {
  console.log('Invalid token');
}
```

### Authentication Middleware

#### `requireAuth(getUserById: GetUserById, secret: string): MiddlewareFunction`

Creates a middleware function that can be used with any Node.js framework.

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
import { JwtPayload, JwtOptions, GetUserById, AuthError } from 'lockify';

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
```

## Error Handling

Lockify provides custom error classes for better error handling:

```typescript
import { AuthError, TokenError, HashError } from 'lockify';

try {
  const decoded = verifyToken(token, secret);
} catch (error) {
  if (error instanceof TokenError) {
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

## Advanced Configuration

### JWT Options

```typescript
interface JwtOptions {
  expiresIn?: string | number;
  issuer?: string;
  audience?: string | string[];
  subject?: string;
  algorithm?: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
  keyid?: string;
  noTimestamp?: boolean;
  header?: object;
  encoding?: string;
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
- Initial release
- Basic password hashing with bcrypt
- JWT token generation and validation
- Framework-agnostic authentication middleware
- Full TypeScript support
- Custom error handling
- Advanced JWT options support

---

Made with ❤️ by the Lockify team
