export const JWT = {
  ACCESS_TOKEN_SECRET: process.env.JWT_SECRET || 'yashika',
  REFRESH_TOKEN_SECRET: process.env.JWT_REFRESH_TOKEN_SECRET || 'yashika1',
  ACCESS_EXPIRES_IN: '1d',
  REFRESH_EXPIRES_IN: '7d',
};

export const REDIS_CONFIG = {
  URL: process.env.REDIS_URL || 'redis://localhost:6379',
};

export const GRPC_ERROR_MESSAGES = {
  UNAUTHORIZED: 'Unauthorized access',
  INVALID_TOKEN: 'Invalid or expired token',
  LOGOUT_FAILED: 'Logout failed',
  LOGIN_FAILED: 'Login failed',
  VALIDATION_FAILED: 'Validation failed',
  SERVICE_UNAVAILABLE: 'Authentication service unavailable',
  NOT_FOUND: 'User not found',
  USER_INACTIVE: 'User is inactive',
  UNAUTHORIZED_ADMIN: 'Unauthorized admin',
  USER_NOT_FOUND: 'user not found',
};

export const HTTP_STATUS_CODES = {
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  INTERNAL_SERVER_ERROR: 500,
};

export const GRPC_AUTH_SERVICE = 'AuthService';

export const AUTHGRPCMETHODS = {
  GET_TOKEN: 'getToken',
  ACCESS_TOKEN: 'accessToken',
  LOGOUT: 'logout',
  VALIDATE_TOKEN: 'validateToken',
};
export const ADMIN_EMAIL = {
  EMAIL: 'mahi.rajput@appinventiv.com',
};
export const ROLES = {
  ADMIN: 'admin',
  USER: 'user',
} as const;

export type ROLETYPE = (typeof ROLES)[keyof typeof ROLES];

export const TOKEN_TYPES = {
  ACCESS: 'access',
  REFRESH: 'refresh',
} as const;

export type TokenType = (typeof TOKEN_TYPES)[keyof typeof TOKEN_TYPES];
