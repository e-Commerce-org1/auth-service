export const JWT = {
    ACCESS_TOKEN_SECRET: process.env.JWT_SECRET || 'yashika',
    REFRESH_TOKEN_SECRET: process.env.JWT_REFRESH_TOKEN_SECRET || 'yashika1',
    ACCESS_EXPIRES_IN: '15m',
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
    SERVICE_UNAVAILABLE:'Authentication service unavailable',
  };
  
export const HTTP_STATUS_CODES = {
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    INTERNAL_SERVER_ERROR: 500,
  }; 