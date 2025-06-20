export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
}
export interface LoginRequest {
  email: string;
  deviceId: string;
  entityId: string;
}
export interface ValidateAccessTokenRequest {
  accessToken: string;
}

export interface ValidateAccessTokenResponse {
  isValid: boolean;
  entityId: string;
  role: string;
}
export interface AccessTokenRequest {
  refreshToken: string;
}

export interface AccessTokenResponse {
  accessToken: string;
}

export interface LogoutResponse {
  success: boolean;
}
export interface LogoutRequest {
  accessToken: string;
}
