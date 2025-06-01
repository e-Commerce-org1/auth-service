
export interface LoginResponse {
    accessToken: string;
    refreshToken: string;
  }
   export interface LoginRequest {
    email: string;
    deviceId: string; 
    role: string;
    userId: string; 
  }
  export interface ValidateAccessTokenRequest{
    accessToken:string;
  }
  
  export interface ValidateAccessTokenResponse {
    isValid: boolean;
    userId: string;
  }
  export interface AccessTokenRequest{
    refreshToken:string;
  }
  
  export interface AccessTokenResponse {
    accessToken: string;
  }
  
  export interface LogoutResponse {
    success: boolean;
  }
  export interface LogoutRequest{
    accessToken:string;
  }
  