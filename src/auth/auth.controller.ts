import { Controller, UseGuards } from '@nestjs/common';
import { GrpcMethod, RpcException } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { JwtGuard } from './guards/jwt.guard';
import { LogoutRequest, AccessTokenRequest, ValidateAccessTokenRequest, LoginRequest } from './interfaces/auth.interface';

@Controller()
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService  
  ) {}

  @GrpcMethod('AuthService', 'getToken')
  async getToken(data: LoginRequest) {
    const payload = { entityId: data.entityId, email: data.email, role: data.role, deviceId: data.deviceId };
    return this.authService.getToken(payload);
  }

  @GrpcMethod('AuthService', 'accessToken')
  async accessToken(data:AccessTokenRequest) {
      return await this.authService.accessToken(data);
    }

@GrpcMethod('AuthService', 'logout')
async logout(data: LogoutRequest) {
  return await this.authService.logout(data);
}
  @UseGuards(JwtGuard)
  @GrpcMethod('AuthService', 'validateToken')
  async validateAccessToken(data:ValidateAccessTokenRequest){
     return await this.authService.validateAccessToken(data);
     
  }
}
