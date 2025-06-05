import { Controller, UseGuards } from '@nestjs/common';
import { GrpcMethod, RpcException } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { JwtGuard } from './guards/jwt.guard';
import { LogoutRequest, AccessTokenRequest, ValidateAccessTokenRequest, ValidateAccessTokenResponse } from './interfaces/auth.interface';

@Controller()
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService  
  ) {}

  @GrpcMethod('AuthService', 'getToken')
  async getToken(data: { email: string, role: string, deviceId: string, entityId:string}) {
    const payload = { entityId: data.entityId, email: data.email, role: data.role, deviceId: data.deviceId };
    return this.authService.getToken(payload);
  }

  @GrpcMethod('AuthService', 'accessToken')
  async accessToken(data:AccessTokenRequest) {
    console.log('Received accessToken request:', data);
      return await this.authService.accessToken(data);
    }

@GrpcMethod('AuthService', 'logout')
async logout(data: LogoutRequest) {
  return await this.authService.logout(data);
}
  @UseGuards(JwtGuard)
  @GrpcMethod('AuthService', 'validateToken')
  async validateAccessToken(data:{accessToken:string}){
     return await this.authService.validateAccessToken(data);
     
  }
}
