import { Controller, UseGuards } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { JwtGuard } from './guards/jwt.guard';
import {
  LogoutRequest,
  AccessTokenRequest,
  ValidateAccessTokenRequest,
  LoginRequest,
} from './interfaces/auth.interface';
import {
  GRPC_AUTH_SERVICE,
  AUTHGRPCMETHODS,
} from '../providers/common/constants';
@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  //generating token
  @GrpcMethod(GRPC_AUTH_SERVICE, AUTHGRPCMETHODS.GET_TOKEN)
  async getToken(data: LoginRequest) {
    return this.authService.getToken(data);
  }
  // generating access token
  @GrpcMethod(GRPC_AUTH_SERVICE, AUTHGRPCMETHODS.ACCESS_TOKEN)
  async accessToken(data: AccessTokenRequest) {
    return await this.authService.accessToken(data);
  }
  // logout
  @GrpcMethod(GRPC_AUTH_SERVICE, AUTHGRPCMETHODS.LOGOUT)
  async logout(data: LogoutRequest) {
    return await this.authService.logout(data);
  }
  //validating access token
  @UseGuards(JwtGuard)
  @GrpcMethod(GRPC_AUTH_SERVICE, AUTHGRPCMETHODS.VALIDATE_TOKEN)
  async validateAccessToken(data: ValidateAccessTokenRequest) {
    return await this.authService.validateAccessToken(data);
  }
}
