import { Injectable, UnauthorizedException, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { UserSession } from './schemas/user-session.schema';
import { RedisService } from './redis.service';
import { JWT, GRPC_ERROR_MESSAGES, HTTP_STATUS_CODES } from '../common/constants';
import {
  LoginResponse,
  ValidateAccessTokenResponse,
  AccessTokenResponse,
  LogoutResponse,
  LoginRequest,
  AccessTokenRequest,
  ValidateAccessTokenRequest,
  LogoutRequest,
  
} from './interfaces/auth.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    @InjectModel(UserSession.name) private readonly userSessionModel: Model<UserSession>,
    private readonly redisService: RedisService,
  ) {}

 
    async getToken(loginRequest: LoginRequest): Promise<LoginResponse> {
    try {
      const accessToken = await this.createToken(loginRequest, 'access');
      const refreshToken = await this.createToken(loginRequest, 'refresh');

      await this.redisService.storeAccessToken(loginRequest.userId, loginRequest.deviceId, accessToken);

      await this.userSessionModel.create({
        userId: loginRequest.userId,
        deviceId: loginRequest.deviceId,
        email: loginRequest.email,
        role: loginRequest.role,
        refreshToken,
        active: true,
      });

     
      return { accessToken, refreshToken };
    } catch (error) {
      throw new HttpException(GRPC_ERROR_MESSAGES.LOGIN_FAILED,
        HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR);
    }
  }
  async accessToken(request: AccessTokenRequest): Promise<AccessTokenResponse> {
    try {
      const { refreshToken } = request;
      const decoded = this.jwtService.verify(refreshToken, {
        secret: JWT.REFRESH_TOKEN_SECRET,
      });
  
      const { userId, deviceId } = decoded;
      const session = await this.userSessionModel.findOne({
        userId,
        deviceId,
        refreshToken,
        active: true,
      });
  
      if (!session) {
        throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
      }
      const accessToken = await this.createToken(
        { userId, email: session.email, role: session.role, deviceId },
        'access'
      );
      await this.redisService.storeAccessToken(userId, deviceId, accessToken);
  
      return { accessToken };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
  
      throw new HttpException(
        GRPC_ERROR_MESSAGES.SERVICE_UNAVAILABLE ,
  HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR
      );
    }
  }
  

  async logout(request: LogoutRequest): Promise<LogoutResponse> {
    try {
      const decoded = this.jwtService.verify(request.accessToken, {
        secret: JWT.ACCESS_TOKEN_SECRET,
      });
  
      const { userId, deviceId } = decoded;
  
      await this.redisService.deleteAccessToken(userId, deviceId);
      await this.userSessionModel.updateOne(
        { userId, deviceId, active: true },
        { $set: { active: false } }
      );
  
      return { success: true };
    } catch (error) {
      console.log(error)
      if (error instanceof HttpException) {
        throw error;
      }
  
      throw new HttpException(GRPC_ERROR_MESSAGES.LOGOUT_FAILED, HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR);
    }
  }
  

  async validateAccessToken(validateToken: ValidateAccessTokenRequest): Promise<ValidateAccessTokenResponse> {
    try {
      const { accessToken } = validateToken;
  
      const decoded = this.jwtService.verify(accessToken, {
        secret: JWT.ACCESS_TOKEN_SECRET,
      });
  
      const { userId, deviceId } = decoded;
  
      const storedToken = await this.redisService.getAccessToken(userId, deviceId);
      if (!storedToken || storedToken !== accessToken) {
        throw new UnauthorizedException(GRPC_ERROR_MESSAGES.INVALID_TOKEN);
      }
  
      return {
        isValid: true,
        message: 'Access token is valid',
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
  
      throw new HttpException(GRPC_ERROR_MESSAGES.VALIDATION_FAILED, HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR);
    }
  }
  


  private async createToken(payload: { userId: string, email: string, role: string, deviceId: string }, type: 'access' | 'refresh') {
    const secret = type === 'access' ? JWT.ACCESS_TOKEN_SECRET : JWT.REFRESH_TOKEN_SECRET;
    const expiresIn = type === 'access' ? JWT.ACCESS_EXPIRES_IN : JWT.REFRESH_EXPIRES_IN ;

    return this.jwtService.sign(payload, { secret, expiresIn });
  }
}
