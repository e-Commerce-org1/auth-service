import {
  Injectable,
  UnauthorizedException,
  HttpException,
  Inject,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Session } from './schemas/user-session.schema';
import { RedisService } from 'src/providers/redis/redis.service';
import {
  JWT,
  GRPC_ERROR_MESSAGES,
  HTTP_STATUS_CODES,
} from '../providers/common/constants';
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
import {  UserDocument } from './schemas/user.schema';
import { RedisKeys } from '../providers/redis/redis.key';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { Logger } from 'winston';
import { LogMessages } from 'src/providers/common/log-message';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(WINSTON_MODULE_PROVIDER) private readonly logger:Logger,
    @InjectModel('Session')
    private readonly SessionModel: Model<Session>,
    @InjectModel('User')
    private readonly userModel: Model<UserDocument>,
    private readonly redisService: RedisService,
    
  ) {}
//generating access and refresh tokens
  async getToken(loginRequest: LoginRequest): Promise<LoginResponse> {
    try {
      this.logger.info(LogMessages.LOGIN_ATTEMPT, { entityId: loginRequest.entityId });
      if (loginRequest.role === 'admin') {
      
        this.logger.info(LogMessages.GENERATING_ADMIN_TOKENS, { entityId: loginRequest.entityId });
        const accessToken = await this.createToken(loginRequest, 'access');
        const refreshToken = await this.createToken(loginRequest, 'refresh');
  
        const redisKey = RedisKeys.accessTokenKey(
          loginRequest.role,
          loginRequest.entityId,
          loginRequest.deviceId
        );
        await this.redisService.storeAccessToken(
          accessToken,
          redisKey,
          RedisKeys.TTL.ACCESS_TOKEN
        );
       //session creation for admin
        await this.SessionModel.create({
          entityId: loginRequest.entityId,
          deviceId: loginRequest.deviceId,
          email: loginRequest.email,
          role: loginRequest.role,
          refreshToken,
          active: true,
        });
        this.logger.info(LogMessages.ADMIN_LOGIN_SUCCESSFUL, { entityId: loginRequest.entityId });
        return { accessToken, refreshToken };
      } else {
        const user = await this.userModel.findById(loginRequest.entityId);
  
        if (!user) {
          this.logger.warn(LogMessages.USER_NOT_FOUND, { entityId: loginRequest.entityId });
          throw new HttpException(GRPC_ERROR_MESSAGES.NOT_FOUND, HTTP_STATUS_CODES.NOT_FOUND);
        }
  
        if (!user.isActive) {
          this.logger.warn(LogMessages.INACTIVE_USER_LOGIN_ATTEMPT, { entityId: loginRequest.entityId });
          throw new HttpException(GRPC_ERROR_MESSAGES.USER_INACTIVE, HTTP_STATUS_CODES.FORBIDDEN);
        }
  
        const accessToken = await this.createToken(loginRequest, 'access');
        const refreshToken = await this.createToken(loginRequest, 'refresh');
  
        const redisKey = RedisKeys.accessTokenKey(
          loginRequest.role,
          loginRequest.entityId,
          loginRequest.deviceId
        );
  
        await this.redisService.storeAccessToken(
          accessToken,
          redisKey,
          RedisKeys.TTL.ACCESS_TOKEN
        );
       //session creation for user
        await this.SessionModel.create({
          entityId: loginRequest.entityId,
          deviceId: loginRequest.deviceId,
          email: loginRequest.email,
          role: loginRequest.role,
          refreshToken,
          active: true,
        });
  
        this.logger.info(LogMessages.LOGIN_SUCCESSFUL, { entityId: loginRequest.entityId });
        return { accessToken, refreshToken };
      }
    } catch (error) {
      this.logger.error(`${LogMessages.LOGIN_FAILED}: ${loginRequest.entityId}`, error.stack);
      throw new HttpException(
        GRPC_ERROR_MESSAGES.LOGIN_FAILED,
        HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR
      );
    }
  }
  //regenarting access token logic
  async accessToken(request: AccessTokenRequest): Promise<AccessTokenResponse> {
    try {
      this.logger.info(LogMessages.RECEIVED_REFRESH_TOKEN_REQUEST);
      const { refreshToken } = request;
      const decoded = this.jwtService.verify(refreshToken, {
        secret: JWT.REFRESH_TOKEN_SECRET,
      });

      const { entityId, deviceId, role } = decoded;
      this.logger.debug(`${LogMessages.DECODED_REFRESH_TOKEN}: ${entityId}, deviceId: ${deviceId}, role: ${role}`);

      const session = await this.SessionModel.findOne({
        entityId,
        deviceId,
        role,
        refreshToken,
        active: true,
      });

      if (!session) {
        this.logger.warn(LogMessages.NO_ACTIVE_SESSION_FOR_REFRESH_TOKEN, { entityId });
        throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
      }

      const accessToken = await this.createToken(
        {
          entityId,
          email: session.email,
          role: session.role,
          deviceId,
        },
        'access'
      );

      const redisKey = RedisKeys.accessTokenKey(role, entityId, deviceId);

      await this.redisService.storeAccessToken(
        accessToken,
        redisKey,
        RedisKeys.TTL.ACCESS_TOKEN
      );
      return { accessToken };
    } catch (error) {
      this.logger.error(LogMessages.ACCESS_TOKEN_GENERATION_FAILED, {
        error: error.stack || error.message,
      });
      if (error instanceof HttpException) throw error;

      throw new HttpException(
        GRPC_ERROR_MESSAGES.SERVICE_UNAVAILABLE,
        HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR
      );
    }
  }
//logout logic
  async logout(request: LogoutRequest): Promise<LogoutResponse> {
    try {
      this.logger.info(LogMessages.LOGOUT_ATTEMPT);
      const decoded = this.jwtService.verify(request.accessToken, {
        secret: JWT.ACCESS_TOKEN_SECRET,
      });

      const { entityId, deviceId, role } = decoded;
      this.logger.debug(LogMessages.DECODED_ACCESS_TOKEN_FOR_LOGOUT, { entityId, deviceId, role });
      const redisKey = RedisKeys.accessTokenKey(role, entityId, deviceId);

      await this.redisService.deleteAccessToken(redisKey);

      await this.SessionModel.updateOne(
        { entityId, deviceId, role, active: true },
        { $set: { active: false } }
      );

      this.logger.info(LogMessages.LOGOUT_SUCCESSFUL, { entityId });
      return { success: true };
    } catch (error) {
      this.logger.error(LogMessages.LOGOUT_FAILED, {
        error: error.stack || error.message,
      });
      if (error instanceof HttpException) throw error;

      throw new HttpException(
        GRPC_ERROR_MESSAGES.LOGOUT_FAILED,
        HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR
      );
    }
  }
//validation logic
  async validateAccessToken(
    validateToken: ValidateAccessTokenRequest
  ): Promise<ValidateAccessTokenResponse> {
    try {
      const { accessToken } = validateToken;
      this.logger.info(LogMessages.VALIDATING_ACCESS_TOKEN);
      const decoded = this.jwtService.verify(accessToken, {
        secret: JWT.ACCESS_TOKEN_SECRET,
      });
      const { entityId, deviceId, role } = decoded;
      this.logger.debug(LogMessages.DECODED_ACCESS_TOKEN, { entityId, deviceId, role });
      const redisKey = RedisKeys.accessTokenKey(role, entityId, deviceId);
      const storedToken = await this.redisService.getAccessToken(redisKey);

      if (storedToken !== accessToken) {
        this.logger.warn(LogMessages.ACCESS_TOKEN_MISMATCH, { entityId });
        throw new UnauthorizedException(GRPC_ERROR_MESSAGES.INVALID_TOKEN);
      }

      this.logger.info(LogMessages.ACCESS_TOKEN_VALID, { entityId });
      return {
        isValid: true,
        entityId,
      };
    } catch (error) {
      this.logger.error(LogMessages.ACCESS_TOKEN_VALIDATION_FAILED, {
        error: error.stack || error.message,
      });
      if (error instanceof HttpException) throw error;

      throw new HttpException(
        GRPC_ERROR_MESSAGES.VALIDATION_FAILED,
        HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR
      );
    }
  }
//method to generate access and refresh tokens
  private async createToken(
    payload: {
      entityId: string;
      email: string;
      role: string;
      deviceId: string;
    },
    type: 'access' | 'refresh'
  ): Promise<string> {
    const secret =
      type === 'access'
        ? JWT.ACCESS_TOKEN_SECRET
        : JWT.REFRESH_TOKEN_SECRET;
    const expiresIn =
      type === 'access'
        ? JWT.ACCESS_EXPIRES_IN
        : JWT.REFRESH_EXPIRES_IN;

    return this.jwtService.sign(payload, { secret, expiresIn });
  }
}
