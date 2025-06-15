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
import { User, UserDocument } from './schemas/user.schema';
import { RedisKeys } from '../providers/redis/redis.key';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { Logger } from 'winston';
import { Observable } from 'rxjs';

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

  async getToken(loginRequest: LoginRequest): Promise<LoginResponse> {
    try {
      this.logger.info(`Login attempt`, { entityId: loginRequest.entityId, role: loginRequest.role });

  
      if (loginRequest.role === 'admin') {
      
        this.logger.info(`Generating tokens for admin`, { entityId: loginRequest.entityId });

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
  
        await this.SessionModel.create({
          entityId: loginRequest.entityId,
          deviceId: loginRequest.deviceId,
          email: loginRequest.email,
          role: loginRequest.role,
          refreshToken,
          active: true,
        });
  
        this.logger.info(`Admin login successful`, { entityId: loginRequest.entityId });
        return { accessToken, refreshToken };
      } else {
        const user = await this.userModel.findById(loginRequest.entityId);
  
        if (!user) {
          this.logger.warn(`User not found`, { entityId: loginRequest.entityId });
          throw new HttpException('User not found', HTTP_STATUS_CODES.NOT_FOUND);
        }
  
        if (!user.isActive) {
          this.logger.warn(`Inactive user login attempt`, { entityId: loginRequest.entityId });
          throw new HttpException('User is inactive', HTTP_STATUS_CODES.FORBIDDEN);
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
  
        await this.SessionModel.create({
          entityId: loginRequest.entityId,
          deviceId: loginRequest.deviceId,
          email: loginRequest.email,
          role: loginRequest.role,
          refreshToken,
          active: true,
        });
  
        this.logger.info(`Login successful`, { entityId: loginRequest.entityId });
        return { accessToken, refreshToken };
      }
    } catch (error) {
      this.logger.error(
        `Login failed for entityId: ${loginRequest.entityId}`,
        error.stack
      );
      throw new HttpException(
        GRPC_ERROR_MESSAGES.LOGIN_FAILED,
        HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR
      );
    }
  }
  
  async accessToken(request: AccessTokenRequest): Promise<AccessTokenResponse> {
    try {
      this.logger.info('Received request for new access token via refresh token.');
      const { refreshToken } = request;
      const decoded = this.jwtService.verify(refreshToken, {
        secret: JWT.REFRESH_TOKEN_SECRET,
      });

      const { entityId, deviceId, role } = decoded;
      this.logger.debug(`Decoded refreshToken for entityId: ${entityId}, deviceId: ${deviceId}, role: ${role}`);

      const session = await this.SessionModel.findOne({
        entityId,
        deviceId,
        role,
        refreshToken,
        active: true,
      });

      if (!session) {
        this.logger.warn('No active session found for refreshToken', { entityId });
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
      this.logger.error('Access token generation failed', {
        error: error.stack || error.message,
      });
      if (error instanceof HttpException) throw error;

      throw new HttpException(
        GRPC_ERROR_MESSAGES.SERVICE_UNAVAILABLE,
        HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR
      );
    }
  }

  async logout(request: LogoutRequest): Promise<LogoutResponse> {
    try {
      this.logger.info('Logout attempt received.');
      const decoded = this.jwtService.verify(request.accessToken, {
        secret: JWT.ACCESS_TOKEN_SECRET,
      });

      const { entityId, deviceId, role } = decoded;
      this.logger.debug('Decoded accessToken for logout', { entityId, deviceId, role });
      const redisKey = RedisKeys.accessTokenKey(role, entityId, deviceId);

      await this.redisService.deleteAccessToken(redisKey);

      await this.SessionModel.updateOne(
        { entityId, deviceId, role, active: true },
        { $set: { active: false } }
      );

      this.logger.info('Logout successful', { entityId });
      return { success: true };
    } catch (error) {
      this.logger.error('Logout failed', {
        error: error.stack || error.message,
      });
      if (error instanceof HttpException) throw error;

      throw new HttpException(
        GRPC_ERROR_MESSAGES.LOGOUT_FAILED,
        HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR
      );
    }
  }

  async validateAccessToken(
    validateToken: ValidateAccessTokenRequest
  ): Promise<ValidateAccessTokenResponse> {
    try {
      const { accessToken } = validateToken;
      this.logger.info('Validating access token.');
      const decoded = this.jwtService.verify(accessToken, {
        secret: JWT.ACCESS_TOKEN_SECRET,
      });

      const { entityId, deviceId, role } = decoded;
      this.logger.debug('Decoded accessToken', { entityId, deviceId, role });

      const redisKey = RedisKeys.accessTokenKey(role, entityId, deviceId);
      const storedToken = await this.redisService.getAccessToken(redisKey);

      if (storedToken !== accessToken) {
        this.logger.warn('Access token mismatch', { entityId });
        throw new UnauthorizedException(GRPC_ERROR_MESSAGES.INVALID_TOKEN);
      }

      this.logger.info('Access token is valid', { entityId });
      return {
        isValid: true,
        entityId,
      };
    } catch (error) {
      this.logger.error('Access token validation failed', {
        error: error.stack || error.message,
      });
      if (error instanceof HttpException) throw error;

      throw new HttpException(
        GRPC_ERROR_MESSAGES.VALIDATION_FAILED,
        HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR
      );
    }
  }

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
