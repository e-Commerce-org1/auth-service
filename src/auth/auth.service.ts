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
import { UserDocument } from './schemas/user.schema';
import { RedisKeys } from '../providers/redis/redis.key';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { Logger } from 'winston';
import { LogMessages } from 'src/providers/common/log-message';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(WINSTON_MODULE_PROVIDER) private readonly logger: Logger,
    @InjectModel('Session')
    private readonly sessionModel: Model<Session>,
    @InjectModel('User')
    private readonly userModel: Model<UserDocument>,
    private readonly redisService: RedisService,
  ) {}

  async getToken(loginRequest: LoginRequest): Promise<LoginResponse> {
    this.logger.info(LogMessages.LOGIN_ATTEMPT, {
      entityId: loginRequest.entityId,
    });

    const user = await this.userModel.findById(loginRequest.entityId);
    let Role: 'admin' | 'user';

    if (user) {
      if (!user.isActive) {
        this.logger.warn(LogMessages.INACTIVE_USER_LOGIN_ATTEMPT, {
          entityId: loginRequest.entityId,
        });
        throw new HttpException(
          GRPC_ERROR_MESSAGES.USER_INACTIVE,
          HTTP_STATUS_CODES.FORBIDDEN,
        );
      }
      Role = 'user';
    } else {
      Role = 'admin';
    }

    const accessToken = await this.generateJwtToken({ ...loginRequest, role: Role }, 'access');
    const refreshToken = await this.generateJwtToken({ ...loginRequest, role: Role }, 'refresh');

    const accessTokenRedisKey = RedisKeys.accessTokenKey(Role, loginRequest.entityId, loginRequest.deviceId);

    await this.redisService.storeAccessToken(
      accessToken,
      accessTokenRedisKey,
      RedisKeys.TTL.ACCESS_TOKEN,
    );

    await this.sessionModel.create({
      entityId: loginRequest.entityId,
      deviceId: loginRequest.deviceId,
      email: loginRequest.email,
      role: Role,
      refreshToken,
      active: true,
    });

    this.logger.info(
      Role === 'admin' ? LogMessages.ADMIN_LOGIN_SUCCESSFUL : LogMessages.LOGIN_SUCCESSFUL,
      { entityId: loginRequest.entityId },
    );

    return { accessToken, refreshToken };
  }

  async accessToken(refreshTokenRequest: AccessTokenRequest): Promise<AccessTokenResponse> {
    this.logger.info(LogMessages.RECEIVED_REFRESH_TOKEN_REQUEST);

    const { refreshToken } = refreshTokenRequest;
    const decodedRefreshToken = this.jwtService.verify(refreshToken, {
      secret: JWT.REFRESH_TOKEN_SECRET,
    });

    const { entityId, deviceId, role } = decodedRefreshToken;
    this.logger.debug(
      `${LogMessages.DECODED_REFRESH_TOKEN}: ${entityId}, deviceId: ${deviceId}, role: ${role}`,
    );

    const activeSession = await this.sessionModel.findOne({
      entityId,
      deviceId,
      role,
      refreshToken,
      active: true,
    });

    if (!activeSession) {
      this.logger.warn(LogMessages.NO_ACTIVE_SESSION_FOR_REFRESH_TOKEN, { entityId });
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
    }

    const newAccessToken = await this.generateJwtToken(
      {
        entityId,
        email: activeSession.email,
        role: activeSession.role,
        deviceId,
      },
      'access',
    );

    const accessTokenRedisKey = RedisKeys.accessTokenKey(role, entityId, deviceId);

    await this.redisService.storeAccessToken(newAccessToken, accessTokenRedisKey, RedisKeys.TTL.ACCESS_TOKEN);

    return { accessToken: newAccessToken };
  }

  async logout(logoutRequest: LogoutRequest): Promise<LogoutResponse> {
    this.logger.info(LogMessages.LOGOUT_ATTEMPT);

    const decodedAccessToken = this.jwtService.verify(logoutRequest.accessToken, {
      secret: JWT.ACCESS_TOKEN_SECRET,
    });

    const { entityId, deviceId, role } = decodedAccessToken;
    this.logger.debug(LogMessages.DECODED_ACCESS_TOKEN_FOR_LOGOUT, {
      entityId,
      deviceId,
      role,
    });

    const accessTokenRedisKey = RedisKeys.accessTokenKey(role, entityId, deviceId);

    await this.redisService.deleteAccessToken(accessTokenRedisKey);

    await this.sessionModel.updateOne(
      { entityId, deviceId, role, active: true },
      { $set: { active: false } },
    );

    this.logger.info(LogMessages.LOGOUT_SUCCESSFUL, { entityId });
    return { success: true };
  }

  async validateAccessToken(
    validateTokenRequest: ValidateAccessTokenRequest,
  ): Promise<ValidateAccessTokenResponse> {
    const { accessToken } = validateTokenRequest;
    this.logger.info(LogMessages.VALIDATING_ACCESS_TOKEN);

    const decodedAccessToken = this.jwtService.verify(accessToken, {
      secret: JWT.ACCESS_TOKEN_SECRET,
    });

    const { entityId, deviceId, role } = decodedAccessToken;
    this.logger.debug(LogMessages.DECODED_ACCESS_TOKEN, { entityId, deviceId, role });

    const accessTokenRedisKey = RedisKeys.accessTokenKey(role, entityId, deviceId);
    const storedAccessToken = await this.redisService.getAccessToken(accessTokenRedisKey);

    if (storedAccessToken !== accessToken) {
      this.logger.warn(LogMessages.ACCESS_TOKEN_MISMATCH, { entityId });
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.INVALID_TOKEN);
    }

    this.logger.info(LogMessages.ACCESS_TOKEN_VALID, { entityId });
    return {
      isValid: true,
      entityId,
    };
  }

  private async generateJwtToken(
    payload: {
      entityId: string;
      email: string;
      role: string;
      deviceId: string;
    },
    tokenType: 'access' | 'refresh',
  ): Promise<string> {
    const secret = tokenType === 'access' ? JWT.ACCESS_TOKEN_SECRET : JWT.REFRESH_TOKEN_SECRET;
    const expiresIn = tokenType === 'access' ? JWT.ACCESS_EXPIRES_IN : JWT.REFRESH_EXPIRES_IN;

    return await this.jwtService.sign(payload, { secret, expiresIn });
  }
}