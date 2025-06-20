import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { Session } from '../schemas/user-session.schema';
import { JWT, GRPC_ERROR_MESSAGES } from '../../providers/common/constants';
import { JwtService } from '@nestjs/jwt';
import { RedisService } from 'src/providers/redis/redis.service';
import { RedisKeys } from 'src/providers/redis/redis.key';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { Logger } from 'winston';

@Injectable()
export class JwtGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    @Inject(WINSTON_MODULE_PROVIDER) private readonly logger: Logger,
    @InjectModel(Session.name) private readonly SessionModel: Model<Session>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const data = context.switchToRpc().getData();
    const accessToken = data?.accessToken;

    if (!accessToken) {
      this.logger.warn('Access token missing from request.');
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
    }

    const decoded = this.jwtService.verify(accessToken, {
      secret: JWT.ACCESS_TOKEN_SECRET,
    });

    const { entityId, deviceId, role } = decoded;

    if (!entityId || !deviceId || !role) {
      this.logger.warn(
        `Decoded token missing required fields: entityId=${entityId}, deviceId=${deviceId}, role=${role}`,
      );
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
    }

    this.logger.debug('Token decoded', { entityId, deviceId, role });
    // Check if the access token exists in Redis
    const redisKey = RedisKeys.accessTokenKey(role, entityId, deviceId);
    const storedToken = await this.redisService.getAccessToken(redisKey);

    if (!storedToken) {
      this.logger.warn('No token found in Redis', { entityId, deviceId, role });
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
    }
    // check the user exists in the session collection
    const session = await this.SessionModel.findOne({
      entityId,
      deviceId,
      role,
      active: true,
    }).exec();

    if (!session) {
      this.logger.warn('No active session found', { entityId, deviceId, role });
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
    }

    this.logger.info('JWT validation passed', { entityId, deviceId, role });
    return true;
  }
}
