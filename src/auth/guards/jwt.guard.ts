import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JWT, GRPC_ERROR_MESSAGES } from '../../common/constants';

import { JwtService } from '@nestjs/jwt';
import { RedisService } from '../redis.service';

@Injectable()
export class JwtGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const data = context.switchToRpc().getData(); 
    const accessToken = data?.accessToken;

    if (!accessToken) {
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
    }

    let decoded: any;
    try {
      decoded = this.jwtService.verify(accessToken, {
        secret: JWT. ACCESS_TOKEN_SECRET,
      });
    } catch (error) {
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.INVALID_TOKEN);
    }

    const userId = decoded.userId;
    const deviceId=decoded.deviceId;
    if (!userId || !deviceId) {
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
    }

    const storedToken = await this.redisService.getAccessToken(userId, deviceId);
    if (!storedToken || storedToken !== accessToken) {
      throw new UnauthorizedException(GRPC_ERROR_MESSAGES.UNAUTHORIZED);
    }

    return true;
  }
}
