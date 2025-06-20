import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { RedisService } from '../providers/redis/redis.service';
import { JwtGuard } from './guards/jwt.guard';
import { Session, SessionSchema } from './schemas/user-session.schema';
import { UserSchema } from './schemas/user.schema';
import { RedisModule } from '../providers/redis/redis.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Session.name, schema: SessionSchema },
      { name: 'User', schema: UserSchema },
    ]),

    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: process.env.JWT_EXPIRES_IN },
    }),
    RedisModule,
  ],

  controllers: [AuthController],
  providers: [AuthService, RedisService, JwtGuard],
})
export class AuthModule {}
