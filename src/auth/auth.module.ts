import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { RedisService } from './redis.service';
import { JwtGuard } from './guards/jwt.guard';
import { UserSession, UserSessionSchema } from './schemas/user-session.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: UserSession.name, schema: UserSessionSchema }]),
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: process.env.JWT_EXPIRES_IN },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, RedisService, JwtGuard],
  exports: [AuthService, JwtGuard],
})
export class AuthModule {}
