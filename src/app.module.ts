import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';
import { WinstonModule } from 'nest-winston';
import { winstonLoggerConfig } from './providers/common/winston.logger';


@Module({
  imports: [
    
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MongooseModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        uri: configService.get<string>('MONGODB_URI') || 'mongodb+srv://yashikasingh:Yashi%402003@cluster0.r0gt3.mongodb.net/',
         //uri: 'mongodb+srv://yashikasingh:Yashi%402003@cluster0.r0gt3.mongodb.net/',
         dbName:'eCommerce',
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    WinstonModule.forRoot(winstonLoggerConfig),
  ],
})
export class AppModule {}
