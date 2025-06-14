import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Transport, MicroserviceOptions } from '@nestjs/microservices';
import { join } from 'path';
import { HttpExceptionFilter } from './providers/filters/http-exception.filter';
import { WinstonModule } from 'nest-winston';
import { winstonLoggerConfig } from './providers/common/winston.logger';


async function bootstrap() {
  // HTTP Server 
  // const app = await NestFactory.create(AppModule);
  // app.useGlobalFilters(new HttpExceptionFilter());
  // await app.listen(3003);
 

  // AuthService Microservice (gRPC)
  const app1 = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
    transport: Transport.GRPC,
    options: {
      package: 'auth',
      protoPath: join(__dirname, '../src/proto/auth.proto'),
      url: process.env.GRPC_PORT, 
    },
  });
  app1.useGlobalFilters(new HttpExceptionFilter());
  await app1.listen();
  console.log('AuthService gRPC running on 0.0.0.0:5052');  
}

bootstrap();
