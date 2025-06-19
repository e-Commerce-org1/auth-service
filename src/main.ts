import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Transport, MicroserviceOptions } from '@nestjs/microservices';
import { join } from 'path';
import { GlobalExceptionFilter } from './providers/filters/http-exception.filter';

async function bootstrap() {
  // AuthService Microservice (gRPC)
  const app1 = await NestFactory.createMicroservice<MicroserviceOptions>(
    AppModule,
    {
      transport: Transport.GRPC,
      options: {
        package: 'auth',
        protoPath: join(__dirname, '../src/proto/auth.proto'),
        url: process.env.GRPC_PORT,
      },
    },
  );
  app1.useGlobalFilters(new GlobalExceptionFilter());
  await app1.listen();
  console.log('AuthService gRPC running on 0.0.0.0:5052');
}
bootstrap();
