import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Transport, MicroserviceOptions } from '@nestjs/microservices';
import { join } from 'path';
import { HttpExceptionFilter } from './filters/http-exception.filter';

async function bootstrap() {
  // HTTP Server 
  const app = await NestFactory.create(AppModule);
  app.useGlobalFilters(new HttpExceptionFilter());
  await app.listen(3000);
 

  // AuthService Microservice (gRPC)
  const app1 = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
    transport: Transport.GRPC,
    options: {
      package: 'auth',
      protoPath: join(__dirname, '../proto/auth.proto'),
      url: '0.0.0.0:5051', 
    },
  });
  app1.useGlobalFilters(new HttpExceptionFilter());
  await app1.listen();
  console.log('AuthService gRPC running on 0.0.0.0:5051');
}

bootstrap();
