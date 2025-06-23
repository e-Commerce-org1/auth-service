import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  UnauthorizedException,
} from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctxType = host.getType();

    if (ctxType === 'http') {
      const response = host.switchToHttp().getResponse();
      const status =
        exception instanceof HttpException ? exception.getStatus() : 500;

      response.status(status).json({
        statusCode: status,
        message:
          exception instanceof HttpException
            ? exception.message
            : 'Internal server error',
      });
    }

    if (ctxType === 'rpc') {
      // gRPC expects an RpcException to be thrown
      throw new RpcException(
        exception instanceof HttpException
          ? exception.message
          : 'Internal server error',
      );
    }
  }
}
