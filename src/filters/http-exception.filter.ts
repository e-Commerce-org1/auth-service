import { ExceptionFilter, Catch, ArgumentsHost, HttpException, Logger } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctxType = host.getType();

    if (ctxType === 'http') {
      const ctx = host.switchToHttp();
      const response = ctx.getResponse<Response>();
      const request = ctx.getRequest();

      const status = exception.getStatus();
      const errorResponse = exception.getResponse();
      const errorMessage = typeof errorResponse === 'string' ? errorResponse : errorResponse['message'];

      response.status(status).json({
        statusCode: status,
        timestamp: new Date().toISOString(),
        path: request.url,
        message: errorMessage,
      });

    } else if (ctxType === 'rpc') {
        const status = exception.getStatus();
        const errorResponse = exception.getResponse();
        const errorMessage = typeof errorResponse === 'string' ? errorResponse : errorResponse['message'] || 'Internal server error';
      
        // Log the full exception
        this.logger.error(`RpcException caught: ${errorMessage}`, exception.stack);
      
        throw new RpcException({
          statusCode: status,
          message: errorMessage,
        });
      }
  }
}     