import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import type { AuthenticatedUser } from '../../auth/jwt.strategy';

const INTERNAL_SERVER_ERROR: number = HttpStatus.INTERNAL_SERVER_ERROR;

// The one place every exception that reaches the HTTP boundary passes
// through, from any controller or service, caught or not. Logs it, then
// returns the exact response NestJS would have sent anyway — this filter
// adds logging, it never changes response behavior.
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request & { user?: AuthenticatedUser }>();

    const isHttpException = exception instanceof HttpException;
    const status: number = isHttpException
      ? exception.getStatus()
      : INTERNAL_SERVER_ERROR;
    const body = isHttpException
      ? exception.getResponse()
      : { statusCode: status, message: 'Internal server error' };

    const context = `${request.method} ${request.originalUrl} tenantId=${request.user?.tenantId ?? 'n/a'} userId=${request.user?.userId ?? 'n/a'}`;

    if (status >= INTERNAL_SERVER_ERROR) {
      // Real application faults — the client got an unexpected 500, this is
      // the one place that's guaranteed to see it and log it with a stack.
      const stack = exception instanceof Error ? exception.stack : undefined;
      this.logger.error(`${context} -> ${status}`, stack);
    } else {
      // Expected, client-driven outcomes (404, 403, 409, validation
      // failures...) — not application bugs, so not worth error/warn noise
      // that would drown out the failures that actually matter.
      this.logger.debug(`${context} -> ${status}`);
    }

    response.status(status).json(body);
  }
}
