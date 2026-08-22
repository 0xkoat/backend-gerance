import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AuthenticatedUser } from '../jwt.strategy';
import { Request } from 'express';

// Param decorator: `@CurrentUser() user: AuthenticatedUser` in a controller
// method pulls the JwtStrategy-populated request.user off the request,
// instead of every controller reaching into `@Req()` and casting it by hand.
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthenticatedUser => {
    const request = ctx
      .switchToHttp()
      .getRequest<Request & { user: AuthenticatedUser }>();
    return request.user;
  },
);
