import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SKIP_PASSWORD_CHECK_KEY } from '../decorators/skip-password-check.decorator';
import type { AuthenticatedUser } from '../jwt.strategy';

// Third of the three global guards. Blocks every route for a user whose
// mustChangePassword flag is still set, except ones explicitly opted out
// via @SkipPasswordCheck() (e.g. logout, and the self-change route itself).
// Forces a fresh account through the mandatory first-login password change
// before it can touch anything else in the API.
@Injectable()
export class MustChangePasswordGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const skip = this.reflector.getAllAndOverride<boolean>(
      SKIP_PASSWORD_CHECK_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (skip) {
      return true;
    }

    const request = context
      .switchToHttp()
      .getRequest<{ user?: AuthenticatedUser }>();
    const user = request.user;

    if (!user) {
      return true;
    }

    if (user.mustChangePassword) {
      throw new ForbiddenException(
        'You must change your password before continuing',
      );
    }

    return true;
  }
}
