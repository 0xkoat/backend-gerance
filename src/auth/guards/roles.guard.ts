import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
  CanActivate,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { UserRole } from '../../generated/prisma/enums';
import type { Request } from 'express';
import type { AuthenticatedUser } from '../jwt.strategy';

// Second of the three global guards, runs after JwtAuthGuard, so
// context.user is already populated for any non-public route by the time
// this checks @Roles(). A route with no @Roles() decorator at all (handler
// or controller level) is open to any authenticated role.
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (!requiredRoles) {
      return true;
    }
    const { user } = context
      .switchToHttp()
      .getRequest<Request & { user?: AuthenticatedUser }>();
    if (!user || !user.role) {
      throw new UnauthorizedException('User role not found');
    }
    return requiredRoles.includes(user.role);
  }
}
