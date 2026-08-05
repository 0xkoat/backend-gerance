import { ForbiddenException } from '@nestjs/common';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

export function requireTenantId(user: AuthenticatedUser): string {
  if (!user.tenantId) {
    throw new ForbiddenException('This account is not scoped to a tenant');
  }
  return user.tenantId;
}
