import { ForbiddenException } from '@nestjs/common';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

// Narrows the JWT's nullable tenantId (null for the platform-wide Super Admin
// and Integration Admin) to a real string before touching tenant-scoped data.
// The one shared place for this check (users, modules, tickets): a
// tenant-less caller gets a clean 403 here rather than either a Prisma error
// from a null tenantId filter or, worse, silently querying across every
// tenant.
export function requireTenantId(user: AuthenticatedUser): string {
  if (!user.tenantId) {
    throw new ForbiddenException('This account is not scoped to a tenant');
  }
  return user.tenantId;
}
