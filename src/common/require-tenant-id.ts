import { ForbiddenException } from '@nestjs/common';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

// Narrows the JWT's nullable tenantId (null for Super Admin, who isn't
// scoped to any tenant) to a real string before a controller touches
// tenant-scoped data. Shared by every one of the six module controllers —
// extracted (2026-08-05) after the identical check was duplicated across
// all of them. A Super Admin hitting one of these routes gets a clean 403
// here rather than either a Prisma error from a null tenantId filter or,
// worse, silently querying across every tenant.
export function requireTenantId(user: AuthenticatedUser): string {
  if (!user.tenantId) {
    throw new ForbiddenException('This account is not scoped to a tenant');
  }
  return user.tenantId;
}
