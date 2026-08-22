import { SetMetadata } from '@nestjs/common';
import { UserRole } from '../../generated/prisma/enums';

// Read by RolesGuard. No @Roles() at all on a route (handler or
// controller) means any authenticated role can call it — this decorator is
// only for narrowing access, never for opening it wider than "logged in".
export const ROLES_KEY = 'roles';
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
