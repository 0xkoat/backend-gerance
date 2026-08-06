import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { UserRole } from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { PrismaService } from '../prisma/prisma.service';

// Admins can assign to any Analyst/Admin in their own tenant; Analysts can
// only ever self-assign. Viewer never reaches this — the route's @Roles
// decorator blocks it before the service layer runs.
export async function resolveAssignee(
  prisma: PrismaService,
  caller: AuthenticatedUser,
  tenantId: string,
  requestedAssigneeId: string | undefined,
): Promise<string> {
  if (caller.role === UserRole.ANALYST) {
    if (requestedAssigneeId && requestedAssigneeId !== caller.userId) {
      throw new ForbiddenException(
        'Analysts can only assign records to themselves',
      );
    }
    return caller.userId;
  }

  if (!requestedAssigneeId) {
    throw new ForbiddenException(
      'assignedToUserId is required when an Admin assigns a record',
    );
  }

  const target = await prisma.user.findFirst({
    where: {
      id: requestedAssigneeId,
      tenantId,
      role: { in: [UserRole.ANALYST, UserRole.ADMIN] },
    },
  });
  if (!target) {
    throw new NotFoundException('Target user not found in this tenant');
  }

  return requestedAssigneeId;
}

// Only the current assignee or an Admin may escalate/resolve a record — an
// unrelated Analyst can't close out someone else's assigned work.
export function assertCanTransitionStatus(
  caller: AuthenticatedUser,
  currentAssignedToUserId: string | null,
): void {
  if (caller.role === UserRole.ADMIN) {
    return;
  }
  if (currentAssignedToUserId !== caller.userId) {
    throw new ForbiddenException(
      'Only the assigned analyst or an Admin can change this status',
    );
  }
}
