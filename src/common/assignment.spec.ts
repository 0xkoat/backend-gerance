import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { resolveAssignee, assertCanTransitionStatus } from './assignment';
import { PrismaService } from '../prisma/prisma.service';
import { UserRole } from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

// Kept untyped (not cast to PrismaService here) so `expect(...findFirst)`
// refers to a plain jest.fn(), not an unbound PrismaClient method reference
// — the PrismaService cast only happens at each resolveAssignee call site.
const mockPrismaService = {
  user: {
    findFirst: jest.fn(),
  },
};

function authUser(overrides: Partial<AuthenticatedUser>): AuthenticatedUser {
  return {
    userId: 'caller-1',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    mustChangePassword: false,
    ...overrides,
  };
}

describe('resolveAssignee', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns the caller id when an Analyst omits assignedToUserId (self-assign)', async () => {
    const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });

    const result = await resolveAssignee(
      mockPrismaService as unknown as PrismaService,
      caller,
      'tenant-1',
      undefined,
    );

    expect(result).toBe('analyst-1');
    expect(mockPrismaService.user.findFirst).not.toHaveBeenCalled();
  });

  it('returns the caller id when an Analyst explicitly assigns to themselves', async () => {
    const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });

    const result = await resolveAssignee(
      mockPrismaService as unknown as PrismaService,
      caller,
      'tenant-1',
      'analyst-1',
    );

    expect(result).toBe('analyst-1');
  });

  it('throws when an Analyst tries to assign to someone else', async () => {
    const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });

    await expect(
      resolveAssignee(
        mockPrismaService as unknown as PrismaService,
        caller,
        'tenant-1',
        'analyst-2',
      ),
    ).rejects.toThrow(ForbiddenException);
    expect(mockPrismaService.user.findFirst).not.toHaveBeenCalled();
  });

  it('throws when an Admin omits assignedToUserId', async () => {
    const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });

    await expect(
      resolveAssignee(
        mockPrismaService as unknown as PrismaService,
        caller,
        'tenant-1',
        undefined,
      ),
    ).rejects.toThrow(ForbiddenException);
  });

  it('resolves to the target id when an Admin assigns a valid tenant Analyst/Admin', async () => {
    const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
    mockPrismaService.user.findFirst.mockResolvedValue({
      id: 'analyst-2',
    });

    const result = await resolveAssignee(
      mockPrismaService as unknown as PrismaService,
      caller,
      'tenant-1',
      'analyst-2',
    );

    expect(result).toBe('analyst-2');
    expect(mockPrismaService.user.findFirst).toHaveBeenCalledWith({
      where: {
        id: 'analyst-2',
        tenantId: 'tenant-1',
        role: { in: [UserRole.ANALYST, UserRole.ADMIN] },
      },
    });
  });

  it('throws NotFoundException when the target does not exist in the tenant', async () => {
    const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
    mockPrismaService.user.findFirst.mockResolvedValue(null);

    await expect(
      resolveAssignee(
        mockPrismaService as unknown as PrismaService,
        caller,
        'tenant-1',
        'missing-id',
      ),
    ).rejects.toThrow(NotFoundException);
  });
});

describe('assertCanTransitionStatus', () => {
  it('allows an Admin regardless of who the record is assigned to', () => {
    const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });

    expect(() =>
      assertCanTransitionStatus(caller, 'someone-else'),
    ).not.toThrow();
    expect(() => assertCanTransitionStatus(caller, null)).not.toThrow();
  });

  it('allows the assigned Analyst', () => {
    const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });

    expect(() => assertCanTransitionStatus(caller, 'analyst-1')).not.toThrow();
  });

  it('rejects an Analyst who is not the assignee', () => {
    const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });

    expect(() => assertCanTransitionStatus(caller, 'analyst-2')).toThrow(
      ForbiddenException,
    );
  });

  it('rejects an Analyst when the record has no assignee at all', () => {
    const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });

    expect(() => assertCanTransitionStatus(caller, null)).toThrow(
      ForbiddenException,
    );
  });
});
