import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { AnalystLevel, Prisma, UserRole } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/createUser.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import * as argon2 from 'argon2';

// Checked against the current password plus this many prior ones — "last 5
// passwords" total, including the one about to be replaced.
const PASSWORD_HISTORY_CHECK_LIMIT = 4;

// Every ANALYST has a level and no other role has one. The database enforces
// the same rule (User_analystLevel_matches_role CHECK), this turns a
// violation into a 400 instead of a constraint-error 500.
function resolveAnalystLevel(
  role: UserRole,
  analystLevel: AnalystLevel | undefined,
): AnalystLevel | null {
  if (role === UserRole.ANALYST) {
    if (!analystLevel) {
      throw new BadRequestException('analystLevel is required for an Analyst');
    }
    return analystLevel;
  }
  if (analystLevel) {
    throw new BadRequestException(
      'analystLevel is only allowed for an Analyst',
    );
  }
  return null;
}

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(private readonly prisma: PrismaService) {}

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  // The tenant-isolation choke point every other tenant-scoped lookup below
  // routes through: a user existing is not enough, it must belong to the
  // caller's own tenant, a cross-tenant ID gets the same 404 as a
  // nonexistent one, so it can't be used to probe for other tenants' users.
  async findByIdForTenant(id: string, tenantId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user || user.tenantId !== tenantId) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async findAllForTenant(tenantId: string, page: number, pageSize: number) {
    const [users, total] = await this.prisma.$transaction([
      this.prisma.user.findMany({
        where: { tenantId },
        orderBy: { createdAt: 'asc' },
        skip: (page - 1) * pageSize,
        take: pageSize,
      }),
      this.prisma.user.count({ where: { tenantId } }),
    ]);

    return { users, total, page, pageSize };
  }

  // role and tenantId are always caller-supplied by the controller (from the
  // creator's own token / the endpoint being called), never taken from the
  // request body, per the provisioning hierarchy rules. mustChangePassword
  // is explicitly forced true here rather than relying on the schema default,
  // per a fixed bug where the column default alone meant no new account was
  // ever actually pushed through the forced-change flow.
  async createUser(
    createUserDto: CreateUserDto,
    role: UserRole,
    tenantId: string | null,
    analystLevel?: AnalystLevel,
  ) {
    if (role === UserRole.SUPER_ADMIN) {
      throw new ForbiddenException(
        'Super Admin cannot be created through the API',
      );
    }
    const level = resolveAnalystLevel(role, analystLevel);

    const { password, ...rest } = createUserDto;
    const hashedPassword = await argon2.hash(password);

    try {
      return await this.prisma.user.create({
        data: {
          ...rest,
          hashedPassword,
          role,
          analystLevel: level,
          tenantId,
          mustChangePassword: true,
        },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        this.logger.warn(
          `User creation rejected — duplicate email: ${rest.email}`,
        );
        throw new ConflictException('A user with this email already exists');
      }
      throw error;
    }
  }

  async updateUserForTenant(
    id: string,
    tenantId: string,
    updateUserDto: UpdateUserDto,
  ) {
    await this.findByIdForTenant(id, tenantId);

    try {
      return await this.prisma.user.update({
        where: { id },
        data: updateUserDto,
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        this.logger.warn(
          `User update rejected — duplicate email for user ${id}`,
        );
        throw new ConflictException('A user with this email already exists');
      }
      throw error;
    }
  }

  async removeUserForTenant(id: string, tenantId: string) {
    await this.findByIdForTenant(id, tenantId);

    // RefreshToken and PasswordHistory RESTRICT on userId (same class of bug
    // already hit and fixed for tenant deletion — see TenantsService). A user
    // who's ever logged in (RefreshToken) or changed a password
    // (PasswordHistory — unconditional on first login) would otherwise 500 a
    // plain user.delete().
    const results = await this.prisma.$transaction([
      this.prisma.refreshToken.deleteMany({ where: { userId: id } }),
      this.prisma.passwordHistory.deleteMany({ where: { userId: id } }),
      this.prisma.user.delete({ where: { id } }),
    ]);

    // Last element is the user.delete() result, per the array above.
    return results[2];
  }

  // Every tenant must always have at least one Admin. Demoting the last one
  // is rejected outright rather than silently leaving the tenant with no one
  // able to administer it.
  async changeRoleForTenant(
    id: string,
    tenantId: string,
    role: UserRole,
    analystLevel?: AnalystLevel,
  ) {
    const level = resolveAnalystLevel(role, analystLevel);
    const user = await this.findByIdForTenant(id, tenantId);

    if (user.role === UserRole.ADMIN && role !== UserRole.ADMIN) {
      const adminCount = await this.prisma.user.count({
        where: { tenantId, role: UserRole.ADMIN },
      });

      if (adminCount <= 1) {
        throw new ConflictException(
          'Cannot demote the last remaining Admin in this tenant',
        );
      }
    }

    return this.prisma.user.update({
      where: { id },
      data: { role, analystLevel: level },
    });
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Self-service change only exists to get past the mandatory first-login change — once
    // that's done, voluntary rotation goes through requestOwnPasswordChange instead (a
    // stolen bearer token alone can no longer be turned into a silent password change).
    if (!user.mustChangePassword) {
      throw new ForbiddenException(
        'Self password change is only available for your mandatory first-time change. Use the request-password-change flow instead.',
      );
    }

    const isCurrentPasswordValid = await argon2.verify(
      user.hashedPassword,
      currentPassword,
    );
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    await this.assertPasswordNotReused(
      userId,
      user.hashedPassword,
      newPassword,
    );

    const hashedPassword = await argon2.hash(newPassword);
    await this.recordPasswordHistory(userId, user.hashedPassword);

    return this.prisma.user.update({
      where: { id: userId },
      data: { hashedPassword, mustChangePassword: false },
    });
  }

  async requestOwnPasswordChange(userId: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordResetRequestedAt: new Date() },
    });
  }

  // Single designated recipient per tenant: the earliest-created Admin (by createdAt),
  // computed live rather than stored, so it stays correct if that Admin is later deleted.
  // That Admin's own request is deliberately excluded here — it escalates to Super Admins
  // instead (see hasPendingPasswordRequestsForSuperAdmin) rather than pinging themselves.
  async hasPendingPasswordRequestsForAdmin(
    adminId: string,
    tenantId: string,
  ): Promise<boolean> {
    const firstAdmin = await this.prisma.user.findFirst({
      where: { tenantId, role: UserRole.ADMIN },
      // id as a tiebreaker: two Admins created in the same transaction (e.g.
      // prisma/seed-modules.ts's createMany) can share an identical createdAt,
      // which otherwise makes "first Admin" non-deterministic across calls.
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      select: { id: true },
    });

    if (!firstAdmin || firstAdmin.id !== adminId) {
      return false;
    }

    const pendingCount = await this.prisma.user.count({
      where: {
        tenantId,
        id: { not: adminId },
        passwordResetRequestedAt: { not: null },
      },
    });

    return pendingCount > 0;
  }

  // Escalation counterpart to hasPendingPasswordRequestsForAdmin: a tenant's first-created
  // Admin has no one else in-tenant to notify, so their own pending request surfaces to
  // every Super Admin instead — as does any Integration Admin's request. Bounded by the (small) number of currently-pending Admins,
  // not the total Admin count, so the N+1 lookup here is cheap in practice.
  async hasPendingPasswordRequestsForSuperAdmin(): Promise<boolean> {
    // Integration Admins have no tenant, so no tenant Admin can see their
    // request — Super Admins are their only reset path.
    const pendingIntegrationAdmin = await this.prisma.user.findFirst({
      where: {
        role: UserRole.INTEGRATION_ADMIN,
        passwordResetRequestedAt: { not: null },
      },
      select: { id: true },
    });
    if (pendingIntegrationAdmin) {
      return true;
    }

    const pendingAdmins = await this.prisma.user.findMany({
      where: { role: UserRole.ADMIN, passwordResetRequestedAt: { not: null } },
      select: { id: true, tenantId: true },
    });

    for (const admin of pendingAdmins) {
      if (!admin.tenantId) continue;

      const firstAdmin = await this.prisma.user.findFirst({
        where: { tenantId: admin.tenantId, role: UserRole.ADMIN },
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        select: { id: true },
      });

      if (firstAdmin?.id === admin.id) {
        return true;
      }
    }

    return false;
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user || user.role === UserRole.SUPER_ADMIN) {
      return;
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { passwordResetRequestedAt: new Date() },
    });
  }

  async resetPasswordForTenant(
    id: string,
    tenantId: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.findByIdForTenant(id, tenantId);
    await this.applyPasswordReset(id, user.hashedPassword, newPassword);
  }

  // Escalation path for a tenant with no co-Admin to handle the reset themselves: a Super
  // Admin may reset an Admin's password, but only when that Admin is the tenant's sole
  // Admin — if a co-Admin exists, they're expected to use resetPasswordForTenant instead
  // (an Admin can already reset a co-Admin's password), keeping the Super Admin out of a
  // tenant's day-to-day account administration whenever there's an in-tenant alternative.
  async resetSoleAdminPassword(id: string, newPassword: string): Promise<void> {
    const target = await this.prisma.user.findUnique({ where: { id } });

    if (!target || target.role !== UserRole.ADMIN || !target.tenantId) {
      throw new NotFoundException('Admin not found');
    }

    const adminCount = await this.prisma.user.count({
      where: { tenantId: target.tenantId, role: UserRole.ADMIN },
    });

    if (adminCount > 1) {
      throw new ConflictException(
        'This tenant has other Admins who can reset this password',
      );
    }

    await this.applyPasswordReset(id, target.hashedPassword, newPassword);
  }

  // INTEGRATION_ADMIN accounts are platform-wide (tenantId null) and managed
  // only by Super Admins — see IntegrationAdminsController.
  async findAllIntegrationAdmins() {
    return this.prisma.user.findMany({
      where: { role: UserRole.INTEGRATION_ADMIN },
      omit: { hashedPassword: true },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    });
  }

  async removeIntegrationAdmin(id: string) {
    await this.findIntegrationAdminOrThrow(id);

    // Same RESTRICT-on-userId cleanup as removeUserForTenant.
    const results = await this.prisma.$transaction([
      this.prisma.refreshToken.deleteMany({ where: { userId: id } }),
      this.prisma.passwordHistory.deleteMany({ where: { userId: id } }),
      this.prisma.user.delete({ where: { id } }),
    ]);

    return results[2];
  }

  async resetIntegrationAdminPassword(
    id: string,
    newPassword: string,
  ): Promise<void> {
    const target = await this.findIntegrationAdminOrThrow(id);
    await this.applyPasswordReset(id, target.hashedPassword, newPassword);
  }

  private async findIntegrationAdminOrThrow(id: string) {
    const target = await this.prisma.user.findUnique({ where: { id } });

    if (!target || target.role !== UserRole.INTEGRATION_ADMIN) {
      throw new NotFoundException('Integration Admin not found');
    }
    return target;
  }

  private async applyPasswordReset(
    id: string,
    currentHashedPassword: string,
    newPassword: string,
  ): Promise<void> {
    await this.assertPasswordNotReused(id, currentHashedPassword, newPassword);

    const hashedPassword = await argon2.hash(newPassword);
    await this.recordPasswordHistory(id, currentHashedPassword);

    await this.prisma.user.update({
      where: { id },
      data: {
        hashedPassword,
        mustChangePassword: true,
        passwordResetRequestedAt: null,
        // An Admin/Super Admin actively resetting this password is already
        // the fix for a locked-out account — leaving the lock in place for
        // the rest of the window would just re-lock them out of the account
        // that was just repaired.
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });
  }

  // Checked against the current password plus the last PASSWORD_HISTORY_CHECK_LIMIT
  // historical ones — argon2.verify, not equality, since argon2 salts are random.
  private async assertPasswordNotReused(
    userId: string,
    currentHashedPassword: string,
    newPassword: string,
  ): Promise<void> {
    const matchesCurrent = await argon2.verify(
      currentHashedPassword,
      newPassword,
    );
    if (matchesCurrent) {
      throw new ConflictException(
        'New password must not match your current or last 5 passwords',
      );
    }

    const history = await this.prisma.passwordHistory.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: PASSWORD_HISTORY_CHECK_LIMIT,
    });

    for (const entry of history) {
      const matchesHistorical = await argon2.verify(
        entry.hashedPassword,
        newPassword,
      );
      if (matchesHistorical) {
        throw new ConflictException(
          'New password must not match your current or last 5 passwords',
        );
      }
    }
  }

  // Never pruned — a permanent audit trail of when this account's password
  // changed is cheap to keep and useful for later investigation. Only the
  // reuse *check* above is bounded to the most recent entries.
  private async recordPasswordHistory(
    userId: string,
    hashedPassword: string,
  ): Promise<void> {
    await this.prisma.passwordHistory.create({
      data: { userId, hashedPassword },
    });
  }
}
