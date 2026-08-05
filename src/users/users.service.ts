import {
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Prisma, UserRole } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/createUser.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import * as argon2 from 'argon2';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(private readonly prisma: PrismaService) {}

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

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

  async createUser(
    createUserDto: CreateUserDto,
    role: UserRole,
    tenantId: string | null,
  ) {
    if (role === UserRole.SUPER_ADMIN) {
      throw new ForbiddenException(
        'Super Admin cannot be created through the API',
      );
    }

    const { password, ...rest } = createUserDto;
    const hashedPassword = await argon2.hash(password);

    try {
      return await this.prisma.user.create({
        data: {
          ...rest,
          hashedPassword,
          role,
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

    return this.prisma.user.delete({
      where: { id },
    });
  }

  async changeRoleForTenant(id: string, tenantId: string, role: UserRole) {
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
      data: { role },
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

    const hashedPassword = await argon2.hash(newPassword);

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
      orderBy: { createdAt: 'asc' },
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
  // every Super Admin instead. Bounded by the (small) number of currently-pending Admins,
  // not the total Admin count, so the N+1 lookup here is cheap in practice.
  async hasPendingPasswordRequestsForSuperAdmin(): Promise<boolean> {
    const pendingAdmins = await this.prisma.user.findMany({
      where: { role: UserRole.ADMIN, passwordResetRequestedAt: { not: null } },
      select: { id: true, tenantId: true },
    });

    for (const admin of pendingAdmins) {
      if (!admin.tenantId) continue;

      const firstAdmin = await this.prisma.user.findFirst({
        where: { tenantId: admin.tenantId, role: UserRole.ADMIN },
        orderBy: { createdAt: 'asc' },
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
    await this.findByIdForTenant(id, tenantId);
    await this.applyPasswordReset(id, newPassword);
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

    await this.applyPasswordReset(id, newPassword);
  }

  private async applyPasswordReset(
    id: string,
    newPassword: string,
  ): Promise<void> {
    const hashedPassword = await argon2.hash(newPassword);

    await this.prisma.user.update({
      where: { id },
      data: {
        hashedPassword,
        mustChangePassword: true,
        passwordResetRequestedAt: null,
      },
    });
  }
}
