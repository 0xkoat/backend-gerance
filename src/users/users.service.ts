import {
  ConflictException,
  ForbiddenException,
  Injectable,
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
        },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
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
