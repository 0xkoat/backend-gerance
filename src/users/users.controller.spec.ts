import { Test, TestingModule } from '@nestjs/testing';
import {
  ConflictException,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { UserRole } from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { CreateSubordinateUserDto } from './dto/createSubordinateUser.dto';
import { UpdateUserDto } from './dto/updateUser.dto';
import { ChangeUserRoleDto } from './dto/changeUserRole.dto';
import { ChangePasswordDto } from './dto/changePassword.dto';

const mockUsersService = {
  findByIdForTenant: jest.fn(),
  createUser: jest.fn(),
  findAllForTenant: jest.fn(),
  updateUserForTenant: jest.fn(),
  changeRoleForTenant: jest.fn(),
  removeUserForTenant: jest.fn(),
  changePassword: jest.fn(),
  resetPasswordForTenant: jest.fn(),
};

const mockJwtService = {
  sign: jest.fn(),
};

describe('UsersController', () => {
  let controller: UsersController;

  const admin: AuthenticatedUser = {
    userId: 'admin-1',
    role: UserRole.ADMIN,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const noTenantAdmin: AuthenticatedUser = {
    userId: 'admin-1',
    role: UserRole.ADMIN,
    tenantId: null,
    mustChangePassword: false,
  };

  const dbUser = {
    id: 'user-1',
    email: 'bob@x.com',
    name: 'Bob',
    phoneNumber: '+21612345678',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    hashedPassword: 'hashed-password',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        { provide: UsersService, useValue: mockUsersService },
        { provide: JwtService, useValue: mockJwtService },
      ],
    }).compile();

    controller = module.get<UsersController>(UsersController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getMe', () => {
    it('returns the caller own record without the hashed password', async () => {
      mockUsersService.findByIdForTenant.mockResolvedValue(dbUser);

      const result = await controller.getMe(admin);

      expect(mockUsersService.findByIdForTenant).toHaveBeenCalledWith(
        'admin-1',
        'tenant-1',
      );
      expect(result).not.toHaveProperty('hashedPassword');
      expect(result).toEqual(
        expect.objectContaining({ id: 'user-1', email: 'bob@x.com' }),
      );
    });

    it('throws ForbiddenException when the caller has no tenantId', async () => {
      await expect(controller.getMe(noTenantAdmin)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockUsersService.findByIdForTenant).not.toHaveBeenCalled();
    });
  });

  describe('createUser', () => {
    const dto: CreateSubordinateUserDto = {
      name: 'New Analyst',
      email: 'analyst@x.com',
      password: 'Str0ng!Passw0rd',
      phoneNumber: '+21612345678',
      role: UserRole.ANALYST,
    };

    it('creates a user in the caller tenant with the role from the DTO, without the hashed password', async () => {
      const createdUser = { ...dbUser, ...dto };
      mockUsersService.createUser.mockResolvedValue(createdUser);

      const result = await controller.createUser(admin, dto);

      expect(mockUsersService.createUser).toHaveBeenCalledWith(
        dto,
        UserRole.ANALYST,
        'tenant-1',
      );
      expect(result).not.toHaveProperty('hashedPassword');
    });

    it('throws ForbiddenException when the caller has no tenantId', async () => {
      await expect(controller.createUser(noTenantAdmin, dto)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockUsersService.createUser).not.toHaveBeenCalled();
    });

    it('propagates ConflictException from the service (duplicate email)', async () => {
      mockUsersService.createUser.mockRejectedValue(
        new ConflictException('duplicate'),
      );

      await expect(controller.createUser(admin, dto)).rejects.toThrow(
        ConflictException,
      );
    });
  });

  describe('getAllUsers', () => {
    it('returns all tenant users with hashed passwords stripped', async () => {
      const secondUser = {
        ...dbUser,
        id: 'user-2',
        hashedPassword: 'other-hash',
      };
      mockUsersService.findAllForTenant.mockResolvedValue([dbUser, secondUser]);

      const result = await controller.getAllUsers(admin);

      expect(mockUsersService.findAllForTenant).toHaveBeenCalledWith(
        'tenant-1',
      );
      expect(result).toHaveLength(2);
      result.forEach((user) =>
        expect(user).not.toHaveProperty('hashedPassword'),
      );
    });

    it('returns an empty array when the tenant has no users', async () => {
      mockUsersService.findAllForTenant.mockResolvedValue([]);

      const result = await controller.getAllUsers(admin);

      expect(result).toEqual([]);
    });

    it('throws ForbiddenException when the caller has no tenantId', async () => {
      await expect(controller.getAllUsers(noTenantAdmin)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockUsersService.findAllForTenant).not.toHaveBeenCalled();
    });
  });

  describe('getUserById', () => {
    it('returns the requested user scoped to the caller tenant, without the hashed password', async () => {
      mockUsersService.findByIdForTenant.mockResolvedValue(dbUser);

      const result = await controller.getUserById(admin, 'user-1');

      expect(mockUsersService.findByIdForTenant).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
      );
      expect(result).not.toHaveProperty('hashedPassword');
    });

    it('throws ForbiddenException when the caller has no tenantId', async () => {
      await expect(
        controller.getUserById(noTenantAdmin, 'user-1'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockUsersService.findByIdForTenant).not.toHaveBeenCalled();
    });

    it('propagates NotFoundException from the service (missing or cross-tenant user)', async () => {
      mockUsersService.findByIdForTenant.mockRejectedValue(
        new NotFoundException('User not found'),
      );

      await expect(controller.getUserById(admin, 'missing-id')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('updateUserById', () => {
    const dto: UpdateUserDto = { name: 'New Name' };

    it('updates the user and returns it without the hashed password', async () => {
      mockUsersService.updateUserForTenant.mockResolvedValue({
        ...dbUser,
        name: 'New Name',
      });

      const result = await controller.updateUserById(admin, 'user-1', dto);

      expect(mockUsersService.updateUserForTenant).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
        dto,
      );
      expect(result).not.toHaveProperty('hashedPassword');
    });

    it('throws ForbiddenException when the caller has no tenantId', async () => {
      await expect(
        controller.updateUserById(noTenantAdmin, 'user-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockUsersService.updateUserForTenant).not.toHaveBeenCalled();
    });

    it('propagates NotFoundException from the service', async () => {
      mockUsersService.updateUserForTenant.mockRejectedValue(
        new NotFoundException('User not found'),
      );

      await expect(
        controller.updateUserById(admin, 'missing-id', dto),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateUserRoleById', () => {
    const dto: ChangeUserRoleDto = { role: UserRole.VIEWER };

    it('changes the role of another user in the tenant', async () => {
      mockUsersService.changeRoleForTenant.mockResolvedValue({
        ...dbUser,
        role: UserRole.VIEWER,
      });

      const result = await controller.updateUserRoleById(admin, 'user-1', dto);

      expect(mockUsersService.changeRoleForTenant).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
        UserRole.VIEWER,
      );
      expect(result).not.toHaveProperty('hashedPassword');
    });

    it('throws ForbiddenException when the caller has no tenantId', async () => {
      await expect(
        controller.updateUserRoleById(noTenantAdmin, 'user-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockUsersService.changeRoleForTenant).not.toHaveBeenCalled();
    });

    it('throws ForbiddenException when the caller tries to change their own role, without calling the service', async () => {
      await expect(
        controller.updateUserRoleById(admin, admin.userId, dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockUsersService.changeRoleForTenant).not.toHaveBeenCalled();
    });

    it('propagates ConflictException from the service (last remaining Admin)', async () => {
      mockUsersService.changeRoleForTenant.mockRejectedValue(
        new ConflictException(
          'Cannot demote the last remaining Admin in this tenant',
        ),
      );

      await expect(
        controller.updateUserRoleById(admin, 'user-1', dto),
      ).rejects.toThrow(ConflictException);
    });

    it('propagates NotFoundException from the service', async () => {
      mockUsersService.changeRoleForTenant.mockRejectedValue(
        new NotFoundException('User not found'),
      );

      await expect(
        controller.updateUserRoleById(admin, 'missing-id', dto),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteUserById', () => {
    it('deletes another user in the tenant and returns a confirmation', async () => {
      mockUsersService.removeUserForTenant.mockResolvedValue(dbUser);

      const result = await controller.deleteUserById(admin, 'user-1');

      expect(mockUsersService.removeUserForTenant).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
      );
      expect(result).toEqual({
        message: 'User deleted successfully',
        id: 'user-1',
      });
    });

    it('throws ForbiddenException when the caller has no tenantId', async () => {
      await expect(
        controller.deleteUserById(noTenantAdmin, 'user-1'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockUsersService.removeUserForTenant).not.toHaveBeenCalled();
    });

    it('throws ForbiddenException when the caller tries to delete their own account, without calling the service', async () => {
      await expect(
        controller.deleteUserById(admin, admin.userId),
      ).rejects.toThrow(ForbiddenException);
      expect(mockUsersService.removeUserForTenant).not.toHaveBeenCalled();
    });

    it('propagates NotFoundException from the service', async () => {
      mockUsersService.removeUserForTenant.mockRejectedValue(
        new NotFoundException('User not found'),
      );

      await expect(
        controller.deleteUserById(admin, 'missing-id'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('resetUserPassword', () => {
    it('resets another user password in the tenant', async () => {
      mockUsersService.resetPasswordForTenant.mockResolvedValue(undefined);

      const result = await controller.resetUserPassword(admin, 'user-1', {
        newPassword: 'New-password1!',
      });

      expect(mockUsersService.resetPasswordForTenant).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
        'New-password1!',
      );
      expect(result).toEqual({ message: 'Password reset successfully' });
    });

    it('throws ForbiddenException when the caller has no tenantId', async () => {
      await expect(
        controller.resetUserPassword(noTenantAdmin, 'user-1', {
          newPassword: 'New-password1!',
        }),
      ).rejects.toThrow(ForbiddenException);
      expect(mockUsersService.resetPasswordForTenant).not.toHaveBeenCalled();
    });

    it('propagates NotFoundException from the service', async () => {
      mockUsersService.resetPasswordForTenant.mockRejectedValue(
        new NotFoundException('User not found'),
      );

      await expect(
        controller.resetUserPassword(admin, 'missing-id', {
          newPassword: 'New-password1!',
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it('throws ForbiddenException when the caller targets their own account, without calling the service', async () => {
      await expect(
        controller.resetUserPassword(admin, admin.userId, {
          newPassword: 'New-password1!',
        }),
      ).rejects.toThrow(ForbiddenException);
      expect(mockUsersService.resetPasswordForTenant).not.toHaveBeenCalled();
    });
  });

  describe('changeMyPassword', () => {
    const dto: ChangePasswordDto = {
      currentPassword: 'Old-password1!',
      newPassword: 'New-password1!',
    };

    it('changes the caller own password and returns a confirmation with a fresh token', async () => {
      mockUsersService.changePassword.mockResolvedValue({
        id: admin.userId,
        role: UserRole.ADMIN,
        tenantId: 'tenant-1',
        mustChangePassword: false,
      });
      mockJwtService.sign.mockReturnValue('fresh-jwt');

      const result = await controller.changeMyPassword(admin, dto);

      expect(mockUsersService.changePassword).toHaveBeenCalledWith(
        admin.userId,
        dto.currentPassword,
        dto.newPassword,
      );
      expect(mockJwtService.sign).toHaveBeenCalledWith({
        sub: admin.userId,
        role: UserRole.ADMIN,
        tenantId: 'tenant-1',
        mustChangePassword: false,
      });
      expect(result).toEqual({
        message: 'Password changed successfully',
        access_token: 'fresh-jwt',
        mustChangePassword: false,
      });
    });

    it('propagates UnauthorizedException when the current password is wrong', async () => {
      mockUsersService.changePassword.mockRejectedValue(
        new UnauthorizedException('Current password is incorrect'),
      );

      await expect(controller.changeMyPassword(admin, dto)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(mockJwtService.sign).not.toHaveBeenCalled();
    });

    it('works even when the caller has no tenantId (no tenant guard on this route)', async () => {
      mockUsersService.changePassword.mockResolvedValue({
        id: noTenantAdmin.userId,
        role: UserRole.ADMIN,
        tenantId: null,
        mustChangePassword: false,
      });
      mockJwtService.sign.mockReturnValue('fresh-jwt');

      const result = await controller.changeMyPassword(noTenantAdmin, dto);

      expect(mockUsersService.changePassword).toHaveBeenCalledWith(
        noTenantAdmin.userId,
        dto.currentPassword,
        dto.newPassword,
      );
      expect(result).toEqual({
        message: 'Password changed successfully',
        access_token: 'fresh-jwt',
        mustChangePassword: false,
      });
    });
  });
});
