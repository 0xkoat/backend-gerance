import { Test, TestingModule } from '@nestjs/testing';
import {
  ConflictException,
  ForbiddenException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import { UsersService } from './users.service';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma, UserRole } from '../generated/prisma/client';
import { CreateUserDto } from './dto/createUser.dto';
import { UpdateUserDto } from './dto/updateUser.dto';

jest.mock('argon2');

const mockPrismaService = {
  user: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  passwordHistory: {
    findMany: jest.fn(),
    create: jest.fn(),
  },
  $transaction: jest.fn(),
};

function prismaKnownError(code: string) {
  return new Prisma.PrismaClientKnownRequestError('mocked prisma error', {
    code,
    clientVersion: '7.8.0',
  });
}

describe('UsersService', () => {
  let service: UsersService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        { provide: PrismaService, useValue: mockPrismaService },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('findByEmail', () => {
    it('returns the user when found', async () => {
      const user = { id: '1', email: 'bob@x.com' };
      mockPrismaService.user.findUnique.mockResolvedValue(user);

      const result = await service.findByEmail('bob@x.com');

      expect(result).toEqual(user);
      expect(mockPrismaService.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'bob@x.com' },
      });
    });

    it('returns null when no user matches (not an error case for this method)', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      const result = await service.findByEmail('missing@x.com');

      expect(result).toBeNull();
    });
  });

  describe('findByIdForTenant', () => {
    it('returns the user when found in the given tenant', async () => {
      const user = { id: '1', email: 'bob@x.com', tenantId: 'tenant-1' };
      mockPrismaService.user.findUnique.mockResolvedValue(user);

      const result = await service.findByIdForTenant('1', 'tenant-1');

      expect(result).toEqual(user);
    });

    it('throws NotFoundException when no user matches', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.findByIdForTenant('missing-id', 'tenant-1'),
      ).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when the user belongs to a different tenant', async () => {
      const user = { id: '1', email: 'bob@x.com', tenantId: 'tenant-2' };
      mockPrismaService.user.findUnique.mockResolvedValue(user);

      await expect(service.findByIdForTenant('1', 'tenant-1')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('findAllForTenant', () => {
    it('returns a page of users scoped to the given tenant, plus the total count', async () => {
      const users = [{ id: '1', tenantId: 'tenant-1' }];
      mockPrismaService.$transaction.mockResolvedValue([users, 1]);

      const result = await service.findAllForTenant('tenant-1', 1, 20);

      expect(result).toEqual({ users, total: 1, page: 1, pageSize: 20 });
      expect(mockPrismaService.user.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        orderBy: { createdAt: 'asc' },
        skip: 0,
        take: 20,
      });
      expect(mockPrismaService.user.count).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
      });
    });

    it('computes skip from the requested page', async () => {
      mockPrismaService.$transaction.mockResolvedValue([[], 45]);

      await service.findAllForTenant('tenant-1', 3, 20);

      expect(mockPrismaService.user.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ skip: 40, take: 20 }),
      );
    });

    it('returns an empty page when the tenant has no users', async () => {
      mockPrismaService.$transaction.mockResolvedValue([[], 0]);

      const result = await service.findAllForTenant('empty-tenant', 1, 20);

      expect(result.users).toEqual([]);
      expect(result.total).toBe(0);
    });
  });

  describe('createUser', () => {
    const dto: CreateUserDto = {
      name: 'Bob',
      email: 'bob@x.com',
      password: 'Str0ng!Passw0rd',
      phoneNumber: '+21612345678',
    };

    beforeEach(() => {
      (argon2.hash as jest.Mock).mockResolvedValue('hashed-password');
    });

    it('creates a user with a hashed password and never persists the plaintext password', async () => {
      const createdUser = {
        id: '1',
        ...dto,
        hashedPassword: 'hashed-password',
      };
      mockPrismaService.user.create.mockResolvedValue(createdUser);

      const result = await service.createUser(
        dto,
        UserRole.ANALYST,
        'tenant-1',
      );

      expect(argon2.hash).toHaveBeenCalledWith(dto.password);
      expect(mockPrismaService.user.create).toHaveBeenCalledWith({
        data: {
          name: dto.name,
          email: dto.email,
          phoneNumber: dto.phoneNumber,
          hashedPassword: 'hashed-password',
          role: UserRole.ANALYST,
          tenantId: 'tenant-1',
          mustChangePassword: true,
        },
      });
      expect(result).toEqual(createdUser);
    });

    it('rejects creating a SUPER_ADMIN through this method, without touching the database', async () => {
      await expect(
        service.createUser(dto, UserRole.SUPER_ADMIN, null),
      ).rejects.toThrow(ForbiddenException);

      expect(mockPrismaService.user.create).not.toHaveBeenCalled();
    });

    it('allows tenantId to be null (e.g. not applicable at this call site)', async () => {
      mockPrismaService.user.create.mockResolvedValue({
        id: '1',
        ...dto,
        tenantId: null,
      });

      await service.createUser(dto, UserRole.ADMIN, null);

      expect(mockPrismaService.user.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ tenantId: null }),
        }),
      );
    });

    it('throws ConflictException and logs a warning when the email already exists (Prisma P2002)', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
      mockPrismaService.user.create.mockRejectedValue(
        prismaKnownError('P2002'),
      );

      await expect(
        service.createUser(dto, UserRole.VIEWER, 'tenant-1'),
      ).rejects.toThrow(ConflictException);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining(dto.email));
      warnSpy.mockRestore();
    });

    it('rethrows unrelated errors instead of swallowing them', async () => {
      const unexpected = new Error('database connection lost');
      mockPrismaService.user.create.mockRejectedValue(unexpected);

      await expect(
        service.createUser(dto, UserRole.VIEWER, 'tenant-1'),
      ).rejects.toThrow('database connection lost');
    });
  });

  describe('updateUserForTenant', () => {
    const dto: UpdateUserDto = { name: 'New Name' };
    const existingUser = { id: '1', tenantId: 'tenant-1' };

    it('updates and returns the user on success', async () => {
      const updatedUser = { id: '1', name: 'New Name', tenantId: 'tenant-1' };
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.user.update.mockResolvedValue(updatedUser);

      const result = await service.updateUserForTenant('1', 'tenant-1', dto);

      expect(result).toEqual(updatedUser);
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: dto,
      });
    });

    it('throws NotFoundException when the user does not exist', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.updateUserForTenant('missing-id', 'tenant-1', dto),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the user belongs to a different tenant', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: '1',
        tenantId: 'tenant-2',
      });

      await expect(
        service.updateUserForTenant('1', 'tenant-1', dto),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws ConflictException and logs a warning when the new email collides with another user (Prisma P2002)', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.user.update.mockRejectedValue(
        prismaKnownError('P2002'),
      );

      await expect(
        service.updateUserForTenant('1', 'tenant-1', { email: 'taken@x.com' }),
      ).rejects.toThrow(ConflictException);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('1'));
      warnSpy.mockRestore();
    });

    it('rethrows unrelated errors instead of swallowing them', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.user.update.mockRejectedValue(
        new Error('unexpected failure'),
      );

      await expect(
        service.updateUserForTenant('1', 'tenant-1', dto),
      ).rejects.toThrow('unexpected failure');
    });
  });

  describe('removeUserForTenant', () => {
    const existingUser = { id: '1', tenantId: 'tenant-1' };

    it('deletes and returns the user on success', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.user.delete.mockResolvedValue(existingUser);

      const result = await service.removeUserForTenant('1', 'tenant-1');

      expect(result).toEqual(existingUser);
      expect(mockPrismaService.user.delete).toHaveBeenCalledWith({
        where: { id: '1' },
      });
    });

    it('throws NotFoundException when the user does not exist', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.removeUserForTenant('missing-id', 'tenant-1'),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.delete).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the user belongs to a different tenant', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: '1',
        tenantId: 'tenant-2',
      });

      await expect(
        service.removeUserForTenant('1', 'tenant-1'),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.delete).not.toHaveBeenCalled();
    });
  });

  describe('changeRoleForTenant', () => {
    it('changes the role when the target is not an Admin', async () => {
      const existingUser = {
        id: '1',
        tenantId: 'tenant-1',
        role: UserRole.ANALYST,
      };
      const updatedUser = { ...existingUser, role: UserRole.VIEWER };
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.user.update.mockResolvedValue(updatedUser);

      const result = await service.changeRoleForTenant(
        '1',
        'tenant-1',
        UserRole.VIEWER,
      );

      expect(mockPrismaService.user.count).not.toHaveBeenCalled();
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: { role: UserRole.VIEWER },
      });
      expect(result).toEqual(updatedUser);
    });

    it('promotes a non-Admin to Admin without checking the admin count', async () => {
      const existingUser = {
        id: '1',
        tenantId: 'tenant-1',
        role: UserRole.ANALYST,
      };
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.user.update.mockResolvedValue({
        ...existingUser,
        role: UserRole.ADMIN,
      });

      await service.changeRoleForTenant('1', 'tenant-1', UserRole.ADMIN);

      expect(mockPrismaService.user.count).not.toHaveBeenCalled();
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: { role: UserRole.ADMIN },
      });
    });

    it('demotes an Admin when other Admins remain in the tenant', async () => {
      const existingUser = {
        id: '1',
        tenantId: 'tenant-1',
        role: UserRole.ADMIN,
      };
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.user.count.mockResolvedValue(2);
      mockPrismaService.user.update.mockResolvedValue({
        ...existingUser,
        role: UserRole.ANALYST,
      });

      await service.changeRoleForTenant('1', 'tenant-1', UserRole.ANALYST);

      expect(mockPrismaService.user.count).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1', role: UserRole.ADMIN },
      });
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: { role: UserRole.ANALYST },
      });
    });

    it('throws ConflictException when demoting the last remaining Admin', async () => {
      const existingUser = {
        id: '1',
        tenantId: 'tenant-1',
        role: UserRole.ADMIN,
      };
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.user.count.mockResolvedValue(1);

      await expect(
        service.changeRoleForTenant('1', 'tenant-1', UserRole.ANALYST),
      ).rejects.toThrow(ConflictException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the user does not exist', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.changeRoleForTenant('missing-id', 'tenant-1', UserRole.VIEWER),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the user belongs to a different tenant', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: '1',
        tenantId: 'tenant-2',
        role: UserRole.ANALYST,
      });

      await expect(
        service.changeRoleForTenant('1', 'tenant-1', UserRole.VIEWER),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });
  });

  describe('changePassword', () => {
    const existingUser = {
      id: '1',
      hashedPassword: 'old-hashed-password',
      mustChangePassword: true,
    };

    it('verifies the current password, hashes the new one, and updates it', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.passwordHistory.findMany.mockResolvedValue([]);
      (argon2.verify as jest.Mock)
        .mockResolvedValueOnce(true) // current-password check
        .mockResolvedValueOnce(false); // reuse check against the current hash
      (argon2.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      await service.changePassword('1', 'old-password', 'New-password1!');

      expect(argon2.verify).toHaveBeenNthCalledWith(
        1,
        'old-hashed-password',
        'old-password',
      );
      expect(argon2.hash).toHaveBeenCalledWith('New-password1!');
      expect(mockPrismaService.passwordHistory.create).toHaveBeenCalledWith({
        data: { userId: '1', hashedPassword: 'old-hashed-password' },
      });
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: {
          hashedPassword: 'new-hashed-password',
          mustChangePassword: false,
        },
      });
    });

    it('rejects when the new password matches the current one', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      (argon2.verify as jest.Mock)
        .mockResolvedValueOnce(true) // current-password check
        .mockResolvedValueOnce(true); // reuse check: same as current
      (argon2.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      await expect(
        service.changePassword('1', 'old-password', 'old-password'),
      ).rejects.toThrow(ConflictException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
      expect(mockPrismaService.passwordHistory.create).not.toHaveBeenCalled();
    });

    it('rejects when the new password matches one of the last 4 historical passwords', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.passwordHistory.findMany.mockResolvedValue([
        { hashedPassword: 'hist-1' },
        { hashedPassword: 'hist-2' },
      ]);
      (argon2.verify as jest.Mock)
        .mockResolvedValueOnce(true) // current-password check
        .mockResolvedValueOnce(false) // reuse check vs current hash: no match
        .mockResolvedValueOnce(false) // vs hist-1: no match
        .mockResolvedValueOnce(true); // vs hist-2: match

      await expect(
        service.changePassword('1', 'old-password', 'a-reused-password'),
      ).rejects.toThrow(ConflictException);
      expect(mockPrismaService.passwordHistory.findMany).toHaveBeenCalledWith({
        where: { userId: '1' },
        orderBy: { createdAt: 'desc' },
        take: 4,
      });
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws UnauthorizedException when the current password is wrong', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      (argon2.verify as jest.Mock).mockResolvedValue(false);

      await expect(
        service.changePassword('1', 'wrong-password', 'New-password1!'),
      ).rejects.toThrow(UnauthorizedException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the user does not exist', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.changePassword('missing-id', 'old-password', 'New-password1!'),
      ).rejects.toThrow(NotFoundException);
      expect(argon2.verify).not.toHaveBeenCalled();
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('rejects with ForbiddenException once mustChangePassword is already false, without checking the password', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: '1',
        hashedPassword: 'old-hashed-password',
        mustChangePassword: false,
      });

      await expect(
        service.changePassword('1', 'old-password', 'New-password1!'),
      ).rejects.toThrow(ForbiddenException);
      expect(argon2.verify).not.toHaveBeenCalled();
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });
  });

  describe('requestOwnPasswordChange', () => {
    it('sets passwordResetRequestedAt on the caller', async () => {
      await service.requestOwnPasswordChange('1');

      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: { passwordResetRequestedAt: expect.any(Date) },
      });
    });
  });

  describe('hasPendingPasswordRequestsForAdmin', () => {
    it("returns false when the caller is not the tenant's first-created Admin", async () => {
      mockPrismaService.user.findFirst.mockResolvedValue({ id: 'first-admin' });

      const result = await service.hasPendingPasswordRequestsForAdmin(
        'other-admin',
        'tenant-1',
      );

      expect(result).toBe(false);
      expect(mockPrismaService.user.count).not.toHaveBeenCalled();
    });

    it('returns false when there is no tenant Admin at all', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue(null);

      const result = await service.hasPendingPasswordRequestsForAdmin(
        'admin-1',
        'tenant-1',
      );

      expect(result).toBe(false);
    });

    it('returns true when the first Admin has a pending request from someone else in the tenant', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue({ id: 'admin-1' });
      mockPrismaService.user.count.mockResolvedValue(1);

      const result = await service.hasPendingPasswordRequestsForAdmin(
        'admin-1',
        'tenant-1',
      );

      expect(result).toBe(true);
      expect(mockPrismaService.user.count).toHaveBeenCalledWith({
        where: {
          tenantId: 'tenant-1',
          id: { not: 'admin-1' },
          passwordResetRequestedAt: { not: null },
        },
      });
    });

    it('returns false when the first Admin has no pending requests from others', async () => {
      mockPrismaService.user.findFirst.mockResolvedValue({ id: 'admin-1' });
      mockPrismaService.user.count.mockResolvedValue(0);

      const result = await service.hasPendingPasswordRequestsForAdmin(
        'admin-1',
        'tenant-1',
      );

      expect(result).toBe(false);
    });
  });

  describe('hasPendingPasswordRequestsForSuperAdmin', () => {
    it('returns false when no Admin has a pending request', async () => {
      mockPrismaService.user.findMany.mockResolvedValue([]);

      const result = await service.hasPendingPasswordRequestsForSuperAdmin();

      expect(result).toBe(false);
    });

    it("returns true when a pending Admin is their tenant's first-created Admin", async () => {
      mockPrismaService.user.findMany.mockResolvedValue([
        { id: 'admin-1', tenantId: 'tenant-1' },
      ]);
      mockPrismaService.user.findFirst.mockResolvedValue({ id: 'admin-1' });

      const result = await service.hasPendingPasswordRequestsForSuperAdmin();

      expect(result).toBe(true);
    });

    it('returns false when the pending Admin is a co-Admin, not the first-created one (handled by the tenant Admin path instead)', async () => {
      mockPrismaService.user.findMany.mockResolvedValue([
        { id: 'co-admin-2', tenantId: 'tenant-1' },
      ]);
      mockPrismaService.user.findFirst.mockResolvedValue({ id: 'admin-1' });

      const result = await service.hasPendingPasswordRequestsForSuperAdmin();

      expect(result).toBe(false);
    });
  });

  describe('requestPasswordReset', () => {
    it('sets passwordResetRequestedAt when the user exists', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: '1',
        role: UserRole.ANALYST,
      });

      await service.requestPasswordReset('bob@x.com');

      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: { passwordResetRequestedAt: expect.any(Date) },
      });
    });

    it('does nothing when no user matches the email (no enumeration)', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.requestPasswordReset('missing@x.com'),
      ).resolves.toBeUndefined();
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('does nothing for a Super Admin account', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: '2',
        role: UserRole.SUPER_ADMIN,
      });

      await service.requestPasswordReset('root@x.com');

      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });
  });

  describe('resetPasswordForTenant', () => {
    it('hashes the new password, sets mustChangePassword, and clears the pending request', async () => {
      const existingUser = {
        id: '1',
        tenantId: 'tenant-1',
        hashedPassword: 'old-hashed-password',
      };
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.passwordHistory.findMany.mockResolvedValue([]);
      (argon2.verify as jest.Mock).mockResolvedValue(false);
      (argon2.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      await service.resetPasswordForTenant('1', 'tenant-1', 'New-password1!');

      expect(argon2.hash).toHaveBeenCalledWith('New-password1!');
      expect(mockPrismaService.passwordHistory.create).toHaveBeenCalledWith({
        data: { userId: '1', hashedPassword: 'old-hashed-password' },
      });
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: {
          hashedPassword: 'new-hashed-password',
          mustChangePassword: true,
          passwordResetRequestedAt: null,
          failedLoginAttempts: 0,
          lockedUntil: null,
        },
      });
    });

    it('rejects when the new password matches one the target has used before', async () => {
      const existingUser = {
        id: '1',
        tenantId: 'tenant-1',
        hashedPassword: 'old-hashed-password',
      };
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.passwordHistory.findMany.mockResolvedValue([]);
      (argon2.verify as jest.Mock).mockResolvedValue(true);

      await expect(
        service.resetPasswordForTenant('1', 'tenant-1', 'Old-password1!'),
      ).rejects.toThrow(ConflictException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the user does not exist', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.resetPasswordForTenant(
          'missing-id',
          'tenant-1',
          'New-password1!',
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the user belongs to a different tenant', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: '1',
        tenantId: 'tenant-2',
      });

      await expect(
        service.resetPasswordForTenant('1', 'tenant-1', 'New-password1!'),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });
  });

  describe('resetSoleAdminPassword', () => {
    const soleAdmin = {
      id: 'admin-1',
      role: UserRole.ADMIN,
      tenantId: 'tenant-1',
      hashedPassword: 'old-hashed-password',
    };

    it("resets the password when the target is the tenant's only Admin", async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(soleAdmin);
      mockPrismaService.user.count.mockResolvedValue(1);
      mockPrismaService.passwordHistory.findMany.mockResolvedValue([]);
      (argon2.verify as jest.Mock).mockResolvedValue(false);
      (argon2.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      await service.resetSoleAdminPassword('admin-1', 'New-password1!');

      expect(mockPrismaService.user.count).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1', role: UserRole.ADMIN },
      });
      expect(mockPrismaService.passwordHistory.create).toHaveBeenCalledWith({
        data: { userId: 'admin-1', hashedPassword: 'old-hashed-password' },
      });
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: 'admin-1' },
        data: {
          hashedPassword: 'new-hashed-password',
          mustChangePassword: true,
          passwordResetRequestedAt: null,
          failedLoginAttempts: 0,
          lockedUntil: null,
        },
      });
    });

    it('clears a pre-existing lockout as part of the reset', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...soleAdmin,
        failedLoginAttempts: 5,
        lockedUntil: new Date(Date.now() + 10 * 60 * 1000),
      });
      mockPrismaService.user.count.mockResolvedValue(1);
      mockPrismaService.passwordHistory.findMany.mockResolvedValue([]);
      (argon2.verify as jest.Mock).mockResolvedValue(false);
      (argon2.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      await service.resetSoleAdminPassword('admin-1', 'New-password1!');

      expect(mockPrismaService.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            failedLoginAttempts: 0,
            lockedUntil: null,
          }),
        }),
      );
    });

    it('rejects when the tenant has a co-Admin who could handle it instead', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(soleAdmin);
      mockPrismaService.user.count.mockResolvedValue(2);

      await expect(
        service.resetSoleAdminPassword('admin-1', 'New-password1!'),
      ).rejects.toThrow(ConflictException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the target does not exist', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(
        service.resetSoleAdminPassword('missing-id', 'New-password1!'),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the target is not an Admin', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: 'viewer-1',
        role: UserRole.VIEWER,
        tenantId: 'tenant-1',
      });

      await expect(
        service.resetSoleAdminPassword('viewer-1', 'New-password1!'),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.user.count).not.toHaveBeenCalled();
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });
  });
});
