import { Test, TestingModule } from '@nestjs/testing';
import {
  ConflictException,
  ForbiddenException,
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
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
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
    it('returns users scoped to the given tenant', async () => {
      const users = [{ id: '1', tenantId: 'tenant-1' }];
      mockPrismaService.user.findMany.mockResolvedValue(users);

      const result = await service.findAllForTenant('tenant-1');

      expect(result).toEqual(users);
      expect(mockPrismaService.user.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
      });
    });

    it('returns an empty array when the tenant has no users', async () => {
      mockPrismaService.user.findMany.mockResolvedValue([]);

      const result = await service.findAllForTenant('empty-tenant');

      expect(result).toEqual([]);
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

    it('throws ConflictException when the email already exists (Prisma P2002)', async () => {
      mockPrismaService.user.create.mockRejectedValue(
        prismaKnownError('P2002'),
      );

      await expect(
        service.createUser(dto, UserRole.VIEWER, 'tenant-1'),
      ).rejects.toThrow(ConflictException);
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

    it('throws ConflictException when the new email collides with another user (Prisma P2002)', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      mockPrismaService.user.update.mockRejectedValue(
        prismaKnownError('P2002'),
      );

      await expect(
        service.updateUserForTenant('1', 'tenant-1', { email: 'taken@x.com' }),
      ).rejects.toThrow(ConflictException);
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
    const existingUser = { id: '1', hashedPassword: 'old-hashed-password' };

    it('verifies the current password, hashes the new one, and updates it', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      (argon2.verify as jest.Mock).mockResolvedValue(true);
      (argon2.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      await service.changePassword('1', 'old-password', 'New-password1!');

      expect(argon2.verify).toHaveBeenCalledWith(
        'old-hashed-password',
        'old-password',
      );
      expect(argon2.hash).toHaveBeenCalledWith('New-password1!');
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: {
          hashedPassword: 'new-hashed-password',
          mustChangePassword: false,
        },
      });
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
      const existingUser = { id: '1', tenantId: 'tenant-1' };
      mockPrismaService.user.findUnique.mockResolvedValue(existingUser);
      (argon2.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      await service.resetPasswordForTenant('1', 'tenant-1', 'New-password1!');

      expect(argon2.hash).toHaveBeenCalledWith('New-password1!');
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: {
          hashedPassword: 'new-hashed-password',
          mustChangePassword: true,
          passwordResetRequestedAt: null,
        },
      });
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
});
