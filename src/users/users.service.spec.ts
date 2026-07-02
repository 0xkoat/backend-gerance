import { Test, TestingModule } from '@nestjs/testing';
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
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

  describe('findById', () => {
    it('returns the user when found', async () => {
      const user = { id: '1', email: 'bob@x.com' };
      mockPrismaService.user.findUnique.mockResolvedValue(user);

      const result = await service.findById('1');

      expect(result).toEqual(user);
    });

    it('throws NotFoundException when no user matches', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(service.findById('missing-id')).rejects.toThrow(NotFoundException);
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
      const createdUser = { id: '1', ...dto, hashedPassword: 'hashed-password' };
      mockPrismaService.user.create.mockResolvedValue(createdUser);

      const result = await service.createUser(dto, UserRole.ANALYST, 'tenant-1');

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
      mockPrismaService.user.create.mockResolvedValue({ id: '1', ...dto, tenantId: null });

      await service.createUser(dto, UserRole.ADMIN, null);

      expect(mockPrismaService.user.create).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ tenantId: null }) }),
      );
    });

    it('throws ConflictException when the email already exists (Prisma P2002)', async () => {
      mockPrismaService.user.create.mockRejectedValue(prismaKnownError('P2002'));

      await expect(service.createUser(dto, UserRole.VIEWER, 'tenant-1')).rejects.toThrow(
        ConflictException,
      );
    });

    it('rethrows unrelated errors instead of swallowing them', async () => {
      const unexpected = new Error('database connection lost');
      mockPrismaService.user.create.mockRejectedValue(unexpected);

      await expect(service.createUser(dto, UserRole.VIEWER, 'tenant-1')).rejects.toThrow(
        'database connection lost',
      );
    });
  });

  describe('updateUser', () => {
    const dto: UpdateUserDto = { name: 'New Name' };

    it('updates and returns the user on success', async () => {
      const updatedUser = { id: '1', name: 'New Name' };
      mockPrismaService.user.update.mockResolvedValue(updatedUser);

      const result = await service.updateUser('1', dto);

      expect(result).toEqual(updatedUser);
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: dto,
      });
    });

    it('throws NotFoundException when the user does not exist (Prisma P2025)', async () => {
      mockPrismaService.user.update.mockRejectedValue(prismaKnownError('P2025'));

      await expect(service.updateUser('missing-id', dto)).rejects.toThrow(NotFoundException);
    });

    it('throws ConflictException when the new email collides with another user (Prisma P2002)', async () => {
      mockPrismaService.user.update.mockRejectedValue(prismaKnownError('P2002'));

      await expect(service.updateUser('1', { email: 'taken@x.com' })).rejects.toThrow(
        ConflictException,
      );
    });

    it('rethrows unrelated errors instead of swallowing them', async () => {
      mockPrismaService.user.update.mockRejectedValue(new Error('unexpected failure'));

      await expect(service.updateUser('1', dto)).rejects.toThrow('unexpected failure');
    });
  });

  describe('removeUser', () => {
    it('deletes and returns the user on success', async () => {
      const deletedUser = { id: '1' };
      mockPrismaService.user.delete.mockResolvedValue(deletedUser);

      const result = await service.removeUser('1');

      expect(result).toEqual(deletedUser);
      expect(mockPrismaService.user.delete).toHaveBeenCalledWith({ where: { id: '1' } });
    });

    it('throws NotFoundException when the user does not exist (Prisma P2025)', async () => {
      mockPrismaService.user.delete.mockRejectedValue(prismaKnownError('P2025'));

      await expect(service.removeUser('missing-id')).rejects.toThrow(NotFoundException);
    });

    it('rethrows unrelated errors instead of swallowing them', async () => {
      mockPrismaService.user.delete.mockRejectedValue(new Error('unexpected failure'));

      await expect(service.removeUser('1')).rejects.toThrow('unexpected failure');
    });
  });
});
