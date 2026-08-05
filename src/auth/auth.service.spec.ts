import { Test, TestingModule } from '@nestjs/testing';
import { Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { createHash } from 'crypto';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { PrismaService } from '../prisma/prisma.service';
import { UserRole } from '../generated/prisma/client';

jest.mock('argon2');

const DUMMY_HASH =
  '$argon2id$v=19$m=65536,t=3,p=4$GI8yFc6QCemSdwM0skhZvg$3elgnlxE0oIy891fIvSi8cabR0CpJgR2fGQ/xqKpOys';

function hashOf(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

const mockUsersService = {
  findByEmail: jest.fn(),
  requestPasswordReset: jest.fn(),
};

const mockJwtService = {
  sign: jest.fn(),
};

const mockPrismaService = {
  user: {
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  refreshToken: {
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn(),
    deleteMany: jest.fn(),
  },
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: mockUsersService },
        { provide: JwtService, useValue: mockJwtService },
        { provide: PrismaService, useValue: mockPrismaService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateUser', () => {
    const dbUser = {
      id: '1',
      email: 'bob@x.com',
      name: 'Bob',
      phoneNumber: '+21612345678',
      role: UserRole.ANALYST,
      tenantId: 'tenant-1',
      hashedPassword: 'hashed-password',
      failedLoginAttempts: 0,
      lockedUntil: null,
    };

    it('returns the user without the password hash when credentials are valid', async () => {
      mockUsersService.findByEmail.mockResolvedValue(dbUser);
      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const result = await service.validateUser(
        'bob@x.com',
        'correct-password',
      );

      expect(argon2.verify).toHaveBeenCalledWith(
        'hashed-password',
        'correct-password',
      );
      expect(result).toEqual({
        id: '1',
        email: 'bob@x.com',
        name: 'Bob',
        phoneNumber: '+21612345678',
        role: UserRole.ANALYST,
        tenantId: 'tenant-1',
        failedLoginAttempts: 0,
        lockedUntil: null,
      });
      expect(result).not.toHaveProperty('hashedPassword');
      expect(mockPrismaService.user.update).not.toHaveBeenCalled();
    });

    it('throws UnauthorizedException when no user matches the email', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);
      (argon2.verify as jest.Mock).mockResolvedValue(false);

      await expect(
        service.validateUser('missing@x.com', 'whatever'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('still runs argon2.verify against a dummy hash when no user matches, to avoid a timing side-channel that would let an attacker enumerate valid emails by response time', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);
      (argon2.verify as jest.Mock).mockResolvedValue(false);

      await expect(
        service.validateUser('missing@x.com', 'whatever'),
      ).rejects.toThrow(UnauthorizedException);

      expect(argon2.verify).toHaveBeenCalledWith(DUMMY_HASH, 'whatever');
    });

    it('throws UnauthorizedException when the password is wrong', async () => {
      mockUsersService.findByEmail.mockResolvedValue(dbUser);
      (argon2.verify as jest.Mock).mockResolvedValue(false);

      await expect(
        service.validateUser('bob@x.com', 'wrong-password'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('throws the same error message for unknown email and wrong password (no user enumeration)', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);
      await expect(
        service.validateUser('missing@x.com', 'whatever'),
      ).rejects.toThrow('Invalid credentials');

      mockUsersService.findByEmail.mockResolvedValue(dbUser);
      (argon2.verify as jest.Mock).mockResolvedValue(false);
      await expect(
        service.validateUser('bob@x.com', 'wrong-password'),
      ).rejects.toThrow('Invalid credentials');
    });

    describe('account lockout', () => {
      it('increments failedLoginAttempts on a wrong password, without locking below the threshold', async () => {
        mockUsersService.findByEmail.mockResolvedValue({
          ...dbUser,
          failedLoginAttempts: 2,
        });
        (argon2.verify as jest.Mock).mockResolvedValue(false);

        await expect(
          service.validateUser('bob@x.com', 'wrong-password'),
        ).rejects.toThrow(UnauthorizedException);

        expect(mockPrismaService.user.update).toHaveBeenCalledWith({
          where: { id: '1' },
          data: { failedLoginAttempts: 3, lockedUntil: null },
        });
      });

      it('locks the account once the 5th consecutive failure is reached', async () => {
        mockUsersService.findByEmail.mockResolvedValue({
          ...dbUser,
          failedLoginAttempts: 4,
        });
        (argon2.verify as jest.Mock).mockResolvedValue(false);

        await expect(
          service.validateUser('bob@x.com', 'wrong-password'),
        ).rejects.toThrow(UnauthorizedException);

        expect(mockPrismaService.user.update).toHaveBeenCalledWith({
          where: { id: '1' },
          data: { failedLoginAttempts: 5, lockedUntil: expect.any(Date) },
        });
      });

      it('rejects a correct password while the account is locked, without touching the counters', async () => {
        mockUsersService.findByEmail.mockResolvedValue({
          ...dbUser,
          failedLoginAttempts: 5,
          lockedUntil: new Date(Date.now() + 10 * 60 * 1000),
        });
        (argon2.verify as jest.Mock).mockResolvedValue(true);

        await expect(
          service.validateUser('bob@x.com', 'correct-password'),
        ).rejects.toThrow(UnauthorizedException);

        expect(mockPrismaService.user.update).not.toHaveBeenCalled();
      });

      it('does not extend the lockout when a wrong password is retried during the lockout window', async () => {
        mockUsersService.findByEmail.mockResolvedValue({
          ...dbUser,
          failedLoginAttempts: 5,
          lockedUntil: new Date(Date.now() + 10 * 60 * 1000),
        });
        (argon2.verify as jest.Mock).mockResolvedValue(false);

        await expect(
          service.validateUser('bob@x.com', 'wrong-password'),
        ).rejects.toThrow(UnauthorizedException);

        expect(mockPrismaService.user.update).not.toHaveBeenCalled();
      });

      it('allows login again and clears both counters once lockedUntil has passed', async () => {
        mockUsersService.findByEmail.mockResolvedValue({
          ...dbUser,
          failedLoginAttempts: 5,
          lockedUntil: new Date(Date.now() - 1000),
        });
        (argon2.verify as jest.Mock).mockResolvedValue(true);

        const result = await service.validateUser(
          'bob@x.com',
          'correct-password',
        );

        expect(result.id).toBe('1');
        expect(mockPrismaService.user.update).toHaveBeenCalledWith({
          where: { id: '1' },
          data: { failedLoginAttempts: 0, lockedUntil: null },
        });
      });
    });
  });

  describe('login', () => {
    const safeUser = {
      id: '1',
      email: 'bob@x.com',
      name: 'Bob',
      phoneNumber: '+21612345678',
      role: UserRole.ANALYST,
      tenantId: 'tenant-1',
      mustChangePassword: false,
      passwordResetRequestedAt: null,
      failedLoginAttempts: 0,
      lockedUntil: null,
      updatedAt: new Date(),
      createdAt: new Date(),
    };

    beforeEach(() => {
      mockPrismaService.refreshToken.create.mockResolvedValue({ id: 'rt-1' });
    });

    it('signs a JWT with sub, role, tenantId and mustChangePassword', async () => {
      mockJwtService.sign.mockReturnValue('signed-jwt');

      await service.login(safeUser);

      expect(mockJwtService.sign).toHaveBeenCalledWith({
        sub: '1',
        role: UserRole.ANALYST,
        tenantId: 'tenant-1',
        mustChangePassword: false,
      });
    });

    it('signs tenantId as null for a Super Admin (no tenant)', async () => {
      const superAdmin = {
        ...safeUser,
        id: '2',
        role: UserRole.SUPER_ADMIN,
        tenantId: null,
      };
      mockJwtService.sign.mockReturnValue('signed-jwt');

      await service.login(superAdmin);

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ sub: '2', tenantId: null }),
      );
    });

    it('persists a new refresh token in a fresh family and returns it alongside the access token', async () => {
      mockJwtService.sign.mockReturnValue('signed-jwt');

      const result = await service.login(safeUser);

      expect(mockPrismaService.refreshToken.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: '1',
          tokenHash: expect.any(String),
          familyId: expect.any(String),
          expiresAt: expect.any(Date),
        }),
      });
      expect(result).toEqual({
        accessToken: 'signed-jwt',
        mustChangePassword: false,
        refreshToken: expect.any(String),
        refreshTokenExpiresAt: expect.any(Date),
      });
    });

    it('propagates mustChangePassword: true through to both the JWT payload and the response', async () => {
      const forcedUser = { ...safeUser, mustChangePassword: true };
      mockJwtService.sign.mockReturnValue('signed-jwt');

      const result = await service.login(forcedUser);

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ mustChangePassword: true }),
      );
      expect(result.mustChangePassword).toBe(true);
    });
  });

  describe('refresh', () => {
    const userId = 'user-1';
    const familyId = 'family-1';
    const dbUser = {
      id: userId,
      email: 'bob@x.com',
      name: 'Bob',
      phoneNumber: '+21612345678',
      role: UserRole.ANALYST,
      tenantId: 'tenant-1',
      mustChangePassword: false,
      hashedPassword: 'hash',
      passwordResetRequestedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    it('throws when no token matches the presented value', async () => {
      mockPrismaService.refreshToken.findUnique.mockResolvedValue(null);

      await expect(service.refresh('bogus')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('revokes the entire token family and throws when an already-revoked token is replayed', async () => {
      mockPrismaService.refreshToken.findUnique.mockResolvedValue({
        id: 'rt-1',
        userId,
        familyId,
        tokenHash: hashOf('raw'),
        revokedAt: new Date(),
        expiresAt: new Date(Date.now() + 1000),
      });

      await expect(service.refresh('raw')).rejects.toThrow(
        UnauthorizedException,
      );
      expect(mockPrismaService.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { familyId, revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
    });

    it('throws when the token has expired', async () => {
      mockPrismaService.refreshToken.findUnique.mockResolvedValue({
        id: 'rt-1',
        userId,
        familyId,
        tokenHash: hashOf('raw'),
        revokedAt: null,
        expiresAt: new Date(Date.now() - 1000),
      });

      await expect(service.refresh('raw')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('throws when the referenced user no longer exists', async () => {
      mockPrismaService.refreshToken.findUnique.mockResolvedValue({
        id: 'rt-1',
        userId,
        familyId,
        tokenHash: hashOf('raw'),
        revokedAt: null,
        expiresAt: new Date(Date.now() + 1000),
      });
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(service.refresh('raw')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('rotates: revokes the used token, issues a new one in the same family, and signs a fresh access token', async () => {
      mockPrismaService.refreshToken.findUnique.mockResolvedValue({
        id: 'rt-1',
        userId,
        familyId,
        tokenHash: hashOf('raw'),
        revokedAt: null,
        expiresAt: new Date(Date.now() + 1000),
      });
      mockPrismaService.user.findUnique.mockResolvedValue(dbUser);
      mockPrismaService.refreshToken.create.mockResolvedValue({ id: 'rt-2' });
      mockJwtService.sign.mockReturnValue('new-jwt');

      const result = await service.refresh('raw');

      expect(mockPrismaService.refreshToken.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId,
          familyId,
          tokenHash: expect.any(String),
          expiresAt: expect.any(Date),
        }),
      });
      expect(mockPrismaService.refreshToken.update).toHaveBeenCalledWith({
        where: { id: 'rt-1' },
        data: { revokedAt: expect.any(Date), replacedByTokenId: 'rt-2' },
      });
      expect(result).toEqual({
        accessToken: 'new-jwt',
        mustChangePassword: false,
        refreshToken: expect.any(String),
        refreshTokenExpiresAt: expect.any(Date),
      });
    });

    it('carries mustChangePassword: true through the rotated response', async () => {
      mockPrismaService.refreshToken.findUnique.mockResolvedValue({
        id: 'rt-1',
        userId,
        familyId,
        tokenHash: hashOf('raw'),
        revokedAt: null,
        expiresAt: new Date(Date.now() + 1000),
      });
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...dbUser,
        mustChangePassword: true,
      });
      mockPrismaService.refreshToken.create.mockResolvedValue({ id: 'rt-2' });
      mockJwtService.sign.mockReturnValue('new-jwt');

      const result = await service.refresh('raw');

      expect(result.mustChangePassword).toBe(true);
    });
  });

  describe('logout', () => {
    it('revokes the matching non-revoked token', async () => {
      await service.logout('raw-token');

      expect(mockPrismaService.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { tokenHash: hashOf('raw-token'), revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
    });
  });

  describe('cleanupExpiredRefreshTokens', () => {
    it('deletes only rows past their own expiry', async () => {
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({
        count: 3,
      });

      await service.cleanupExpiredRefreshTokens();

      expect(mockPrismaService.refreshToken.deleteMany).toHaveBeenCalledWith({
        where: { expiresAt: { lt: expect.any(Date) } },
      });
    });

    it('logs the purged count when rows were deleted', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation();
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({
        count: 2,
      });

      await service.cleanupExpiredRefreshTokens();

      expect(logSpy).toHaveBeenCalledWith('Purged 2 expired refresh token(s)');
      logSpy.mockRestore();
    });

    it('does not log when nothing was purged', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation();
      mockPrismaService.refreshToken.deleteMany.mockResolvedValue({
        count: 0,
      });

      await service.cleanupExpiredRefreshTokens();

      expect(logSpy).not.toHaveBeenCalled();
      logSpy.mockRestore();
    });
  });

  describe('requestPasswordReset', () => {
    it('delegates to UsersService.requestPasswordReset', async () => {
      mockUsersService.requestPasswordReset.mockResolvedValue(undefined);

      await service.requestPasswordReset('bob@x.com');

      expect(mockUsersService.requestPasswordReset).toHaveBeenCalledWith(
        'bob@x.com',
      );
    });
  });
});
