import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { UserRole } from '../generated/prisma/client';

jest.mock('argon2');

const mockUsersService = {
  findByEmail: jest.fn(),
  requestPasswordReset: jest.fn(),
};

const mockJwtService = {
  sign: jest.fn(),
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
      });
      expect(result).not.toHaveProperty('hashedPassword');
    });

    it('throws UnauthorizedException when no user matches the email', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);

      await expect(
        service.validateUser('missing@x.com', 'whatever'),
      ).rejects.toThrow(UnauthorizedException);
      expect(argon2.verify).not.toHaveBeenCalled();
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
  });

  describe('login', () => {
    it('signs a JWT with sub, role, tenantId and mustChangePassword, and returns them alongside access_token', async () => {
      const safeUser = {
        id: '1',
        email: 'bob@x.com',
        name: 'Bob',
        phoneNumber: '+21612345678',
        role: UserRole.ANALYST,
        tenantId: 'tenant-1',
        mustChangePassword: false,
        passwordResetRequestedAt: null,
        updatedAt: new Date(),
        createdAt: new Date(),
      };
      mockJwtService.sign.mockReturnValue('signed-jwt');

      const result = await service.login(safeUser);

      expect(mockJwtService.sign).toHaveBeenCalledWith({
        sub: '1',
        role: UserRole.ANALYST,
        tenantId: 'tenant-1',
        mustChangePassword: false,
      });
      expect(result).toEqual({
        access_token: 'signed-jwt',
        mustChangePassword: false,
      });
    });

    it('signs tenantId as null for a Super Admin (no tenant)', async () => {
      const safeUser = {
        id: '2',
        email: 'root@x.com',
        name: 'Root',
        phoneNumber: '+21600000000',
        role: UserRole.SUPER_ADMIN,
        tenantId: null,
        mustChangePassword: false,
        passwordResetRequestedAt: null,
        updatedAt: new Date(),
        createdAt: new Date(),
      };
      mockJwtService.sign.mockReturnValue('signed-jwt');

      const result = await service.login(safeUser);

      expect(mockJwtService.sign).toHaveBeenCalledWith({
        sub: '2',
        role: UserRole.SUPER_ADMIN,
        tenantId: null,
        mustChangePassword: false,
      });
      expect(result).toEqual({
        access_token: 'signed-jwt',
        mustChangePassword: false,
      });
    });

    it('propagates mustChangePassword: true through to both the JWT payload and the response body', async () => {
      const safeUser = {
        id: '3',
        email: 'reset@x.com',
        name: 'Reset User',
        phoneNumber: '+21620000003',
        role: UserRole.VIEWER,
        tenantId: 'tenant-1',
        mustChangePassword: true,
        passwordResetRequestedAt: null,
        updatedAt: new Date(),
        createdAt: new Date(),
      };
      mockJwtService.sign.mockReturnValue('signed-jwt');

      const result = await service.login(safeUser);

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ mustChangePassword: true }),
      );
      expect(result).toEqual({
        access_token: 'signed-jwt',
        mustChangePassword: true,
      });
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
