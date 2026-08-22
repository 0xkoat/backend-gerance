import { Test, TestingModule } from '@nestjs/testing';
import { ThrottlerGuard } from '@nestjs/throttler';
import { UnauthorizedException } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserRole } from '../generated/prisma/client';

const mockAuthService = {
  validateUser: jest.fn(),
  login: jest.fn(),
  refresh: jest.fn(),
  logout: jest.fn(),
  requestPasswordReset: jest.fn(),
};

// Kept untyped (not cast to Response here) so `expect(res.cookie)` refers to
// a plain jest.fn(), not an unbound Response-interface method reference —
// the Response cast only happens at each controller call site below.
function mockResponse() {
  return {
    cookie: jest.fn(),
    clearCookie: jest.fn(),
  };
}

type MockResponse = ReturnType<typeof mockResponse>;
type Response = import('express').Response;

describe('AuthController', () => {
  let controller: AuthController;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [{ provide: AuthService, useValue: mockAuthService }],
    })
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('login', () => {
    const safeUser = {
      id: '1',
      email: 'bob@x.com',
      name: 'Bob',
      phoneNumber: '+21612345678',
      role: UserRole.ANALYST,
      tenantId: 'tenant-1',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const tokens = {
      accessToken: 'signed-jwt',
      mustChangePassword: false,
      refreshToken: 'raw-refresh-token',
      refreshTokenExpiresAt: new Date(Date.now() + 1000),
    };

    it('validates credentials, signs a token, sets the refresh cookie, and returns access_token in the body', async () => {
      mockAuthService.validateUser.mockResolvedValue(safeUser);
      mockAuthService.login.mockResolvedValue(tokens);
      const res: MockResponse = mockResponse();

      const result = await controller.login(
        { email: 'bob@x.com', password: 'correct-password' },
        res as unknown as Response,
      );

      expect(mockAuthService.validateUser).toHaveBeenCalledWith(
        'bob@x.com',
        'correct-password',
      );
      expect(mockAuthService.login).toHaveBeenCalledWith(safeUser);
      expect(res.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'raw-refresh-token',
        expect.objectContaining({
          httpOnly: true,
          sameSite: 'lax',
          path: '/api/auth',
        }),
      );
      expect(result).toEqual({
        access_token: 'signed-jwt',
        mustChangePassword: false,
      });
    });

    it('propagates the UnauthorizedException from validateUser without calling login', async () => {
      const error = new Error('Invalid credentials');
      mockAuthService.validateUser.mockRejectedValue(error);
      const res: MockResponse = mockResponse();

      await expect(
        controller.login(
          { email: 'bob@x.com', password: 'wrong-password' },
          res as unknown as Response,
        ),
      ).rejects.toThrow('Invalid credentials');
      expect(mockAuthService.login).not.toHaveBeenCalled();
      expect(res.cookie).not.toHaveBeenCalled();
    });
  });

  describe('refresh', () => {
    const tokens = {
      accessToken: 'new-jwt',
      mustChangePassword: false,
      refreshToken: 'new-raw-refresh-token',
      refreshTokenExpiresAt: new Date(Date.now() + 1000),
    };

    it('rejects when no refresh cookie is present, without calling the service', async () => {
      const req = { cookies: {} } as unknown as import('express').Request;
      const res: MockResponse = mockResponse();

      await expect(
        controller.refresh(req, res as unknown as Response),
      ).rejects.toThrow(UnauthorizedException);
      expect(mockAuthService.refresh).not.toHaveBeenCalled();
    });

    it('rotates the cookie and returns the new access token', async () => {
      const req = {
        cookies: { refresh_token: 'old-raw-refresh-token' },
      } as unknown as import('express').Request;
      const res: MockResponse = mockResponse();
      mockAuthService.refresh.mockResolvedValue(tokens);

      const result = await controller.refresh(req, res as unknown as Response);

      expect(mockAuthService.refresh).toHaveBeenCalledWith(
        'old-raw-refresh-token',
      );
      expect(res.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'new-raw-refresh-token',
        expect.objectContaining({ httpOnly: true, path: '/api/auth' }),
      );
      expect(result).toEqual({
        access_token: 'new-jwt',
        mustChangePassword: false,
      });
    });
  });

  describe('logout', () => {
    it('revokes the presented token and clears the cookie', async () => {
      const req = {
        cookies: { refresh_token: 'raw-refresh-token' },
      } as unknown as import('express').Request;
      const res: MockResponse = mockResponse();

      const result = await controller.logout(req, res as unknown as Response);

      expect(mockAuthService.logout).toHaveBeenCalledWith('raw-refresh-token');
      expect(res.clearCookie).toHaveBeenCalledWith('refresh_token', {
        path: '/api/auth',
      });
      expect(result).toEqual({ message: 'Logged out' });
    });

    it('clears the cookie without calling the service when no cookie is present', async () => {
      const req = { cookies: {} } as unknown as import('express').Request;
      const res: MockResponse = mockResponse();

      const result = await controller.logout(req, res as unknown as Response);

      expect(mockAuthService.logout).not.toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalled();
      expect(result).toEqual({ message: 'Logged out' });
    });
  });

  describe('forgotPassword', () => {
    it('delegates to AuthService and returns a generic confirmation message', async () => {
      mockAuthService.requestPasswordReset.mockResolvedValue(undefined);

      const result = await controller.forgotPassword({ email: 'bob@x.com' });

      expect(mockAuthService.requestPasswordReset).toHaveBeenCalledWith(
        'bob@x.com',
      );
      expect(result).toEqual({
        message:
          'If an account exists with this email, your administrator has been notified.',
      });
    });

    it('returns the same message regardless of whether the email exists (no enumeration)', async () => {
      mockAuthService.requestPasswordReset.mockResolvedValue(undefined);

      const knownResult = await controller.forgotPassword({
        email: 'bob@x.com',
      });
      const unknownResult = await controller.forgotPassword({
        email: 'missing@x.com',
      });

      expect(knownResult).toEqual(unknownResult);
    });
  });
});
