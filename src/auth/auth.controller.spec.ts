import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserRole } from '../generated/prisma/client';

const mockAuthService = {
  validateUser: jest.fn(),
  login: jest.fn(),
};

describe('AuthController', () => {
  let controller: AuthController;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [{ provide: AuthService, useValue: mockAuthService }],
    }).compile();

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

    it('validates credentials then signs a token, returning the access_token', async () => {
      mockAuthService.validateUser.mockResolvedValue(safeUser);
      mockAuthService.login.mockResolvedValue({ access_token: 'signed-jwt' });

      const result = await controller.login({ email: 'bob@x.com', password: 'correct-password' });

      expect(mockAuthService.validateUser).toHaveBeenCalledWith('bob@x.com', 'correct-password');
      expect(mockAuthService.login).toHaveBeenCalledWith(safeUser);
      expect(result).toEqual({ access_token: 'signed-jwt' });
    });

    it('propagates the UnauthorizedException from validateUser without calling login', async () => {
      const error = new Error('Invalid credentials');
      mockAuthService.validateUser.mockRejectedValue(error);

      await expect(
        controller.login({ email: 'bob@x.com', password: 'wrong-password' }),
      ).rejects.toThrow('Invalid credentials');
      expect(mockAuthService.login).not.toHaveBeenCalled();
    });
  });
});
