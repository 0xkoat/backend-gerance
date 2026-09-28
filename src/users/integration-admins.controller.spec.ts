import { Test, TestingModule } from '@nestjs/testing';
import { IntegrationAdminsController } from './integration-admins.controller';
import { UsersService } from './users.service';
import { UserRole } from '../generated/prisma/enums';
import { CreateUserDto } from './dto/createUser.dto';

const mockUsersService = {
  createUser: jest.fn(),
  findAllIntegrationAdmins: jest.fn(),
  resetIntegrationAdminPassword: jest.fn(),
  removeIntegrationAdmin: jest.fn(),
};

describe('IntegrationAdminsController', () => {
  let controller: IntegrationAdminsController;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [IntegrationAdminsController],
      providers: [{ provide: UsersService, useValue: mockUsersService }],
    }).compile();

    controller = module.get(IntegrationAdminsController);
  });

  it('creates a platform-wide INTEGRATION_ADMIN without returning the hash', async () => {
    const dto: CreateUserDto = {
      name: 'Integrator',
      email: 'ia@x.com',
      password: 'Str0ng!Passw0rd',
      phoneNumber: '+21612345678',
    };
    mockUsersService.createUser.mockResolvedValue({
      id: 'ia-1',
      ...dto,
      role: UserRole.INTEGRATION_ADMIN,
      tenantId: null,
      hashedPassword: 'hash',
    });

    const result = await controller.create(dto);

    expect(mockUsersService.createUser).toHaveBeenCalledWith(
      dto,
      UserRole.INTEGRATION_ADMIN,
      null,
    );
    expect(result).not.toHaveProperty('hashedPassword');
  });

  it('lists integration admins', async () => {
    mockUsersService.findAllIntegrationAdmins.mockResolvedValue([]);

    await expect(controller.findAll()).resolves.toEqual([]);
  });

  it('resets an integration admin password', async () => {
    await expect(
      controller.resetPassword('ia-1', { newPassword: 'New-password1!' }),
    ).resolves.toEqual({ message: 'Password reset successfully' });
    expect(mockUsersService.resetIntegrationAdminPassword).toHaveBeenCalledWith(
      'ia-1',
      'New-password1!',
    );
  });

  it('deletes an integration admin', async () => {
    await expect(controller.remove('ia-1')).resolves.toEqual({
      message: 'Integration Admin deleted successfully',
      id: 'ia-1',
    });
    expect(mockUsersService.removeIntegrationAdmin).toHaveBeenCalledWith(
      'ia-1',
    );
  });
});
