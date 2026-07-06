import { Test, TestingModule } from '@nestjs/testing';
import { TenantsController } from './tenants.controller';
import { TenantsService } from './tenants.service';
import { CreateTenantDto } from './dto/createTenant.dto';

const mockTenantsService = {
  createTenantWithAdmin: jest.fn(),
  findAll: jest.fn(),
  findById: jest.fn(),
  deleteTenantWithUsers: jest.fn(),
};

describe('TenantsController', () => {
  let controller: TenantsController;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TenantsController],
      providers: [{ provide: TenantsService, useValue: mockTenantsService }],
    }).compile();

    controller = module.get<TenantsController>(TenantsController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('createTenant', () => {
    const dto: CreateTenantDto = {
      tenantName: 'Acme Corp',
      name: 'Alice Admin',
      email: 'alice@acme.com',
      password: 'Str0ng!Passw0rd',
      phoneNumber: '+21620000001',
    };

    it('delegates to TenantsService.createTenantWithAdmin', async () => {
      const created = { tenant: { id: 'tenant-1' }, admin: { id: 'admin-1' } };
      mockTenantsService.createTenantWithAdmin.mockResolvedValue(created);

      const result = await controller.createTenant(dto);

      expect(mockTenantsService.createTenantWithAdmin).toHaveBeenCalledWith(
        dto,
      );
      expect(result).toEqual(created);
    });
  });

  describe('getAllTenants', () => {
    it('delegates to TenantsService.findAll', async () => {
      const tenants = [{ id: 'tenant-1' }, { id: 'tenant-2' }];
      mockTenantsService.findAll.mockResolvedValue(tenants);

      const result = await controller.getAllTenants();

      expect(result).toEqual(tenants);
    });
  });

  describe('getTenantById', () => {
    it('delegates to TenantsService.findById', async () => {
      const tenant = { id: 'tenant-1' };
      mockTenantsService.findById.mockResolvedValue(tenant);

      const result = await controller.getTenantById('tenant-1');

      expect(mockTenantsService.findById).toHaveBeenCalledWith('tenant-1');
      expect(result).toEqual(tenant);
    });
  });

  describe('deleteTenant', () => {
    it('delegates to TenantsService.deleteTenantWithUsers and returns a confirmation', async () => {
      mockTenantsService.deleteTenantWithUsers.mockResolvedValue({
        id: 'tenant-1',
        name: 'Acme Corp',
        createdAt: new Date(),
      });

      const result = await controller.deleteTenant('tenant-1');

      expect(mockTenantsService.deleteTenantWithUsers).toHaveBeenCalledWith(
        'tenant-1',
      );
      expect(result).toEqual({
        message: 'Tenant and all its accounts deleted successfully',
        id: 'tenant-1',
      });
    });
  });
});
