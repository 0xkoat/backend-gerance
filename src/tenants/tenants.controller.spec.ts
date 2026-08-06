import { Test, TestingModule } from '@nestjs/testing';
import { TenantsController } from './tenants.controller';
import { TenantsService } from './tenants.service';
import { CreateTenantDto } from './dto/createTenant.dto';
import { ModuleName } from '../generated/prisma/enums';

const mockTenantsService = {
  createTenantWithAdmin: jest.fn(),
  findAll: jest.fn(),
  findById: jest.fn(),
  renameTenant: jest.fn(),
  deleteTenantWithUsers: jest.fn(),
  listModules: jest.fn(),
  activateModule: jest.fn(),
  updateModule: jest.fn(),
  deactivateModule: jest.fn(),
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

  describe('renameTenant', () => {
    it('delegates to TenantsService.renameTenant', async () => {
      const renamed = { id: 'tenant-1', name: 'New Name' };
      mockTenantsService.renameTenant.mockResolvedValue(renamed);

      const result = await controller.renameTenant('tenant-1', {
        name: 'New Name',
      });

      expect(mockTenantsService.renameTenant).toHaveBeenCalledWith(
        'tenant-1',
        'New Name',
      );
      expect(result).toEqual(renamed);
    });
  });

  describe('listModules', () => {
    it('delegates to TenantsService.listModules', async () => {
      const modules = [{ id: 'tm-1', moduleName: ModuleName.SIEM }];
      mockTenantsService.listModules.mockResolvedValue(modules);

      const result = await controller.listModules('tenant-1');

      expect(mockTenantsService.listModules).toHaveBeenCalledWith('tenant-1');
      expect(result).toEqual(modules);
    });
  });

  describe('activateModule', () => {
    it('delegates to TenantsService.activateModule', async () => {
      const created = { id: 'tm-1', moduleName: ModuleName.EDR };
      mockTenantsService.activateModule.mockResolvedValue(created);

      const result = await controller.activateModule('tenant-1', {
        moduleName: ModuleName.EDR,
        config: { pollIntervalMinutes: 5 },
      });

      expect(mockTenantsService.activateModule).toHaveBeenCalledWith(
        'tenant-1',
        ModuleName.EDR,
        { pollIntervalMinutes: 5 },
      );
      expect(result).toEqual(created);
    });
  });

  describe('updateModule', () => {
    it('delegates to TenantsService.updateModule', async () => {
      const updated = {
        id: 'tm-1',
        moduleName: ModuleName.EDR,
        isActive: false,
      };
      mockTenantsService.updateModule.mockResolvedValue(updated);

      const result = await controller.updateModule('tenant-1', ModuleName.EDR, {
        isActive: false,
      });

      expect(mockTenantsService.updateModule).toHaveBeenCalledWith(
        'tenant-1',
        ModuleName.EDR,
        { isActive: false },
      );
      expect(result).toEqual(updated);
    });
  });

  describe('deactivateModule', () => {
    it('delegates to TenantsService.deactivateModule', async () => {
      mockTenantsService.deactivateModule.mockResolvedValue(undefined);

      await controller.deactivateModule('tenant-1', ModuleName.EDR);

      expect(mockTenantsService.deactivateModule).toHaveBeenCalledWith(
        'tenant-1',
        ModuleName.EDR,
      );
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
