import { Test, TestingModule } from '@nestjs/testing';
import { ConflictException, Logger, NotFoundException } from '@nestjs/common';
import * as argon2 from 'argon2';
import { TenantsService } from './tenants.service';
import { PrismaService } from '../prisma/prisma.service';
import { ModuleName, Prisma, UserRole } from '../generated/prisma/client';
import { CreateTenantDto } from './dto/createTenant.dto';

jest.mock('argon2');

const mockTx = {
  tenant: { create: jest.fn() },
  user: { create: jest.fn() },
};

function defaultTransactionImplementation(
  arg: ((tx: typeof mockTx) => unknown) | unknown[],
) {
  if (typeof arg === 'function') {
    return arg(mockTx);
  }
  return Promise.all(arg);
}

const mockPrismaService = {
  tenant: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  user: {
    deleteMany: jest.fn(),
  },
  tenantModule: {
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    deleteMany: jest.fn(),
  },
  assetFeedEntry: { deleteMany: jest.fn() },
  dfirLink: { deleteMany: jest.fn() },
  dfirIncident: { deleteMany: jest.fn() },
  soarExecution: { deleteMany: jest.fn() },
  soarPlaybook: { deleteMany: jest.fn() },
  siemAlert: { deleteMany: jest.fn() },
  siemLog: { deleteMany: jest.fn() },
  edrDetection: { deleteMany: jest.fn() },
  edrEndpoint: { deleteMany: jest.fn() },
  ctiIoc: { deleteMany: jest.fn() },
  vmVulnerability: { deleteMany: jest.fn() },
  vmAsset: { deleteMany: jest.fn() },
  refreshToken: { deleteMany: jest.fn() },
  passwordHistory: { deleteMany: jest.fn() },
  $transaction: jest.fn(defaultTransactionImplementation),
};

function prismaKnownError(code: string) {
  return new Prisma.PrismaClientKnownRequestError('mocked prisma error', {
    code,
    clientVersion: '7.8.0',
  });
}

describe('TenantsService', () => {
  let service: TenantsService;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockPrismaService.$transaction.mockImplementation(
      defaultTransactionImplementation,
    );

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TenantsService,
        { provide: PrismaService, useValue: mockPrismaService },
      ],
    }).compile();

    service = module.get<TenantsService>(TenantsService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createTenantWithAdmin', () => {
    const dto: CreateTenantDto = {
      tenantName: 'Acme Corp',
      name: 'Alice Admin',
      email: 'alice@acme.com',
      password: 'Str0ng!Passw0rd',
      phoneNumber: '+21620000001',
    };

    beforeEach(() => {
      (argon2.hash as jest.Mock).mockResolvedValue('hashed-password');
    });

    it('creates a tenant and its first Admin inside a transaction, without leaking the hash', async () => {
      const createdTenant = {
        id: 'tenant-1',
        name: 'Acme Corp',
        createdAt: new Date(),
      };
      const createdAdmin = {
        id: 'admin-1',
        name: 'Alice Admin',
        email: 'alice@acme.com',
        phoneNumber: '+21620000001',
        role: UserRole.ADMIN,
        tenantId: 'tenant-1',
        hashedPassword: 'hashed-password',
      };
      mockTx.tenant.create.mockResolvedValue(createdTenant);
      mockTx.user.create.mockResolvedValue(createdAdmin);

      const result = await service.createTenantWithAdmin(dto);

      expect(argon2.hash).toHaveBeenCalledWith(dto.password);
      expect(mockTx.tenant.create).toHaveBeenCalledWith({
        data: { name: 'Acme Corp' },
      });
      expect(mockTx.user.create).toHaveBeenCalledWith({
        data: {
          name: dto.name,
          email: dto.email,
          phoneNumber: dto.phoneNumber,
          hashedPassword: 'hashed-password',
          role: UserRole.ADMIN,
          tenantId: 'tenant-1',
          mustChangePassword: true,
        },
      });
      expect(result.tenant).toEqual(createdTenant);
      expect(result.admin).not.toHaveProperty('hashedPassword');
      expect(result.admin).toEqual(
        expect.objectContaining({ id: 'admin-1', role: UserRole.ADMIN }),
      );
    });

    it('throws ConflictException and logs a warning when the admin email already exists (Prisma P2002)', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
      (mockPrismaService.$transaction as jest.Mock).mockRejectedValue(
        prismaKnownError('P2002'),
      );

      await expect(service.createTenantWithAdmin(dto)).rejects.toThrow(
        ConflictException,
      );
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining(dto.email));
      warnSpy.mockRestore();
    });

    it('rethrows unrelated errors instead of swallowing them', async () => {
      (mockPrismaService.$transaction as jest.Mock).mockRejectedValue(
        new Error('database connection lost'),
      );

      await expect(service.createTenantWithAdmin(dto)).rejects.toThrow(
        'database connection lost',
      );
    });
  });

  describe('findAll', () => {
    it('returns all tenants', async () => {
      const tenants = [
        { id: 'tenant-1', name: 'Acme Corp', createdAt: new Date() },
      ];
      mockPrismaService.tenant.findMany.mockResolvedValue(tenants);

      const result = await service.findAll();

      expect(result).toEqual(tenants);
    });
  });

  describe('findById', () => {
    it('returns the tenant with its admins, hashed passwords stripped', async () => {
      const tenant = {
        id: 'tenant-1',
        name: 'Acme Corp',
        createdAt: new Date(),
        users: [
          {
            id: 'admin-1',
            name: 'Alice Admin',
            role: UserRole.ADMIN,
            hashedPassword: 'secret-hash',
          },
        ],
      };
      mockPrismaService.tenant.findUnique.mockResolvedValue(tenant);

      const result = await service.findById('tenant-1');

      expect(mockPrismaService.tenant.findUnique).toHaveBeenCalledWith({
        where: { id: 'tenant-1' },
        include: {
          users: {
            where: { role: UserRole.ADMIN },
            orderBy: { createdAt: 'asc' },
          },
        },
      });
      expect(result).not.toHaveProperty('users');
      expect(result.admins).toEqual([
        { id: 'admin-1', name: 'Alice Admin', role: UserRole.ADMIN },
      ]);
      expect(result.admins[0]).not.toHaveProperty('hashedPassword');
    });

    it('throws NotFoundException when no tenant matches', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue(null);

      await expect(service.findById('missing-id')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('renameTenant', () => {
    it('renames a tenant that exists', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
        name: 'Old Name',
      });
      mockPrismaService.tenant.update.mockResolvedValue({
        id: 'tenant-1',
        name: 'New Name',
      });

      const result = await service.renameTenant('tenant-1', 'New Name');

      expect(result).toEqual({ id: 'tenant-1', name: 'New Name' });
      expect(mockPrismaService.tenant.update).toHaveBeenCalledWith({
        where: { id: 'tenant-1' },
        data: { name: 'New Name' },
      });
    });

    it('throws NotFoundException when the tenant does not exist', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue(null);

      await expect(
        service.renameTenant('missing-id', 'New Name'),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.tenant.update).not.toHaveBeenCalled();
    });
  });

  describe('listModules', () => {
    it('returns modules scoped to the tenant', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
      });
      const modules = [
        { id: 'tm-1', tenantId: 'tenant-1', moduleName: ModuleName.SIEM },
      ];
      mockPrismaService.tenantModule.findMany.mockResolvedValue(modules);

      const result = await service.listModules('tenant-1');

      expect(result).toEqual(modules);
      expect(mockPrismaService.tenantModule.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
      });
    });

    it('throws NotFoundException when the tenant does not exist', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue(null);

      await expect(service.listModules('missing-id')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('activateModule', () => {
    it('creates a TenantModule row', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
      });
      const created = {
        id: 'tm-1',
        tenantId: 'tenant-1',
        moduleName: ModuleName.EDR,
        isActive: true,
      };
      mockPrismaService.tenantModule.create.mockResolvedValue(created);

      const result = await service.activateModule('tenant-1', ModuleName.EDR, {
        pollIntervalMinutes: 5,
      });

      expect(result).toEqual(created);
      expect(mockPrismaService.tenantModule.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          moduleName: ModuleName.EDR,
          config: { pollIntervalMinutes: 5 },
        },
      });
    });

    it('throws ConflictException when the module is already configured (P2002)', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
      });
      mockPrismaService.tenantModule.create.mockRejectedValue(
        prismaKnownError('P2002'),
      );

      await expect(
        service.activateModule('tenant-1', ModuleName.EDR),
      ).rejects.toThrow(ConflictException);
    });

    it('throws NotFoundException when the tenant does not exist', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue(null);

      await expect(
        service.activateModule('missing-id', ModuleName.EDR),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.tenantModule.create).not.toHaveBeenCalled();
    });
  });

  describe('updateModule', () => {
    it('updates a TenantModule row', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
      });
      const updated = {
        id: 'tm-1',
        tenantId: 'tenant-1',
        moduleName: ModuleName.EDR,
        isActive: false,
      };
      mockPrismaService.tenantModule.update.mockResolvedValue(updated);

      const result = await service.updateModule('tenant-1', ModuleName.EDR, {
        isActive: false,
      });

      expect(result).toEqual(updated);
      expect(mockPrismaService.tenantModule.update).toHaveBeenCalledWith({
        where: {
          tenantId_moduleName: {
            tenantId: 'tenant-1',
            moduleName: ModuleName.EDR,
          },
        },
        data: { isActive: false },
      });
    });

    it('throws NotFoundException when the module is not configured (P2025)', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
      });
      mockPrismaService.tenantModule.update.mockRejectedValue(
        prismaKnownError('P2025'),
      );

      await expect(
        service.updateModule('tenant-1', ModuleName.EDR, { isActive: false }),
      ).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when the tenant does not exist', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue(null);

      await expect(
        service.updateModule('missing-id', ModuleName.EDR, {}),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.tenantModule.update).not.toHaveBeenCalled();
    });
  });

  describe('deactivateModule', () => {
    it('deletes a TenantModule row', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
      });
      mockPrismaService.tenantModule.delete.mockResolvedValue({
        id: 'tm-1',
      });

      await service.deactivateModule('tenant-1', ModuleName.EDR);

      expect(mockPrismaService.tenantModule.delete).toHaveBeenCalledWith({
        where: {
          tenantId_moduleName: {
            tenantId: 'tenant-1',
            moduleName: ModuleName.EDR,
          },
        },
      });
    });

    it('throws NotFoundException when the module is not configured (P2025)', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
      });
      mockPrismaService.tenantModule.delete.mockRejectedValue(
        prismaKnownError('P2025'),
      );

      await expect(
        service.deactivateModule('tenant-1', ModuleName.EDR),
      ).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when the tenant does not exist', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue(null);

      await expect(
        service.deactivateModule('missing-id', ModuleName.EDR),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.tenantModule.delete).not.toHaveBeenCalled();
    });
  });

  describe('deleteTenantWithUsers', () => {
    const existingTenant = {
      id: 'tenant-1',
      name: 'Acme Corp',
      createdAt: new Date(),
    };

    it('deletes every security-module table scoped to the tenant, then tenant modules, users, and finally the tenant itself', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        ...existingTenant,
        users: [],
      });
      mockPrismaService.tenant.delete.mockResolvedValue(existingTenant);

      const result = await service.deleteTenantWithUsers('tenant-1');

      const scopedTables = [
        mockPrismaService.assetFeedEntry,
        mockPrismaService.dfirLink,
        mockPrismaService.dfirIncident,
        mockPrismaService.soarExecution,
        mockPrismaService.soarPlaybook,
        mockPrismaService.siemAlert,
        mockPrismaService.siemLog,
        mockPrismaService.edrDetection,
        mockPrismaService.edrEndpoint,
        mockPrismaService.ctiIoc,
        mockPrismaService.vmVulnerability,
        mockPrismaService.vmAsset,
        mockPrismaService.tenantModule,
        mockPrismaService.user,
      ];
      for (const table of scopedTables) {
        expect(table.deleteMany).toHaveBeenCalledWith({
          where: { tenantId: 'tenant-1' },
        });
      }
      expect(mockPrismaService.refreshToken.deleteMany).toHaveBeenCalledWith({
        where: { user: { tenantId: 'tenant-1' } },
      });
      expect(mockPrismaService.passwordHistory.deleteMany).toHaveBeenCalledWith(
        { where: { user: { tenantId: 'tenant-1' } } },
      );
      expect(mockPrismaService.tenant.delete).toHaveBeenCalledWith({
        where: { id: 'tenant-1' },
      });
      expect(result).toEqual(existingTenant);
    });

    it('deletes the module tables that reference other module tables before those tables', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        ...existingTenant,
        users: [],
      });
      mockPrismaService.tenant.delete.mockResolvedValue(existingTenant);
      const callOrder: string[] = [];
      const trackCall = (name: string, mockFn: jest.Mock) =>
        mockFn.mockImplementation(() => {
          callOrder.push(name);
          return Promise.resolve({ count: 0 });
        });
      trackCall('dfirLink', mockPrismaService.dfirLink.deleteMany);
      trackCall('dfirIncident', mockPrismaService.dfirIncident.deleteMany);
      trackCall('soarExecution', mockPrismaService.soarExecution.deleteMany);
      trackCall('soarPlaybook', mockPrismaService.soarPlaybook.deleteMany);
      trackCall('siemAlert', mockPrismaService.siemAlert.deleteMany);
      trackCall('edrDetection', mockPrismaService.edrDetection.deleteMany);
      trackCall('edrEndpoint', mockPrismaService.edrEndpoint.deleteMany);
      trackCall(
        'vmVulnerability',
        mockPrismaService.vmVulnerability.deleteMany,
      );
      trackCall('vmAsset', mockPrismaService.vmAsset.deleteMany);
      trackCall('refreshToken', mockPrismaService.refreshToken.deleteMany);
      trackCall(
        'passwordHistory',
        mockPrismaService.passwordHistory.deleteMany,
      );
      trackCall('user', mockPrismaService.user.deleteMany);

      await service.deleteTenantWithUsers('tenant-1');

      expect(callOrder.indexOf('dfirLink')).toBeLessThan(
        callOrder.indexOf('dfirIncident'),
      );
      expect(callOrder.indexOf('soarExecution')).toBeLessThan(
        callOrder.indexOf('soarPlaybook'),
      );
      expect(callOrder.indexOf('soarExecution')).toBeLessThan(
        callOrder.indexOf('siemAlert'),
      );
      expect(callOrder.indexOf('edrDetection')).toBeLessThan(
        callOrder.indexOf('edrEndpoint'),
      );
      expect(callOrder.indexOf('vmVulnerability')).toBeLessThan(
        callOrder.indexOf('vmAsset'),
      );
      expect(callOrder.indexOf('siemAlert')).toBeLessThan(
        callOrder.indexOf('user'),
      );
      expect(callOrder.indexOf('refreshToken')).toBeLessThan(
        callOrder.indexOf('user'),
      );
      expect(callOrder.indexOf('passwordHistory')).toBeLessThan(
        callOrder.indexOf('user'),
      );
    });

    it('throws NotFoundException when the tenant does not exist, without touching any data', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue(null);

      await expect(service.deleteTenantWithUsers('missing-id')).rejects.toThrow(
        NotFoundException,
      );
      expect(mockPrismaService.$transaction).not.toHaveBeenCalled();
      expect(mockPrismaService.user.deleteMany).not.toHaveBeenCalled();
    });
  });
});
