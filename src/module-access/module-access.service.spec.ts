import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { ModuleAccessService } from './module-access.service';
import { ConnectionProbe } from './connection-probe';
import { PrismaService } from '../prisma/prisma.service';
import {
  AnalystLevel,
  ModuleName,
  ModuleProtocol,
  Prisma,
  UserRole,
} from '../generated/prisma/client';

const mockPrismaService = {
  moduleEndpoint: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  tenantModule: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  moduleLaunch: { create: jest.fn(), findMany: jest.fn() },
  user: { findUnique: jest.fn() },
};

const mockConnectionProbe = { probe: jest.fn() };

function prismaKnownError(code: string) {
  return new Prisma.PrismaClientKnownRequestError('mocked prisma error', {
    code,
    clientVersion: 'test',
  });
}

const configuredSiem = {
  moduleName: ModuleName.SIEM,
  protocol: ModuleProtocol.HTTPS,
  host: '10.0.0.5',
  port: 5601,
  path: '/',
};

describe('ModuleAccessService', () => {
  let service: ModuleAccessService;

  beforeEach(async () => {
    jest.resetAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ModuleAccessService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: ConnectionProbe, useValue: mockConnectionProbe },
      ],
    }).compile();

    service = module.get(ModuleAccessService);
  });

  describe('updateEndpoint', () => {
    it('saves the endpoint and who changed it', async () => {
      const dto = {
        protocol: ModuleProtocol.HTTPS,
        host: '10.0.0.5',
        port: 5601,
        path: '/',
      };
      mockPrismaService.moduleEndpoint.update.mockResolvedValue({});

      await service.updateEndpoint(ModuleName.SIEM, dto, 'ia-1');

      expect(mockPrismaService.moduleEndpoint.update).toHaveBeenCalledWith({
        where: { moduleName: ModuleName.SIEM },
        data: { ...dto, updatedById: 'ia-1' },
      });
    });

    it('maps a missing row to 404', async () => {
      mockPrismaService.moduleEndpoint.update.mockRejectedValue(
        prismaKnownError('P2025'),
      );

      await expect(
        service.updateEndpoint(
          ModuleName.SIEM,
          {
            protocol: ModuleProtocol.HTTPS,
            host: 'x',
            port: 1,
            path: '/',
          },
          'ia-1',
        ),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('testConnection', () => {
    it('probes the configured host and port', async () => {
      mockPrismaService.moduleEndpoint.findUnique.mockResolvedValue(
        configuredSiem,
      );
      mockConnectionProbe.probe.mockResolvedValue({
        reachable: true,
        latencyMs: 4,
      });

      await expect(service.testConnection(ModuleName.SIEM)).resolves.toEqual({
        reachable: true,
        latencyMs: 4,
      });
      expect(mockConnectionProbe.probe).toHaveBeenCalledWith('10.0.0.5', 5601);
    });

    it('refuses to probe an unconfigured endpoint', async () => {
      mockPrismaService.moduleEndpoint.findUnique.mockResolvedValue({
        ...configuredSiem,
        host: null,
        port: null,
      });

      await expect(service.testConnection(ModuleName.SIEM)).rejects.toThrow(
        BadRequestException,
      );
      expect(mockConnectionProbe.probe).not.toHaveBeenCalled();
    });
  });

  describe('listForUser', () => {
    beforeEach(() => {
      mockPrismaService.tenantModule.findMany.mockResolvedValue([
        { moduleName: ModuleName.CTI, minAnalystLevel: AnalystLevel.L1 },
        { moduleName: ModuleName.SIEM, minAnalystLevel: AnalystLevel.L2 },
        { moduleName: ModuleName.DFIR, minAnalystLevel: AnalystLevel.L3 },
      ]);
      mockPrismaService.moduleEndpoint.findMany.mockResolvedValue([
        configuredSiem,
        { ...configuredSiem, moduleName: ModuleName.CTI, host: null },
        { ...configuredSiem, moduleName: ModuleName.DFIR },
      ]);
    });

    it("only reads the tenant's active subscriptions", async () => {
      await service.listForUser('tenant-1', UserRole.ADMIN, null);

      expect(mockPrismaService.tenantModule.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1', isActive: true },
        orderBy: { moduleName: 'asc' },
      });
    });

    it('shows an Admin every active module, flagging unconfigured ones', async () => {
      const result = await service.listForUser(
        'tenant-1',
        UserRole.ADMIN,
        null,
      );

      expect(result).toEqual([
        {
          moduleName: ModuleName.CTI,
          minAnalystLevel: AnalystLevel.L1,
          configured: false,
          canLaunch: false,
        },
        {
          moduleName: ModuleName.SIEM,
          minAnalystLevel: AnalystLevel.L2,
          configured: true,
          canLaunch: true,
        },
        {
          moduleName: ModuleName.DFIR,
          minAnalystLevel: AnalystLevel.L3,
          configured: true,
          canLaunch: true,
        },
      ]);
    });

    it('hides modules above an L2 Analyst level', async () => {
      const result = await service.listForUser(
        'tenant-1',
        UserRole.ANALYST,
        AnalystLevel.L2,
      );

      expect(result.map((m) => m.moduleName)).toEqual([
        ModuleName.CTI,
        ModuleName.SIEM,
      ]);
    });
  });

  describe('setMinLevel', () => {
    it("updates the tenant's subscription", async () => {
      mockPrismaService.tenantModule.update.mockResolvedValue({});

      await service.setMinLevel('tenant-1', ModuleName.SIEM, AnalystLevel.L1);

      expect(mockPrismaService.tenantModule.update).toHaveBeenCalledWith({
        where: {
          tenantId_moduleName: {
            tenantId: 'tenant-1',
            moduleName: ModuleName.SIEM,
          },
        },
        data: { minAnalystLevel: AnalystLevel.L1 },
      });
    });

    it('404s for a module the tenant does not have', async () => {
      mockPrismaService.tenantModule.update.mockRejectedValue(
        prismaKnownError('P2025'),
      );

      await expect(
        service.setMinLevel('tenant-1', ModuleName.SIEM, AnalystLevel.L1),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('launch', () => {
    const analyst = {
      id: 'analyst-1',
      email: 'analyst@x.com',
      role: UserRole.ANALYST,
      analystLevel: AnalystLevel.L2,
      tenantId: 'tenant-1',
    };
    const siemSubscription = {
      isActive: true,
      minAnalystLevel: AnalystLevel.L2,
    };

    it('returns the URL and records the launch', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(analyst);
      mockPrismaService.tenantModule.findUnique.mockResolvedValue(
        siemSubscription,
      );
      mockPrismaService.moduleEndpoint.findUnique.mockResolvedValue(
        configuredSiem,
      );

      await expect(
        service.launch('analyst-1', 'tenant-1', ModuleName.SIEM),
      ).resolves.toEqual({ url: 'https://10.0.0.5:5601/' });
      expect(mockPrismaService.moduleLaunch.create).toHaveBeenCalledWith({
        data: {
          userId: 'analyst-1',
          userEmail: 'analyst@x.com',
          role: UserRole.ANALYST,
          tenantId: 'tenant-1',
          moduleName: ModuleName.SIEM,
          targetUrl: 'https://10.0.0.5:5601/',
        },
      });
    });

    it('uses the level stored in the database, not the token', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...analyst,
        analystLevel: AnalystLevel.L1,
      });
      mockPrismaService.tenantModule.findUnique.mockResolvedValue(
        siemSubscription,
      );

      await expect(
        service.launch('analyst-1', 'tenant-1', ModuleName.SIEM),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.moduleLaunch.create).not.toHaveBeenCalled();
    });

    it('lets an Admin launch regardless of the minimum level', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...analyst,
        role: UserRole.ADMIN,
        analystLevel: null,
      });
      mockPrismaService.tenantModule.findUnique.mockResolvedValue({
        isActive: true,
        minAnalystLevel: AnalystLevel.L3,
      });
      mockPrismaService.moduleEndpoint.findUnique.mockResolvedValue(
        configuredSiem,
      );

      await expect(
        service.launch('analyst-1', 'tenant-1', ModuleName.SIEM),
      ).resolves.toEqual({ url: 'https://10.0.0.5:5601/' });
    });

    it('404s when the module is inactive for the tenant', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(analyst);
      mockPrismaService.tenantModule.findUnique.mockResolvedValue({
        ...siemSubscription,
        isActive: false,
      });

      await expect(
        service.launch('analyst-1', 'tenant-1', ModuleName.SIEM),
      ).rejects.toThrow(NotFoundException);
    });

    it('409s when the endpoint is not configured yet', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(analyst);
      mockPrismaService.tenantModule.findUnique.mockResolvedValue(
        siemSubscription,
      );
      mockPrismaService.moduleEndpoint.findUnique.mockResolvedValue({
        ...configuredSiem,
        host: null,
      });

      await expect(
        service.launch('analyst-1', 'tenant-1', ModuleName.SIEM),
      ).rejects.toThrow(ConflictException);
      expect(mockPrismaService.moduleLaunch.create).not.toHaveBeenCalled();
    });

    it('rejects an account that no longer belongs to the tenant', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...analyst,
        tenantId: 'tenant-2',
      });

      await expect(
        service.launch('analyst-1', 'tenant-1', ModuleName.SIEM),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.tenantModule.findUnique).not.toHaveBeenCalled();
    });
  });

  describe('recentLaunches', () => {
    it('returns the newest launches for the tenant', async () => {
      mockPrismaService.moduleLaunch.findMany.mockResolvedValue([]);

      await service.recentLaunches('tenant-1');

      expect(mockPrismaService.moduleLaunch.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        orderBy: { launchedAt: 'desc' },
        take: 50,
      });
    });
  });
});
