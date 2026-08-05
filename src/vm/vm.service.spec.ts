import { Test, TestingModule } from '@nestjs/testing';
import { Logger, NotFoundException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { VmService, VmQueryFilters } from './vm.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  ModuleName,
  Severity,
  VmVulnerabilitiesStatus,
} from '../generated/prisma/enums';
import { UnifiedEvent } from '../common/security-module/types';

const mockPrismaService = {
  vmAsset: {
    upsert: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
  },
  vmVulnerability: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
};

const mockEventEmitter = {
  emit: jest.fn(),
};

describe('VmService', () => {
  let service: VmService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VmService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EventEmitter2, useValue: mockEventEmitter },
      ],
    }).compile();

    service = module.get<VmService>(VmService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('ingest', () => {
    const event: UnifiedEvent = {
      tenantId: 'tenant-1',
      timestamp: new Date(),
      source: ModuleName.VM,
      type: 'vulnerability',
      severity: Severity.HIGH,
      data: {
        assetIP: '10.0.0.5',
        assetName: 'web-server-1',
        assetType: 'server',
        description: 'Outdated OpenSSL version',
        cveId: 'CVE-2026-1234',
      },
    };

    it('upserts the asset by tenantId+ip and creates a vulnerability pointing at it', async () => {
      const asset = { id: 'asset-1', tenantId: 'tenant-1', ip: '10.0.0.5' };
      mockPrismaService.vmAsset.upsert.mockResolvedValue(asset);
      mockPrismaService.vmVulnerability.create.mockResolvedValue({
        id: 'vuln-1',
      });

      await service.ingest(event);

      expect(mockPrismaService.vmAsset.upsert).toHaveBeenCalledWith({
        where: { tenantId_ip: { tenantId: 'tenant-1', ip: '10.0.0.5' } },
        update: {},
        create: {
          tenantId: 'tenant-1',
          name: 'web-server-1',
          ip: '10.0.0.5',
          type: 'server',
        },
      });
      expect(mockPrismaService.vmVulnerability.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          assetId: 'asset-1',
          description: 'Outdated OpenSSL version',
          cveId: 'CVE-2026-1234',
          severity: Severity.HIGH,
          rawData: event.data,
        },
      });
    });

    it('reuses the existing asset id returned by upsert, not a new one', async () => {
      mockPrismaService.vmAsset.upsert.mockResolvedValue({
        id: 'existing-asset',
      });
      mockPrismaService.vmVulnerability.create.mockResolvedValue({
        id: 'vuln-1',
      });

      await service.ingest(event);

      expect(mockPrismaService.vmVulnerability.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ assetId: 'existing-asset' }),
        }),
      );
    });

    it('emits vm.vulnerability.created with the created vulnerability id added to data', async () => {
      mockPrismaService.vmAsset.upsert.mockResolvedValue({ id: 'asset-1' });
      mockPrismaService.vmVulnerability.create.mockResolvedValue({
        id: 'vuln-1',
      });

      await service.ingest(event);

      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'vm.vulnerability.created',
        { ...event, data: { ...event.data, vulnerabilityId: 'vuln-1' } },
      );
    });
  });

  describe('query', () => {
    const baseFilters: VmQueryFilters = { tenantId: 'tenant-1' };

    it('filters by tenantId only and applies default pagination', async () => {
      mockPrismaService.vmVulnerability.findMany.mockResolvedValue([]);

      await service.query(baseFilters);

      expect(mockPrismaService.vmVulnerability.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        skip: 0,
        take: 20,
        orderBy: { createdAt: 'desc' },
      });
    });

    it('adds severity, assetId, and status to the where clause when provided', async () => {
      mockPrismaService.vmVulnerability.findMany.mockResolvedValue([]);

      await service.query({
        tenantId: 'tenant-1',
        severity: Severity.CRITICAL,
        assetId: 'asset-1',
        status: VmVulnerabilitiesStatus.OPEN,
      });

      expect(mockPrismaService.vmVulnerability.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            tenantId: 'tenant-1',
            severity: Severity.CRITICAL,
            assetId: 'asset-1',
            status: VmVulnerabilitiesStatus.OPEN,
          },
        }),
      );
    });

    it('builds a createdAt range when dateFrom/dateTo are provided', async () => {
      const dateFrom = new Date('2026-01-01');
      const dateTo = new Date('2026-01-31');
      mockPrismaService.vmVulnerability.findMany.mockResolvedValue([]);

      await service.query({ tenantId: 'tenant-1', dateFrom, dateTo });

      expect(mockPrismaService.vmVulnerability.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            tenantId: 'tenant-1',
            createdAt: { gte: dateFrom, lte: dateTo },
          },
        }),
      );
    });

    it('computes skip from the requested page', async () => {
      mockPrismaService.vmVulnerability.findMany.mockResolvedValue([]);

      await service.query({ tenantId: 'tenant-1', page: 3, pageSize: 20 });

      expect(mockPrismaService.vmVulnerability.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ skip: 40, take: 20 }),
      );
    });
  });

  describe('healthCheck', () => {
    it('returns ok with the latest ingestion timestamp when records exist', async () => {
      const lastIngestion = new Date('2026-08-04T10:00:00Z');
      mockPrismaService.vmVulnerability.findFirst.mockResolvedValue({
        createdAt: lastIngestion,
      });

      const result = await service.healthCheck();

      expect(result).toEqual({
        module: ModuleName.VM,
        status: 'ok',
        lastIngestion,
      });
    });

    it('returns ok with no lastIngestion when there are no records yet', async () => {
      mockPrismaService.vmVulnerability.findFirst.mockResolvedValue(null);

      const result = await service.healthCheck();

      expect(result).toEqual({
        module: ModuleName.VM,
        status: 'ok',
        lastIngestion: undefined,
      });
    });

    it('returns down and logs the error when the database query fails', async () => {
      const errorSpy = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation();
      const dbError = new Error('connection lost');
      mockPrismaService.vmVulnerability.findFirst.mockRejectedValue(dbError);

      const result = await service.healthCheck();

      expect(result).toEqual({ module: ModuleName.VM, status: 'down' });
      expect(errorSpy).toHaveBeenCalledWith('VM health check failed', dbError);
      errorSpy.mockRestore();
    });
  });

  describe('listAssets', () => {
    it('returns assets scoped to the tenant, oldest first', async () => {
      const assets = [{ id: 'asset-1', tenantId: 'tenant-1' }];
      mockPrismaService.vmAsset.findMany.mockResolvedValue(assets);

      const result = await service.listAssets('tenant-1');

      expect(result).toEqual(assets);
      expect(mockPrismaService.vmAsset.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        orderBy: { createdAt: 'asc' },
      });
    });
  });

  describe('createAsset', () => {
    it('creates an asset scoped to the given tenant', async () => {
      const dto = { name: 'db-server-1', ip: '10.0.0.9', type: 'server' };
      const created = { id: 'asset-2', tenantId: 'tenant-1', ...dto };
      mockPrismaService.vmAsset.create.mockResolvedValue(created);

      const result = await service.createAsset('tenant-1', dto);

      expect(result).toEqual(created);
      expect(mockPrismaService.vmAsset.create).toHaveBeenCalledWith({
        data: { tenantId: 'tenant-1', ...dto },
      });
    });
  });

  describe('updateVulnerabilityStatus', () => {
    const existing = {
      id: 'vuln-1',
      tenantId: 'tenant-1',
      status: VmVulnerabilitiesStatus.OPEN,
    };

    it('updates the status when the vulnerability belongs to the tenant', async () => {
      mockPrismaService.vmVulnerability.findUnique.mockResolvedValue(existing);
      mockPrismaService.vmVulnerability.update.mockResolvedValue({
        ...existing,
        status: VmVulnerabilitiesStatus.REMEDIATED,
      });

      const result = await service.updateVulnerabilityStatus(
        'tenant-1',
        'vuln-1',
        VmVulnerabilitiesStatus.REMEDIATED,
      );

      expect(result.status).toBe(VmVulnerabilitiesStatus.REMEDIATED);
      expect(mockPrismaService.vmVulnerability.update).toHaveBeenCalledWith({
        where: { id: 'vuln-1' },
        data: { status: VmVulnerabilitiesStatus.REMEDIATED },
      });
    });

    it('throws NotFoundException when the vulnerability does not exist', async () => {
      mockPrismaService.vmVulnerability.findUnique.mockResolvedValue(null);

      await expect(
        service.updateVulnerabilityStatus(
          'tenant-1',
          'missing-id',
          VmVulnerabilitiesStatus.REMEDIATED,
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.vmVulnerability.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the vulnerability belongs to a different tenant', async () => {
      mockPrismaService.vmVulnerability.findUnique.mockResolvedValue({
        ...existing,
        tenantId: 'tenant-2',
      });

      await expect(
        service.updateVulnerabilityStatus(
          'tenant-1',
          'vuln-1',
          VmVulnerabilitiesStatus.REMEDIATED,
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.vmVulnerability.update).not.toHaveBeenCalled();
    });
  });
});
