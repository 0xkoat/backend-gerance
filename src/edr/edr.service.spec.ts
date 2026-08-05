import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { EdrService, EdrQueryFilters } from './edr.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  ModuleName,
  Severity,
  EdrEndpointStatus,
} from '../generated/prisma/enums';
import { UnifiedEvent } from '../common/security-module/types';

const mockPrismaService = {
  edrEndpoint: {
    upsert: jest.fn(),
    findMany: jest.fn(),
  },
  edrDetection: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
  },
};

const mockEventEmitter = {
  emit: jest.fn(),
};

describe('EdrService', () => {
  let service: EdrService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EdrService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EventEmitter2, useValue: mockEventEmitter },
      ],
    }).compile();

    service = module.get<EdrService>(EdrService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('ingest', () => {
    const event: UnifiedEvent = {
      tenantId: 'tenant-1',
      timestamp: new Date(),
      source: ModuleName.EDR,
      type: 'detection',
      severity: Severity.HIGH,
      data: {
        hostname: 'web-server-1',
        ip: '10.0.0.5',
        os: 'Ubuntu 24.04',
        detectionName: 'Suspicious PowerShell execution chain',
      },
    };

    it('upserts the endpoint by tenantId+hostname, marks it online, and creates a detection', async () => {
      const endpoint = { id: 'endpoint-1', tenantId: 'tenant-1' };
      mockPrismaService.edrEndpoint.upsert.mockResolvedValue(endpoint);
      mockPrismaService.edrDetection.create.mockResolvedValue({
        id: 'detection-1',
      });

      await service.ingest(event);

      expect(mockPrismaService.edrEndpoint.upsert).toHaveBeenCalledWith({
        where: {
          tenantId_hostname: { tenantId: 'tenant-1', hostname: 'web-server-1' },
        },
        update: {
          ip: '10.0.0.5',
          os: 'Ubuntu 24.04',
          status: EdrEndpointStatus.ONLINE,
          lastSeen: expect.any(Date),
        },
        create: {
          tenantId: 'tenant-1',
          hostname: 'web-server-1',
          ip: '10.0.0.5',
          os: 'Ubuntu 24.04',
          status: EdrEndpointStatus.ONLINE,
        },
      });
      expect(mockPrismaService.edrDetection.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          endpointId: 'endpoint-1',
          detectionName: 'Suspicious PowerShell execution chain',
          severity: Severity.HIGH,
          rawData: event.data,
        },
      });
    });

    it('emits edr.detection.created with the created detection id added to data', async () => {
      mockPrismaService.edrEndpoint.upsert.mockResolvedValue({
        id: 'endpoint-1',
      });
      mockPrismaService.edrDetection.create.mockResolvedValue({
        id: 'detection-1',
      });

      await service.ingest(event);

      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'edr.detection.created',
        { ...event, data: { ...event.data, detectionId: 'detection-1' } },
      );
    });
  });

  describe('query', () => {
    const baseFilters: EdrQueryFilters = { tenantId: 'tenant-1' };

    it('filters by tenantId only and applies default pagination', async () => {
      mockPrismaService.edrDetection.findMany.mockResolvedValue([]);

      await service.query(baseFilters);

      expect(mockPrismaService.edrDetection.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        skip: 0,
        take: 20,
        orderBy: { createdAt: 'desc' },
      });
    });

    it('adds severity and endpointId to the where clause when provided', async () => {
      mockPrismaService.edrDetection.findMany.mockResolvedValue([]);

      await service.query({
        tenantId: 'tenant-1',
        severity: Severity.CRITICAL,
        endpointId: 'endpoint-1',
      });

      expect(mockPrismaService.edrDetection.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            tenantId: 'tenant-1',
            severity: Severity.CRITICAL,
            endpointId: 'endpoint-1',
          },
        }),
      );
    });

    it('builds a createdAt range when dateFrom/dateTo are provided', async () => {
      const dateFrom = new Date('2026-01-01');
      const dateTo = new Date('2026-01-31');
      mockPrismaService.edrDetection.findMany.mockResolvedValue([]);

      await service.query({ tenantId: 'tenant-1', dateFrom, dateTo });

      expect(mockPrismaService.edrDetection.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            tenantId: 'tenant-1',
            createdAt: { gte: dateFrom, lte: dateTo },
          },
        }),
      );
    });

    it('computes skip from the requested page', async () => {
      mockPrismaService.edrDetection.findMany.mockResolvedValue([]);

      await service.query({ tenantId: 'tenant-1', page: 3, pageSize: 20 });

      expect(mockPrismaService.edrDetection.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ skip: 40, take: 20 }),
      );
    });
  });

  describe('healthCheck', () => {
    it('returns ok with the latest ingestion timestamp when records exist', async () => {
      const lastIngestion = new Date('2026-08-04T10:00:00Z');
      mockPrismaService.edrDetection.findFirst.mockResolvedValue({
        createdAt: lastIngestion,
      });

      const result = await service.healthCheck();

      expect(result).toEqual({
        module: ModuleName.EDR,
        status: 'ok',
        lastIngestion,
      });
    });

    it('returns ok with no lastIngestion when there are no records yet', async () => {
      mockPrismaService.edrDetection.findFirst.mockResolvedValue(null);

      const result = await service.healthCheck();

      expect(result).toEqual({
        module: ModuleName.EDR,
        status: 'ok',
        lastIngestion: undefined,
      });
    });

    it('returns down when the database query fails', async () => {
      mockPrismaService.edrDetection.findFirst.mockRejectedValue(
        new Error('connection lost'),
      );

      const result = await service.healthCheck();

      expect(result).toEqual({ module: ModuleName.EDR, status: 'down' });
    });
  });

  describe('listEndpoints', () => {
    it('returns endpoints scoped to the tenant, most recently seen first', async () => {
      const endpoints = [{ id: 'endpoint-1', tenantId: 'tenant-1' }];
      mockPrismaService.edrEndpoint.findMany.mockResolvedValue(endpoints);

      const result = await service.listEndpoints('tenant-1');

      expect(result).toEqual(endpoints);
      expect(mockPrismaService.edrEndpoint.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        orderBy: { lastSeen: 'desc' },
      });
    });
  });
});
