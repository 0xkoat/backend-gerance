import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { CtiService, CtiQueryFilters } from './cti.service';
import { PrismaService } from '../prisma/prisma.service';
import { CtiIocType, ModuleName, Severity } from '../generated/prisma/enums';
import { UnifiedEvent } from '../common/security-module/types';

const mockPrismaService = {
  ctiIoc: {
    upsert: jest.fn(),
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
  },
};

const mockEventEmitter = {
  emit: jest.fn(),
};

describe('CtiService', () => {
  let service: CtiService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CtiService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EventEmitter2, useValue: mockEventEmitter },
      ],
    }).compile();

    service = module.get<CtiService>(CtiService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('ingest', () => {
    const event: UnifiedEvent = {
      tenantId: 'tenant-1',
      timestamp: new Date(),
      source: ModuleName.CTI,
      type: 'ioc',
      severity: Severity.MEDIUM,
      data: {
        type: CtiIocType.IP,
        value: '185.220.101.47',
        confidence: 85,
        source: 'AlienVault OTX',
      },
    };

    it('upserts the IOC keyed by tenantId+type+value', async () => {
      mockPrismaService.ctiIoc.findUnique.mockResolvedValue(null);
      mockPrismaService.ctiIoc.upsert.mockResolvedValue({ id: 'ioc-1' });

      await service.ingest(event);

      expect(mockPrismaService.ctiIoc.upsert).toHaveBeenCalledWith({
        where: {
          tenantId_type_value: {
            tenantId: 'tenant-1',
            type: CtiIocType.IP,
            value: '185.220.101.47',
          },
        },
        update: {
          confidence: 85,
          source: 'AlienVault OTX',
          rawData: event.data,
        },
        create: {
          tenantId: 'tenant-1',
          type: CtiIocType.IP,
          value: '185.220.101.47',
          confidence: 85,
          source: 'AlienVault OTX',
          rawData: event.data,
        },
      });
    });

    it('emits cti.ioc.created with the ioc id added to data when the IOC is new', async () => {
      mockPrismaService.ctiIoc.findUnique.mockResolvedValue(null);
      mockPrismaService.ctiIoc.upsert.mockResolvedValue({ id: 'ioc-1' });

      await service.ingest(event);

      expect(mockEventEmitter.emit).toHaveBeenCalledWith('cti.ioc.created', {
        ...event,
        data: { ...event.data, iocId: 'ioc-1' },
      });
    });

    it('does not emit cti.ioc.created when the IOC already existed (update only)', async () => {
      mockPrismaService.ctiIoc.findUnique.mockResolvedValue({ id: 'ioc-1' });
      mockPrismaService.ctiIoc.upsert.mockResolvedValue({ id: 'ioc-1' });

      await service.ingest(event);

      expect(mockEventEmitter.emit).not.toHaveBeenCalled();
    });
  });

  describe('checkMatch', () => {
    it('returns the matching IOC when found', async () => {
      const ioc = { id: 'ioc-1', value: '185.220.101.47' };
      mockPrismaService.ctiIoc.findFirst.mockResolvedValue(ioc);

      const result = await service.checkMatch('tenant-1', '185.220.101.47');

      expect(result).toEqual(ioc);
      expect(mockPrismaService.ctiIoc.findFirst).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1', value: '185.220.101.47' },
      });
    });

    it('returns null when no IOC matches', async () => {
      mockPrismaService.ctiIoc.findFirst.mockResolvedValue(null);

      const result = await service.checkMatch('tenant-1', 'clean-ip');

      expect(result).toBeNull();
    });
  });

  describe('handleSiemAlert', () => {
    const alertEvent: UnifiedEvent = {
      tenantId: 'tenant-1',
      timestamp: new Date(),
      source: ModuleName.SIEM,
      type: 'alert',
      severity: Severity.HIGH,
      data: { ip: '185.220.101.47', alertId: 'alert-1' },
    };

    it('emits cti.enrichment.applied with escalated severity on a match', async () => {
      mockPrismaService.ctiIoc.findFirst.mockResolvedValue({ id: 'ioc-1' });

      await service.handleSiemAlert(alertEvent);

      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'cti.enrichment.applied',
        {
          tenantId: 'tenant-1',
          alertId: 'alert-1',
          severity: Severity.CRITICAL,
        },
      );
    });

    it('does not emit anything when there is no match', async () => {
      mockPrismaService.ctiIoc.findFirst.mockResolvedValue(null);

      await service.handleSiemAlert(alertEvent);

      expect(mockEventEmitter.emit).not.toHaveBeenCalled();
    });

    it('does not check for a match when the alert has no ip in its data', async () => {
      await service.handleSiemAlert({
        ...alertEvent,
        data: { alertId: 'alert-1' },
      });

      expect(mockPrismaService.ctiIoc.findFirst).not.toHaveBeenCalled();
      expect(mockEventEmitter.emit).not.toHaveBeenCalled();
    });
  });

  describe('query', () => {
    const baseFilters: CtiQueryFilters = { tenantId: 'tenant-1' };

    it('filters by tenantId only and applies default pagination', async () => {
      mockPrismaService.ctiIoc.findMany.mockResolvedValue([]);

      await service.query(baseFilters);

      expect(mockPrismaService.ctiIoc.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        skip: 0,
        take: 20,
        orderBy: { createdAt: 'desc' },
      });
    });

    it('adds type to the where clause when provided', async () => {
      mockPrismaService.ctiIoc.findMany.mockResolvedValue([]);

      await service.query({ tenantId: 'tenant-1', type: CtiIocType.DOMAIN });

      expect(mockPrismaService.ctiIoc.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { tenantId: 'tenant-1', type: CtiIocType.DOMAIN },
        }),
      );
    });
  });

  describe('healthCheck', () => {
    it('returns ok with the latest ingestion timestamp when IOCs exist', async () => {
      const lastIngestion = new Date('2026-08-04T10:00:00Z');
      mockPrismaService.ctiIoc.findFirst.mockResolvedValue({
        createdAt: lastIngestion,
      });

      const result = await service.healthCheck();

      expect(result).toEqual({
        module: ModuleName.CTI,
        status: 'ok',
        lastIngestion,
      });
    });

    it('returns down when the database query fails', async () => {
      mockPrismaService.ctiIoc.findFirst.mockRejectedValue(
        new Error('connection lost'),
      );

      const result = await service.healthCheck();

      expect(result).toEqual({ module: ModuleName.CTI, status: 'down' });
    });
  });
});
