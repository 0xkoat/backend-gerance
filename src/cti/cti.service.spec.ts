import { Test, TestingModule } from '@nestjs/testing';
import { Logger, NotFoundException } from '@nestjs/common';
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
    update: jest.fn(),
    delete: jest.fn(),
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

  describe('updateIoc', () => {
    it('updates confidence/source scoped to the tenant', async () => {
      const existing = { id: 'ioc-1', tenantId: 'tenant-1' };
      const updated = { ...existing, confidence: 40, source: 'corrected' };
      mockPrismaService.ctiIoc.findUnique.mockResolvedValue(existing);
      mockPrismaService.ctiIoc.update.mockResolvedValue(updated);

      const result = await service.updateIoc('tenant-1', 'ioc-1', {
        confidence: 40,
        source: 'corrected',
      });

      expect(result).toEqual(updated);
      expect(mockPrismaService.ctiIoc.update).toHaveBeenCalledWith({
        where: { id: 'ioc-1' },
        data: { confidence: 40, source: 'corrected' },
      });
    });

    it('throws NotFoundException when the IOC belongs to another tenant', async () => {
      mockPrismaService.ctiIoc.findUnique.mockResolvedValue({
        id: 'ioc-1',
        tenantId: 'tenant-2',
      });

      await expect(
        service.updateIoc('tenant-1', 'ioc-1', { confidence: 10 }),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.ctiIoc.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the IOC does not exist', async () => {
      mockPrismaService.ctiIoc.findUnique.mockResolvedValue(null);

      await expect(
        service.updateIoc('tenant-1', 'missing', { confidence: 10 }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteIoc', () => {
    it('deletes the IOC and emits cti.ioc.deleted', async () => {
      mockPrismaService.ctiIoc.findUnique.mockResolvedValue({
        id: 'ioc-1',
        tenantId: 'tenant-1',
      });
      mockPrismaService.ctiIoc.delete.mockResolvedValue({ id: 'ioc-1' });

      await service.deleteIoc('tenant-1', 'ioc-1');

      expect(mockPrismaService.ctiIoc.delete).toHaveBeenCalledWith({
        where: { id: 'ioc-1' },
      });
      expect(mockEventEmitter.emit).toHaveBeenCalledWith('cti.ioc.deleted', {
        tenantId: 'tenant-1',
        source: ModuleName.CTI,
        recordId: 'ioc-1',
        timestamp: expect.any(Date),
      });
    });

    it('throws NotFoundException when the IOC belongs to another tenant', async () => {
      mockPrismaService.ctiIoc.findUnique.mockResolvedValue({
        id: 'ioc-1',
        tenantId: 'tenant-2',
      });

      await expect(service.deleteIoc('tenant-1', 'ioc-1')).rejects.toThrow(
        NotFoundException,
      );
      expect(mockPrismaService.ctiIoc.delete).not.toHaveBeenCalled();
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

    it('returns down and logs the error when the database query fails', async () => {
      const errorSpy = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation();
      const dbError = new Error('connection lost');
      mockPrismaService.ctiIoc.findFirst.mockRejectedValue(dbError);

      const result = await service.healthCheck();

      expect(result).toEqual({ module: ModuleName.CTI, status: 'down' });
      expect(errorSpy).toHaveBeenCalledWith('CTI health check failed', dbError);
      errorSpy.mockRestore();
    });
  });
});
