import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { DfirService, DfirQueryFilters } from './dfir.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  DfirIncidentStatus,
  DfirLinkSourceType,
  ModuleName,
  Severity,
} from '../generated/prisma/enums';
import {
  SoarExecutionPayload,
  UnifiedEvent,
} from '../common/security-module/types';

const mockPrismaService = {
  dfirIncident: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  dfirLink: {
    create: jest.fn(),
  },
  siemAlert: {
    findUnique: jest.fn(),
  },
};

const mockEventEmitter = {
  emit: jest.fn(),
};

describe('DfirService', () => {
  let service: DfirService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DfirService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EventEmitter2, useValue: mockEventEmitter },
      ],
    }).compile();

    service = module.get<DfirService>(DfirService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createIncidentFromEvent', () => {
    it('creates an incident and links every provided record', async () => {
      mockPrismaService.dfirIncident.create.mockResolvedValue({
        id: 'incident-1',
        tenantId: 'tenant-1',
      });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue({
        id: 'incident-1',
        tenantId: 'tenant-1',
      });
      mockPrismaService.dfirLink.create.mockResolvedValue({ id: 'link-1' });

      const result = await service.createIncidentFromEvent(
        'tenant-1',
        'Incident: Outbound C2 beaconing',
        Severity.CRITICAL,
        [
          { sourceType: DfirLinkSourceType.SIEM_ALERT, sourceId: 'alert-1' },
          {
            sourceType: DfirLinkSourceType.SOAR_EXECUTION,
            sourceId: 'execution-1',
          },
        ],
      );

      expect(mockPrismaService.dfirIncident.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          title: 'Incident: Outbound C2 beaconing',
          severity: Severity.CRITICAL,
        },
      });
      expect(mockPrismaService.dfirLink.create).toHaveBeenCalledTimes(2);
      expect(mockPrismaService.dfirLink.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          incidentId: 'incident-1',
          sourceType: DfirLinkSourceType.SIEM_ALERT,
          sourceId: 'alert-1',
        },
      });
      expect(result).toEqual({ id: 'incident-1', tenantId: 'tenant-1' });
    });

    it('creates an incident with no links when none are provided', async () => {
      mockPrismaService.dfirIncident.create.mockResolvedValue({
        id: 'incident-1',
      });

      await service.createIncidentFromEvent(
        'tenant-1',
        'Manual incident',
        Severity.LOW,
        [],
      );

      expect(mockPrismaService.dfirLink.create).not.toHaveBeenCalled();
    });

    it('emits dfir.incident.created after persisting the incident', async () => {
      const createdAt = new Date('2026-08-05T10:25:00Z');
      mockPrismaService.dfirIncident.create.mockResolvedValue({
        id: 'incident-1',
        createdAt,
      });

      await service.createIncidentFromEvent(
        'tenant-1',
        'Incident: Outbound C2 beaconing',
        Severity.CRITICAL,
        [],
      );

      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'dfir.incident.created',
        {
          tenantId: 'tenant-1',
          incidentId: 'incident-1',
          title: 'Incident: Outbound C2 beaconing',
          severity: Severity.CRITICAL,
          timestamp: createdAt,
        },
      );
    });
  });

  describe('linkRecord', () => {
    it('creates a link when the incident belongs to the tenant', async () => {
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue({
        id: 'incident-1',
        tenantId: 'tenant-1',
      });
      mockPrismaService.dfirLink.create.mockResolvedValue({ id: 'link-1' });

      const result = await service.linkRecord(
        'tenant-1',
        'incident-1',
        DfirLinkSourceType.CTI_IOC,
        'ioc-1',
      );

      expect(result).toEqual({ id: 'link-1' });
      expect(mockPrismaService.dfirLink.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          incidentId: 'incident-1',
          sourceType: DfirLinkSourceType.CTI_IOC,
          sourceId: 'ioc-1',
        },
      });
    });

    it('throws NotFoundException when the incident does not exist', async () => {
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(null);

      await expect(
        service.linkRecord(
          'tenant-1',
          'missing-id',
          DfirLinkSourceType.CTI_IOC,
          'ioc-1',
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.dfirLink.create).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the incident belongs to a different tenant', async () => {
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue({
        id: 'incident-1',
        tenantId: 'tenant-2',
      });

      await expect(
        service.linkRecord(
          'tenant-1',
          'incident-1',
          DfirLinkSourceType.CTI_IOC,
          'ioc-1',
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.dfirLink.create).not.toHaveBeenCalled();
    });
  });

  describe('ingest', () => {
    it('creates an incident from a raw event, using the data title', async () => {
      const event: UnifiedEvent = {
        tenantId: 'tenant-1',
        timestamp: new Date(),
        source: ModuleName.DFIR,
        type: 'alert',
        severity: Severity.HIGH,
        data: { title: 'Manually flagged incident' },
      };
      mockPrismaService.dfirIncident.create.mockResolvedValue({
        id: 'incident-1',
      });

      await service.ingest(event);

      expect(mockPrismaService.dfirIncident.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          title: 'Manually flagged incident',
          severity: Severity.HIGH,
        },
      });
    });
  });

  describe('handleSoarExecution', () => {
    const payload: SoarExecutionPayload = {
      tenantId: 'tenant-1',
      executionId: 'execution-1',
      alertId: 'alert-1',
      playbookId: 'playbook-1',
      playbookName: 'Isolate host on critical alert',
      severity: Severity.CRITICAL,
      timestamp: new Date('2026-08-05T10:10:00Z'),
    };

    it('creates an incident linking the originating alert and the SOAR execution', async () => {
      mockPrismaService.siemAlert.findUnique.mockResolvedValue({
        id: 'alert-1',
        tenantId: 'tenant-1',
        title: 'Outbound C2 beaconing detected',
        severity: Severity.CRITICAL,
      });
      mockPrismaService.dfirIncident.create.mockResolvedValue({
        id: 'incident-1',
      });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue({
        id: 'incident-1',
        tenantId: 'tenant-1',
      });
      mockPrismaService.dfirLink.create.mockResolvedValue({ id: 'link-1' });

      await service.handleSoarExecution(payload);

      expect(mockPrismaService.dfirIncident.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          title: 'Incident: Outbound C2 beaconing detected',
          severity: Severity.CRITICAL,
        },
      });
      expect(mockPrismaService.dfirLink.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          incidentId: 'incident-1',
          sourceType: DfirLinkSourceType.SIEM_ALERT,
          sourceId: 'alert-1',
        },
      });
      expect(mockPrismaService.dfirLink.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          incidentId: 'incident-1',
          sourceType: DfirLinkSourceType.SOAR_EXECUTION,
          sourceId: 'execution-1',
        },
      });
    });

    it('does nothing when the referenced alert does not exist', async () => {
      mockPrismaService.siemAlert.findUnique.mockResolvedValue(null);

      await service.handleSoarExecution(payload);

      expect(mockPrismaService.dfirIncident.create).not.toHaveBeenCalled();
    });

    it('does nothing when the referenced alert belongs to a different tenant', async () => {
      mockPrismaService.siemAlert.findUnique.mockResolvedValue({
        id: 'alert-1',
        tenantId: 'tenant-2',
        title: 'Some alert',
        severity: Severity.CRITICAL,
      });

      await service.handleSoarExecution(payload);

      expect(mockPrismaService.dfirIncident.create).not.toHaveBeenCalled();
    });
  });

  describe('query', () => {
    const baseFilters: DfirQueryFilters = { tenantId: 'tenant-1' };

    it('filters by tenantId only and applies default pagination', async () => {
      mockPrismaService.dfirIncident.findMany.mockResolvedValue([]);

      await service.query(baseFilters);

      expect(mockPrismaService.dfirIncident.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        skip: 0,
        take: 20,
        orderBy: { createdAt: 'desc' },
      });
    });

    it('adds severity and status to the where clause when provided', async () => {
      mockPrismaService.dfirIncident.findMany.mockResolvedValue([]);

      await service.query({
        tenantId: 'tenant-1',
        severity: Severity.CRITICAL,
        status: DfirIncidentStatus.INVESTIGATING,
      });

      expect(mockPrismaService.dfirIncident.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            tenantId: 'tenant-1',
            severity: Severity.CRITICAL,
            status: DfirIncidentStatus.INVESTIGATING,
          },
        }),
      );
    });
  });

  describe('healthCheck', () => {
    it('returns ok with the latest incident timestamp', async () => {
      const lastIngestion = new Date('2026-08-04T10:00:00Z');
      mockPrismaService.dfirIncident.findFirst.mockResolvedValue({
        createdAt: lastIngestion,
      });

      const result = await service.healthCheck();

      expect(result).toEqual({
        module: ModuleName.DFIR,
        status: 'ok',
        lastIngestion,
      });
    });

    it('returns down when the database query fails', async () => {
      mockPrismaService.dfirIncident.findFirst.mockRejectedValue(
        new Error('connection lost'),
      );

      const result = await service.healthCheck();

      expect(result).toEqual({ module: ModuleName.DFIR, status: 'down' });
    });
  });

  describe('getIncidentDetail', () => {
    it('returns the incident with its links when it belongs to the tenant', async () => {
      const incident = {
        id: 'incident-1',
        tenantId: 'tenant-1',
        links: [{ id: 'link-1' }],
      };
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(incident);

      const result = await service.getIncidentDetail('tenant-1', 'incident-1');

      expect(result).toEqual(incident);
      expect(mockPrismaService.dfirIncident.findUnique).toHaveBeenCalledWith({
        where: { id: 'incident-1' },
        include: { links: true },
      });
    });

    it('throws NotFoundException when the incident does not exist', async () => {
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(null);

      await expect(
        service.getIncidentDetail('tenant-1', 'missing-id'),
      ).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when the incident belongs to a different tenant', async () => {
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue({
        id: 'incident-1',
        tenantId: 'tenant-2',
        links: [],
      });

      await expect(
        service.getIncidentDetail('tenant-1', 'incident-1'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateStatus', () => {
    const existing = {
      id: 'incident-1',
      tenantId: 'tenant-1',
      status: DfirIncidentStatus.OPEN,
    };

    it('updates the status when the incident belongs to the tenant', async () => {
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(existing);
      mockPrismaService.dfirIncident.update.mockResolvedValue({
        ...existing,
        status: DfirIncidentStatus.RESOLVED,
      });

      const result = await service.updateStatus(
        'tenant-1',
        'incident-1',
        DfirIncidentStatus.RESOLVED,
      );

      expect(result.status).toBe(DfirIncidentStatus.RESOLVED);
      expect(mockPrismaService.dfirIncident.update).toHaveBeenCalledWith({
        where: { id: 'incident-1' },
        data: { status: DfirIncidentStatus.RESOLVED },
      });
    });

    it('throws NotFoundException when the incident does not exist', async () => {
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(null);

      await expect(
        service.updateStatus(
          'tenant-1',
          'missing-id',
          DfirIncidentStatus.RESOLVED,
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.dfirIncident.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the incident belongs to a different tenant', async () => {
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue({
        ...existing,
        tenantId: 'tenant-2',
      });

      await expect(
        service.updateStatus(
          'tenant-1',
          'incident-1',
          DfirIncidentStatus.RESOLVED,
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.dfirIncident.update).not.toHaveBeenCalled();
    });
  });
});
