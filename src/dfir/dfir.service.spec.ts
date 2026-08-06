import { Test, TestingModule } from '@nestjs/testing';
import {
  ConflictException,
  ForbiddenException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { DfirService, DfirQueryFilters } from './dfir.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  DfirIncidentStatus,
  DfirLinkSourceType,
  ModuleName,
  Severity,
  UserRole,
} from '../generated/prisma/enums';
import {
  SoarExecutionPayload,
  UnifiedEvent,
} from '../common/security-module/types';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

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
  user: {
    findFirst: jest.fn(),
  },
};

const mockEventEmitter = {
  emit: jest.fn(),
};

function authUser(overrides: Partial<AuthenticatedUser>): AuthenticatedUser {
  return {
    userId: 'caller-1',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    mustChangePassword: false,
    ...overrides,
  };
}

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

    it('returns down and logs the error when the database query fails', async () => {
      const errorSpy = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation();
      const dbError = new Error('connection lost');
      mockPrismaService.dfirIncident.findFirst.mockRejectedValue(dbError);

      const result = await service.healthCheck();

      expect(result).toEqual({ module: ModuleName.DFIR, status: 'down' });
      expect(errorSpy).toHaveBeenCalledWith(
        'DFIR health check failed',
        dbError,
      );
      errorSpy.mockRestore();
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

  describe('assignIncident', () => {
    const existing = {
      id: 'incident-1',
      tenantId: 'tenant-1',
      status: DfirIncidentStatus.OPEN,
      assignedToUserId: null,
    };

    it('lets an Analyst self-assign, moving status to INVESTIGATING', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(existing);
      mockPrismaService.dfirIncident.update.mockResolvedValue({
        ...existing,
        status: DfirIncidentStatus.INVESTIGATING,
        assignedToUserId: 'analyst-1',
      });

      const result = await service.assignIncident(
        'tenant-1',
        'incident-1',
        caller,
        undefined,
      );

      expect(result.status).toBe(DfirIncidentStatus.INVESTIGATING);
      expect(mockPrismaService.dfirIncident.update).toHaveBeenCalledWith({
        where: { id: 'incident-1' },
        data: {
          assignedToUserId: 'analyst-1',
          status: DfirIncidentStatus.INVESTIGATING,
        },
      });
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'dfir.incident.assigned',
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.DFIR,
          recordId: 'incident-1',
          assignedToUserId: 'analyst-1',
          status: DfirIncidentStatus.INVESTIGATING,
        }),
      );
    });

    it('rejects an Analyst trying to assign someone else', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(existing);

      await expect(
        service.assignIncident('tenant-1', 'incident-1', caller, 'analyst-2'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.dfirIncident.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the incident does not exist', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(null);

      await expect(
        service.assignIncident('tenant-1', 'missing-id', caller, 'analyst-1'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateStatus', () => {
    const investigating = {
      id: 'incident-1',
      tenantId: 'tenant-1',
      status: DfirIncidentStatus.INVESTIGATING,
      assignedToUserId: 'analyst-1',
    };

    it('lets the assigned Analyst resolve the incident', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(
        investigating,
      );
      mockPrismaService.dfirIncident.update.mockResolvedValue({
        ...investigating,
        status: DfirIncidentStatus.RESOLVED,
      });

      const result = await service.updateStatus(
        'tenant-1',
        'incident-1',
        caller,
        DfirIncidentStatus.RESOLVED,
      );

      expect(result.status).toBe(DfirIncidentStatus.RESOLVED);
      expect(mockPrismaService.dfirIncident.update).toHaveBeenCalledWith({
        where: { id: 'incident-1' },
        data: { status: DfirIncidentStatus.RESOLVED },
      });
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'dfir.incident.status_changed',
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.DFIR,
          recordId: 'incident-1',
          status: DfirIncidentStatus.RESOLVED,
        }),
      );
    });

    it('lets an Admin move an assigned incident to CONTAINED', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(
        investigating,
      );
      mockPrismaService.dfirIncident.update.mockResolvedValue({
        ...investigating,
        status: DfirIncidentStatus.CONTAINED,
      });

      await service.updateStatus(
        'tenant-1',
        'incident-1',
        caller,
        DfirIncidentStatus.CONTAINED,
      );

      expect(mockPrismaService.dfirIncident.update).toHaveBeenCalledWith({
        where: { id: 'incident-1' },
        data: { status: DfirIncidentStatus.CONTAINED },
      });
    });

    it('rejects an Analyst who is not the assignee', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-2' });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(
        investigating,
      );

      await expect(
        service.updateStatus(
          'tenant-1',
          'incident-1',
          caller,
          DfirIncidentStatus.RESOLVED,
        ),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.dfirIncident.update).not.toHaveBeenCalled();
    });

    it('rejects transitioning an incident that has never been assigned', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue({
        ...investigating,
        status: DfirIncidentStatus.OPEN,
        assignedToUserId: null,
      });

      await expect(
        service.updateStatus(
          'tenant-1',
          'incident-1',
          caller,
          DfirIncidentStatus.RESOLVED,
        ),
      ).rejects.toThrow(ConflictException);
      expect(mockPrismaService.dfirIncident.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the incident does not exist', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue(null);

      await expect(
        service.updateStatus(
          'tenant-1',
          'missing-id',
          caller,
          DfirIncidentStatus.RESOLVED,
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.dfirIncident.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the incident belongs to a different tenant', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.dfirIncident.findUnique.mockResolvedValue({
        ...investigating,
        tenantId: 'tenant-2',
      });

      await expect(
        service.updateStatus(
          'tenant-1',
          'incident-1',
          caller,
          DfirIncidentStatus.RESOLVED,
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.dfirIncident.update).not.toHaveBeenCalled();
    });
  });
});
