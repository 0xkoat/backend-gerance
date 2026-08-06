import { Test, TestingModule } from '@nestjs/testing';
import {
  ConflictException,
  ForbiddenException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { SiemService, SiemQueryFilters } from './siem.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  ModuleName,
  Severity,
  SiemAlertStatus,
  UserRole,
} from '../generated/prisma/enums';
import { UnifiedEvent } from '../common/security-module/types';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

const mockPrismaService = {
  siemLog: {
    create: jest.fn(),
    findMany: jest.fn(),
  },
  siemAlert: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn(),
  },
  user: {
    findFirst: jest.fn(),
  },
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

const mockEventEmitter = {
  emit: jest.fn(),
};

describe('SiemService', () => {
  let service: SiemService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SiemService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EventEmitter2, useValue: mockEventEmitter },
      ],
    }).compile();

    service = module.get<SiemService>(SiemService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('ingest', () => {
    const lowSeverityEvent: UnifiedEvent = {
      tenantId: 'tenant-1',
      timestamp: new Date('2026-08-04T10:00:00Z'),
      source: ModuleName.SIEM,
      type: 'event',
      severity: Severity.LOW,
      data: { title: 'Routine log entry' },
    };

    it('always writes a SiemLog', async () => {
      mockPrismaService.siemLog.create.mockResolvedValue({ id: 'log-1' });

      await service.ingest(lowSeverityEvent);

      expect(mockPrismaService.siemLog.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          source: ModuleName.SIEM,
          eventType: 'event',
          severity: Severity.LOW,
          rawData: lowSeverityEvent.data,
          timestamp: lowSeverityEvent.timestamp,
        },
      });
    });

    it('does not create a SiemAlert for a low-severity, non-alert event', async () => {
      mockPrismaService.siemLog.create.mockResolvedValue({ id: 'log-1' });

      await service.ingest(lowSeverityEvent);

      expect(mockPrismaService.siemAlert.create).not.toHaveBeenCalled();
      expect(mockEventEmitter.emit).not.toHaveBeenCalled();
    });

    it('creates a SiemAlert and emits siem.alert.created when severity is HIGH or above', async () => {
      const event: UnifiedEvent = {
        ...lowSeverityEvent,
        severity: Severity.HIGH,
        data: { title: 'Suspicious login' },
      };
      mockPrismaService.siemLog.create.mockResolvedValue({ id: 'log-1' });
      mockPrismaService.siemAlert.create.mockResolvedValue({
        id: 'alert-1',
        severity: Severity.HIGH,
      });

      await service.ingest(event);

      expect(mockPrismaService.siemAlert.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          title: 'Suspicious login',
          severity: Severity.HIGH,
          rawData: event.data,
        },
      });
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'siem.alert.created',
        expect.objectContaining({
          data: expect.objectContaining({ alertId: 'alert-1' }),
        }),
      );
    });

    it('creates a SiemAlert for type "alert" regardless of severity', async () => {
      const event: UnifiedEvent = {
        ...lowSeverityEvent,
        type: 'alert',
        severity: Severity.LOW,
        data: { title: 'Manually flagged event' },
      };
      mockPrismaService.siemLog.create.mockResolvedValue({ id: 'log-1' });
      mockPrismaService.siemAlert.create.mockResolvedValue({
        id: 'alert-1',
        severity: Severity.LOW,
      });

      await service.ingest(event);

      expect(mockPrismaService.siemAlert.create).toHaveBeenCalled();
    });

    it('falls back to a generated title when data has none', async () => {
      const event: UnifiedEvent = {
        ...lowSeverityEvent,
        severity: Severity.CRITICAL,
        data: {},
      };
      mockPrismaService.siemLog.create.mockResolvedValue({ id: 'log-1' });
      mockPrismaService.siemAlert.create.mockResolvedValue({
        id: 'alert-1',
        severity: Severity.CRITICAL,
      });

      await service.ingest(event);

      expect(mockPrismaService.siemAlert.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ title: `${ModuleName.SIEM} event` }),
        }),
      );
    });
  });

  describe('handleEdrDetection', () => {
    it('converts an EDR detection into a SIEM alert with a generated title', async () => {
      const edrEvent: UnifiedEvent = {
        tenantId: 'tenant-1',
        timestamp: new Date(),
        source: ModuleName.EDR,
        type: 'detection',
        severity: Severity.HIGH,
        data: {
          hostname: 'web-server-1',
          detectionName: 'Suspicious PowerShell execution chain',
        },
      };
      mockPrismaService.siemLog.create.mockResolvedValue({ id: 'log-1' });
      mockPrismaService.siemAlert.create.mockResolvedValue({
        id: 'alert-1',
        severity: Severity.HIGH,
      });

      await service.handleEdrDetection(edrEvent);

      expect(mockPrismaService.siemAlert.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            title: 'Suspicious PowerShell execution chain on web-server-1',
          }),
        }),
      );
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'siem.alert.created',
        expect.anything(),
      );
    });
  });

  describe('handleEnrichment', () => {
    it('applies the escalated severity to the referenced alert, scoped to the tenant', async () => {
      mockPrismaService.siemAlert.updateMany.mockResolvedValue({ count: 1 });

      await service.handleEnrichment({
        tenantId: 'tenant-1',
        alertId: 'alert-1',
        severity: Severity.CRITICAL,
      });

      expect(mockPrismaService.siemAlert.updateMany).toHaveBeenCalledWith({
        where: { id: 'alert-1', tenantId: 'tenant-1' },
        data: { severity: Severity.CRITICAL },
      });
    });
  });

  describe('query', () => {
    const baseFilters: SiemQueryFilters = { tenantId: 'tenant-1' };

    it('filters by tenantId only and applies default pagination', async () => {
      mockPrismaService.siemAlert.findMany.mockResolvedValue([]);

      await service.query(baseFilters);

      expect(mockPrismaService.siemAlert.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        skip: 0,
        take: 20,
        orderBy: { createdAt: 'desc' },
      });
    });

    it('adds severity and status to the where clause when provided', async () => {
      mockPrismaService.siemAlert.findMany.mockResolvedValue([]);

      await service.query({
        tenantId: 'tenant-1',
        severity: Severity.CRITICAL,
        status: SiemAlertStatus.ESCALATED,
      });

      expect(mockPrismaService.siemAlert.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            tenantId: 'tenant-1',
            severity: Severity.CRITICAL,
            status: SiemAlertStatus.ESCALATED,
          },
        }),
      );
    });
  });

  describe('healthCheck', () => {
    it('returns ok with the latest ingestion timestamp when alerts exist', async () => {
      const lastIngestion = new Date('2026-08-04T10:00:00Z');
      mockPrismaService.siemAlert.findFirst.mockResolvedValue({
        createdAt: lastIngestion,
      });

      const result = await service.healthCheck();

      expect(result).toEqual({
        module: ModuleName.SIEM,
        status: 'ok',
        lastIngestion,
      });
    });

    it('returns down and logs the error when the database query fails', async () => {
      const errorSpy = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation();
      const dbError = new Error('connection lost');
      mockPrismaService.siemAlert.findFirst.mockRejectedValue(dbError);

      const result = await service.healthCheck();

      expect(result).toEqual({ module: ModuleName.SIEM, status: 'down' });
      expect(errorSpy).toHaveBeenCalledWith(
        'SIEM health check failed',
        dbError,
      );
      errorSpy.mockRestore();
    });
  });

  describe('listLogs', () => {
    it('returns logs scoped to the tenant, most recent first', async () => {
      const logs = [{ id: 'log-1', tenantId: 'tenant-1' }];
      mockPrismaService.siemLog.findMany.mockResolvedValue(logs);

      const result = await service.listLogs('tenant-1');

      expect(result).toEqual(logs);
      expect(mockPrismaService.siemLog.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        orderBy: { timestamp: 'desc' },
      });
    });
  });

  describe('assignAlert', () => {
    const existing = {
      id: 'alert-1',
      tenantId: 'tenant-1',
      status: SiemAlertStatus.OPEN,
      assignedToUserId: null,
    };

    it('lets an Analyst self-assign, moving status to ASSIGNED', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue(existing);
      mockPrismaService.siemAlert.update.mockResolvedValue({
        ...existing,
        status: SiemAlertStatus.ASSIGNED,
        assignedToUserId: 'analyst-1',
      });

      const result = await service.assignAlert(
        'tenant-1',
        'alert-1',
        caller,
        undefined,
      );

      expect(result.status).toBe(SiemAlertStatus.ASSIGNED);
      expect(mockPrismaService.siemAlert.update).toHaveBeenCalledWith({
        where: { id: 'alert-1' },
        data: {
          assignedToUserId: 'analyst-1',
          status: SiemAlertStatus.ASSIGNED,
        },
      });
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'siem.alert.assigned',
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.SIEM,
          recordId: 'alert-1',
          assignedToUserId: 'analyst-1',
          status: SiemAlertStatus.ASSIGNED,
        }),
      );
    });

    it('rejects an Analyst trying to assign someone else', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue(existing);

      await expect(
        service.assignAlert('tenant-1', 'alert-1', caller, 'analyst-2'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.siemAlert.update).not.toHaveBeenCalled();
    });

    it('lets an Admin assign a valid tenant Analyst', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue(existing);
      mockPrismaService.user.findFirst.mockResolvedValue({ id: 'analyst-2' });
      mockPrismaService.siemAlert.update.mockResolvedValue({
        ...existing,
        status: SiemAlertStatus.ASSIGNED,
        assignedToUserId: 'analyst-2',
      });

      await service.assignAlert('tenant-1', 'alert-1', caller, 'analyst-2');

      expect(mockPrismaService.siemAlert.update).toHaveBeenCalledWith({
        where: { id: 'alert-1' },
        data: {
          assignedToUserId: 'analyst-2',
          status: SiemAlertStatus.ASSIGNED,
        },
      });
    });

    it('throws NotFoundException when the alert does not exist', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue(null);

      await expect(
        service.assignAlert('tenant-1', 'missing-id', caller, 'analyst-1'),
      ).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when the alert belongs to a different tenant', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue({
        ...existing,
        tenantId: 'tenant-2',
      });

      await expect(
        service.assignAlert('tenant-1', 'alert-1', caller, 'analyst-1'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateAlertStatus', () => {
    const assigned = {
      id: 'alert-1',
      tenantId: 'tenant-1',
      status: SiemAlertStatus.ASSIGNED,
      assignedToUserId: 'analyst-1',
    };

    it('lets the assigned Analyst resolve the alert', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue(assigned);
      mockPrismaService.siemAlert.update.mockResolvedValue({
        ...assigned,
        status: SiemAlertStatus.RESOLVED,
      });

      const result = await service.updateAlertStatus(
        'tenant-1',
        'alert-1',
        caller,
        SiemAlertStatus.RESOLVED,
      );

      expect(result.status).toBe(SiemAlertStatus.RESOLVED);
      expect(mockPrismaService.siemAlert.update).toHaveBeenCalledWith({
        where: { id: 'alert-1' },
        data: { status: SiemAlertStatus.RESOLVED },
      });
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'siem.alert.status_changed',
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.SIEM,
          recordId: 'alert-1',
          status: SiemAlertStatus.RESOLVED,
        }),
      );
    });

    it('lets an Admin resolve an alert assigned to someone else', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue(assigned);
      mockPrismaService.siemAlert.update.mockResolvedValue({
        ...assigned,
        status: SiemAlertStatus.ESCALATED,
      });

      await service.updateAlertStatus(
        'tenant-1',
        'alert-1',
        caller,
        SiemAlertStatus.ESCALATED,
      );

      expect(mockPrismaService.siemAlert.update).toHaveBeenCalledWith({
        where: { id: 'alert-1' },
        data: { status: SiemAlertStatus.ESCALATED },
      });
    });

    it('rejects an Analyst who is not the assignee', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-2' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue(assigned);

      await expect(
        service.updateAlertStatus(
          'tenant-1',
          'alert-1',
          caller,
          SiemAlertStatus.RESOLVED,
        ),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.siemAlert.update).not.toHaveBeenCalled();
    });

    it('rejects transitioning an alert that has never been assigned', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue({
        ...assigned,
        status: SiemAlertStatus.OPEN,
        assignedToUserId: null,
      });

      await expect(
        service.updateAlertStatus(
          'tenant-1',
          'alert-1',
          caller,
          SiemAlertStatus.RESOLVED,
        ),
      ).rejects.toThrow(ConflictException);
      expect(mockPrismaService.siemAlert.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the alert does not exist', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue(null);

      await expect(
        service.updateAlertStatus(
          'tenant-1',
          'missing-id',
          caller,
          SiemAlertStatus.RESOLVED,
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.siemAlert.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the alert belongs to a different tenant', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.siemAlert.findUnique.mockResolvedValue({
        ...assigned,
        tenantId: 'tenant-2',
      });

      await expect(
        service.updateAlertStatus(
          'tenant-1',
          'alert-1',
          caller,
          SiemAlertStatus.RESOLVED,
        ),
      ).rejects.toThrow(NotFoundException);
      expect(mockPrismaService.siemAlert.update).not.toHaveBeenCalled();
    });
  });
});
