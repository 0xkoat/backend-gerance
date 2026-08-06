import { Test, TestingModule } from '@nestjs/testing';
import { ConflictException, ForbiddenException, Logger } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { EdrService, EdrQueryFilters } from './edr.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  ModuleName,
  Severity,
  EdrEndpointStatus,
  EdrDetectionStatus,
  UserRole,
} from '../generated/prisma/enums';
import { UnifiedEvent } from '../common/security-module/types';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

const mockPrismaService = {
  edrEndpoint: {
    upsert: jest.fn(),
    findMany: jest.fn(),
  },
  edrDetection: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
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

    it('returns down and logs the error when the database query fails', async () => {
      const errorSpy = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation();
      const dbError = new Error('connection lost');
      mockPrismaService.edrDetection.findFirst.mockRejectedValue(dbError);

      const result = await service.healthCheck();

      expect(result).toEqual({ module: ModuleName.EDR, status: 'down' });
      expect(errorSpy).toHaveBeenCalledWith('EDR health check failed', dbError);
      errorSpy.mockRestore();
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

  describe('assignDetection', () => {
    const existing = {
      id: 'detection-1',
      tenantId: 'tenant-1',
      status: EdrDetectionStatus.OPEN,
      assignedToUserId: null,
    };

    it('lets an Analyst self-assign, moving status to ASSIGNED', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });
      mockPrismaService.edrDetection.findUnique.mockResolvedValue(existing);
      mockPrismaService.edrDetection.update.mockResolvedValue({
        ...existing,
        status: EdrDetectionStatus.ASSIGNED,
        assignedToUserId: 'analyst-1',
      });

      const result = await service.assignDetection(
        'tenant-1',
        'detection-1',
        caller,
        undefined,
      );

      expect(result.status).toBe(EdrDetectionStatus.ASSIGNED);
      expect(mockPrismaService.edrDetection.update).toHaveBeenCalledWith({
        where: { id: 'detection-1' },
        data: {
          assignedToUserId: 'analyst-1',
          status: EdrDetectionStatus.ASSIGNED,
        },
      });
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'edr.detection.assigned',
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.EDR,
          recordId: 'detection-1',
          assignedToUserId: 'analyst-1',
          status: EdrDetectionStatus.ASSIGNED,
        }),
      );
    });

    it('rejects an Analyst trying to assign someone else', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });
      mockPrismaService.edrDetection.findUnique.mockResolvedValue(existing);

      await expect(
        service.assignDetection('tenant-1', 'detection-1', caller, 'analyst-2'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.edrDetection.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the detection does not exist', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.edrDetection.findUnique.mockResolvedValue(null);

      await expect(
        service.assignDetection('tenant-1', 'missing-id', caller, 'analyst-1'),
      ).rejects.toThrow('Detection not found');
    });
  });

  describe('updateDetectionStatus', () => {
    const assigned = {
      id: 'detection-1',
      tenantId: 'tenant-1',
      status: EdrDetectionStatus.ASSIGNED,
      assignedToUserId: 'analyst-1',
    };

    it('lets the assigned Analyst resolve the detection', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-1' });
      mockPrismaService.edrDetection.findUnique.mockResolvedValue(assigned);
      mockPrismaService.edrDetection.update.mockResolvedValue({
        ...assigned,
        status: EdrDetectionStatus.RESOLVED,
      });

      const result = await service.updateDetectionStatus(
        'tenant-1',
        'detection-1',
        caller,
        EdrDetectionStatus.RESOLVED,
      );

      expect(result.status).toBe(EdrDetectionStatus.RESOLVED);
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'edr.detection.status_changed',
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.EDR,
          recordId: 'detection-1',
          status: EdrDetectionStatus.RESOLVED,
        }),
      );
    });

    it('rejects an Analyst who is not the assignee', async () => {
      const caller = authUser({ role: UserRole.ANALYST, userId: 'analyst-2' });
      mockPrismaService.edrDetection.findUnique.mockResolvedValue(assigned);

      await expect(
        service.updateDetectionStatus(
          'tenant-1',
          'detection-1',
          caller,
          EdrDetectionStatus.RESOLVED,
        ),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.edrDetection.update).not.toHaveBeenCalled();
    });

    it('rejects transitioning a detection that has never been assigned', async () => {
      const caller = authUser({ role: UserRole.ADMIN, userId: 'admin-1' });
      mockPrismaService.edrDetection.findUnique.mockResolvedValue({
        ...assigned,
        status: EdrDetectionStatus.OPEN,
        assignedToUserId: null,
      });

      await expect(
        service.updateDetectionStatus(
          'tenant-1',
          'detection-1',
          caller,
          EdrDetectionStatus.RESOLVED,
        ),
      ).rejects.toThrow(ConflictException);
      expect(mockPrismaService.edrDetection.update).not.toHaveBeenCalled();
    });
  });
});
