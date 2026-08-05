import { Test, TestingModule } from '@nestjs/testing';
import { Logger } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { SoarService, SoarQueryFilters } from './soar.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  ModuleName,
  Severity,
  SoarExecutionStatus,
} from '../generated/prisma/enums';
import {
  UnifiedEvent,
  CtiEnrichmentPayload,
} from '../common/security-module/types';

const mockPrismaService = {
  soarPlaybook: {
    findMany: jest.fn(),
    create: jest.fn(),
  },
  soarExecution: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
  },
};

const mockEventEmitter = {
  emit: jest.fn(),
};

describe('SoarService', () => {
  let service: SoarService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SoarService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EventEmitter2, useValue: mockEventEmitter },
      ],
    }).compile();

    service = module.get<SoarService>(SoarService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('evaluateTriggers', () => {
    it('creates a simulated execution and emits soar.execution.created for a matching playbook', async () => {
      mockPrismaService.soarPlaybook.findMany.mockResolvedValue([
        {
          id: 'playbook-1',
          name: 'Isolate host on critical alert',
          triggerCondition: { severity: 'CRITICAL' },
        },
      ]);
      const createdAt = new Date('2026-08-05T10:10:00Z');
      mockPrismaService.soarExecution.create.mockResolvedValue({
        id: 'execution-1',
        createdAt,
      });

      await service.evaluateTriggers('tenant-1', 'alert-1', Severity.CRITICAL);

      expect(mockPrismaService.soarExecution.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          playbookId: 'playbook-1',
          alertId: 'alert-1',
          status: SoarExecutionStatus.SUCCESS,
          logs: 'Playbook "Isolate host on critical alert" executed (simulated).',
        },
      });
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'soar.execution.created',
        {
          tenantId: 'tenant-1',
          executionId: 'execution-1',
          alertId: 'alert-1',
          playbookId: 'playbook-1',
          playbookName: 'Isolate host on critical alert',
          severity: Severity.CRITICAL,
          timestamp: createdAt,
        },
      );
    });

    it('does not create an execution when the trigger condition does not match', async () => {
      mockPrismaService.soarPlaybook.findMany.mockResolvedValue([
        {
          id: 'playbook-1',
          name: 'Critical only',
          triggerCondition: { severity: 'CRITICAL' },
        },
      ]);

      await service.evaluateTriggers('tenant-1', 'alert-1', Severity.LOW);

      expect(mockPrismaService.soarExecution.create).not.toHaveBeenCalled();
      expect(mockEventEmitter.emit).not.toHaveBeenCalled();
    });

    it('only fires the playbooks whose condition matches, out of several', async () => {
      mockPrismaService.soarPlaybook.findMany.mockResolvedValue([
        {
          id: 'playbook-1',
          name: 'Critical',
          triggerCondition: { severity: 'CRITICAL' },
        },
        {
          id: 'playbook-2',
          name: 'High',
          triggerCondition: { severity: 'HIGH' },
        },
      ]);
      mockPrismaService.soarExecution.create.mockResolvedValue({
        id: 'execution-1',
      });

      await service.evaluateTriggers('tenant-1', 'alert-1', Severity.HIGH);

      expect(mockPrismaService.soarExecution.create).toHaveBeenCalledTimes(1);
      expect(mockPrismaService.soarExecution.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ playbookId: 'playbook-2' }),
        }),
      );
    });
  });

  describe('ingest', () => {
    it('calls evaluateTriggers when the event data has an alertId', async () => {
      const event: UnifiedEvent = {
        tenantId: 'tenant-1',
        timestamp: new Date(),
        source: ModuleName.SOAR,
        type: 'alert',
        severity: Severity.CRITICAL,
        data: { alertId: 'alert-1' },
      };
      mockPrismaService.soarPlaybook.findMany.mockResolvedValue([]);

      await service.ingest(event);

      expect(mockPrismaService.soarPlaybook.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
      });
    });

    it('does nothing when the event data has no alertId', async () => {
      const event: UnifiedEvent = {
        tenantId: 'tenant-1',
        timestamp: new Date(),
        source: ModuleName.SOAR,
        type: 'event',
        severity: Severity.LOW,
        data: {},
      };

      await service.ingest(event);

      expect(mockPrismaService.soarPlaybook.findMany).not.toHaveBeenCalled();
    });
  });

  describe('handleSiemAlert', () => {
    it('evaluates triggers using the event severity and the alertId from data', async () => {
      const event: UnifiedEvent = {
        tenantId: 'tenant-1',
        timestamp: new Date(),
        source: ModuleName.SIEM,
        type: 'alert',
        severity: Severity.CRITICAL,
        data: { alertId: 'alert-1' },
      };
      mockPrismaService.soarPlaybook.findMany.mockResolvedValue([]);

      await service.handleSiemAlert(event);

      expect(mockPrismaService.soarPlaybook.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
      });
    });
  });

  describe('handleCtiEnrichment', () => {
    it('evaluates triggers using the enrichment payload', async () => {
      const payload: CtiEnrichmentPayload = {
        tenantId: 'tenant-1',
        alertId: 'alert-1',
        severity: Severity.CRITICAL,
      };
      mockPrismaService.soarPlaybook.findMany.mockResolvedValue([
        {
          id: 'playbook-1',
          name: 'Critical',
          triggerCondition: { severity: 'CRITICAL' },
        },
      ]);
      mockPrismaService.soarExecution.create.mockResolvedValue({
        id: 'execution-1',
      });

      await service.handleCtiEnrichment(payload);

      expect(mockPrismaService.soarExecution.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ alertId: 'alert-1' }),
        }),
      );
    });
  });

  describe('query', () => {
    const baseFilters: SoarQueryFilters = { tenantId: 'tenant-1' };

    it('filters by tenantId only and applies default pagination', async () => {
      mockPrismaService.soarExecution.findMany.mockResolvedValue([]);

      await service.query(baseFilters);

      expect(mockPrismaService.soarExecution.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        skip: 0,
        take: 20,
        orderBy: { createdAt: 'desc' },
      });
    });

    it('adds status to the where clause when provided', async () => {
      mockPrismaService.soarExecution.findMany.mockResolvedValue([]);

      await service.query({
        tenantId: 'tenant-1',
        status: SoarExecutionStatus.FAILED,
      });

      expect(mockPrismaService.soarExecution.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { tenantId: 'tenant-1', status: SoarExecutionStatus.FAILED },
        }),
      );
    });
  });

  describe('healthCheck', () => {
    it('returns ok with the latest execution timestamp', async () => {
      const lastIngestion = new Date('2026-08-04T10:00:00Z');
      mockPrismaService.soarExecution.findFirst.mockResolvedValue({
        createdAt: lastIngestion,
      });

      const result = await service.healthCheck();

      expect(result).toEqual({
        module: ModuleName.SOAR,
        status: 'ok',
        lastIngestion,
      });
    });

    it('returns down and logs the error when the database query fails', async () => {
      const errorSpy = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation();
      const dbError = new Error('connection lost');
      mockPrismaService.soarExecution.findFirst.mockRejectedValue(dbError);

      const result = await service.healthCheck();

      expect(result).toEqual({ module: ModuleName.SOAR, status: 'down' });
      expect(errorSpy).toHaveBeenCalledWith(
        'SOAR health check failed',
        dbError,
      );
      errorSpy.mockRestore();
    });
  });

  describe('listPlaybooks', () => {
    it('returns playbooks scoped to the tenant', async () => {
      const playbooks = [{ id: 'playbook-1', tenantId: 'tenant-1' }];
      mockPrismaService.soarPlaybook.findMany.mockResolvedValue(playbooks);

      const result = await service.listPlaybooks('tenant-1');

      expect(result).toEqual(playbooks);
      expect(mockPrismaService.soarPlaybook.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-1' },
        orderBy: { createdAt: 'desc' },
      });
    });
  });

  describe('createPlaybook', () => {
    it('creates a playbook scoped to the tenant', async () => {
      const dto = {
        name: 'Isolate host on critical alert',
        triggerCondition: { severity: 'CRITICAL' },
        actions: { isolateHost: true },
      };
      const created = { id: 'playbook-1', tenantId: 'tenant-1', ...dto };
      mockPrismaService.soarPlaybook.create.mockResolvedValue(created);

      const result = await service.createPlaybook('tenant-1', dto);

      expect(result).toEqual(created);
      expect(mockPrismaService.soarPlaybook.create).toHaveBeenCalledWith({
        data: { tenantId: 'tenant-1', ...dto },
      });
    });
  });
});
