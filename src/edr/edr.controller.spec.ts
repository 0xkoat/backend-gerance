import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { EdrController } from './edr.controller';
import { EdrService } from './edr.service';
import {
  ModuleName,
  Severity,
  UserRole,
  EdrDetectionStatus,
} from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { IngestEdrEventDto } from './dto/ingestEdrEvent.dto';
import { EdrQueryDto } from './dto/edrQuery.dto';
import { UpdateEdrDetectionStatusDto } from './dto/updateEdrDetectionStatus.dto';
import { AssignDto } from '../common/dto/assign.dto';

const mockEdrService = {
  listEndpoints: jest.fn(),
  updateEndpoint: jest.fn(),
  deleteEndpoint: jest.fn(),
  query: jest.fn(),
  assignDetection: jest.fn(),
  unassignDetection: jest.fn(),
  updateDetectionStatus: jest.fn(),
  ingest: jest.fn(),
};

describe('EdrController', () => {
  let controller: EdrController;

  const analyst: AuthenticatedUser = {
    userId: 'user-1',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const admin: AuthenticatedUser = {
    userId: 'admin-1',
    role: UserRole.ADMIN,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const noTenantAdmin: AuthenticatedUser = {
    userId: 'admin-1',
    role: UserRole.ADMIN,
    tenantId: null,
    mustChangePassword: false,
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [EdrController],
      providers: [{ provide: EdrService, useValue: mockEdrService }],
    }).compile();

    controller = module.get<EdrController>(EdrController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('listEndpoints', () => {
    it('returns endpoints for the caller tenant', async () => {
      const endpoints = [{ id: 'endpoint-1', tenantId: 'tenant-1' }];
      mockEdrService.listEndpoints.mockResolvedValue(endpoints);

      const result = await controller.listEndpoints(analyst);

      expect(result).toEqual(endpoints);
      expect(mockEdrService.listEndpoints).toHaveBeenCalledWith('tenant-1');
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.listEndpoints(noTenantAdmin)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockEdrService.listEndpoints).not.toHaveBeenCalled();
    });
  });

  describe('updateEndpoint', () => {
    it('passes the tenant and id to the service', async () => {
      const updated = { id: 'endpoint-1', tenantId: 'tenant-1' };
      mockEdrService.updateEndpoint.mockResolvedValue(updated);

      const result = await controller.updateEndpoint(analyst, 'endpoint-1', {
        hostname: 'renamed',
      });

      expect(result).toEqual(updated);
      expect(mockEdrService.updateEndpoint).toHaveBeenCalledWith(
        'tenant-1',
        'endpoint-1',
        { hostname: 'renamed' },
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.updateEndpoint(noTenantAdmin, 'endpoint-1', {}),
      ).rejects.toThrow(ForbiddenException);
      expect(mockEdrService.updateEndpoint).not.toHaveBeenCalled();
    });
  });

  describe('deleteEndpoint', () => {
    it('passes the tenant and id to the service', async () => {
      mockEdrService.deleteEndpoint.mockResolvedValue(undefined);

      await controller.deleteEndpoint(analyst, 'endpoint-1');

      expect(mockEdrService.deleteEndpoint).toHaveBeenCalledWith(
        'tenant-1',
        'endpoint-1',
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.deleteEndpoint(noTenantAdmin, 'endpoint-1'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockEdrService.deleteEndpoint).not.toHaveBeenCalled();
    });
  });

  describe('queryDetections', () => {
    it('merges the query params with the caller tenantId', async () => {
      const query: EdrQueryDto = {
        severity: Severity.HIGH,
        page: 1,
        pageSize: 20,
      };
      mockEdrService.query.mockResolvedValue([]);

      await controller.queryDetections(analyst, query);

      expect(mockEdrService.query).toHaveBeenCalledWith({
        ...query,
        tenantId: 'tenant-1',
      });
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.queryDetections(noTenantAdmin, {}),
      ).rejects.toThrow(ForbiddenException);
      expect(mockEdrService.query).not.toHaveBeenCalled();
    });
  });

  describe('assignDetection', () => {
    it('passes the caller and requested assignee to the service', async () => {
      const updated = {
        id: 'detection-1',
        status: EdrDetectionStatus.ASSIGNED,
      };
      mockEdrService.assignDetection.mockResolvedValue(updated);

      const result = await controller.assignDetection(analyst, 'detection-1', {
        assignedToUserId: 'analyst-2',
      });

      expect(result).toEqual(updated);
      expect(mockEdrService.assignDetection).toHaveBeenCalledWith(
        'tenant-1',
        'detection-1',
        analyst,
        'analyst-2',
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      const dto: AssignDto = {};
      await expect(
        controller.assignDetection(noTenantAdmin, 'detection-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockEdrService.assignDetection).not.toHaveBeenCalled();
    });
  });

  describe('unassignDetection', () => {
    it('passes the caller to the service', async () => {
      const updated = { id: 'detection-1', status: EdrDetectionStatus.OPEN };
      mockEdrService.unassignDetection.mockResolvedValue(updated);

      const result = await controller.unassignDetection(analyst, 'detection-1');

      expect(result).toEqual(updated);
      expect(mockEdrService.unassignDetection).toHaveBeenCalledWith(
        'tenant-1',
        'detection-1',
        analyst,
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.unassignDetection(noTenantAdmin, 'detection-1'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockEdrService.unassignDetection).not.toHaveBeenCalled();
    });
  });

  describe('updateDetectionStatus', () => {
    const dto: UpdateEdrDetectionStatusDto = {
      status: EdrDetectionStatus.RESOLVED,
    };

    it('passes the caller and status to the service', async () => {
      const updated = {
        id: 'detection-1',
        status: EdrDetectionStatus.RESOLVED,
      };
      mockEdrService.updateDetectionStatus.mockResolvedValue(updated);

      const result = await controller.updateDetectionStatus(
        analyst,
        'detection-1',
        dto,
      );

      expect(result).toEqual(updated);
      expect(mockEdrService.updateDetectionStatus).toHaveBeenCalledWith(
        'tenant-1',
        'detection-1',
        analyst,
        EdrDetectionStatus.RESOLVED,
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.updateDetectionStatus(noTenantAdmin, 'detection-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockEdrService.updateDetectionStatus).not.toHaveBeenCalled();
    });
  });

  describe('ingestEvent', () => {
    const dto: IngestEdrEventDto = {
      hostname: 'web-server-1',
      ip: '10.0.0.5',
      os: 'Ubuntu 24.04',
      detectionName: 'Suspicious PowerShell execution chain',
      severity: Severity.HIGH,
    };

    it('builds a UnifiedEvent with the endpoint/detection fields nested under data', async () => {
      mockEdrService.ingest.mockResolvedValue(undefined);

      await controller.ingestEvent(admin, dto);

      expect(mockEdrService.ingest).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.EDR,
          type: 'detection',
          severity: Severity.HIGH,
          data: {
            hostname: 'web-server-1',
            ip: '10.0.0.5',
            os: 'Ubuntu 24.04',
            detectionName: 'Suspicious PowerShell execution chain',
          },
        }),
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.ingestEvent(noTenantAdmin, dto)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockEdrService.ingest).not.toHaveBeenCalled();
    });
  });
});
