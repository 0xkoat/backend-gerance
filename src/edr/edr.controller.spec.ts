import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { EdrController } from './edr.controller';
import { EdrService } from './edr.service';
import { ModuleName, Severity, UserRole } from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { IngestEdrEventDto } from './dto/ingestEdrEvent.dto';
import { EdrQueryDto } from './dto/edrQuery.dto';

const mockEdrService = {
  listEndpoints: jest.fn(),
  query: jest.fn(),
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
